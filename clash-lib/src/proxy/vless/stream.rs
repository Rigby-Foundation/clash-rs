use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{sleep, Duration, Sleep};
use tracing::{debug, error, info, warn};

use crate::{
    proxy::{AnyStream, transport::switch_reality_raw_modes},
    session::SocksAddr,
};

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_COMMAND_UDP: u8 = 2;
const VLESS_COMMAND_MUX: u8 = 3;

const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

const COMMAND_PADDING_CONTINUE: u8 = 0x00;
const COMMAND_PADDING_END: u8 = 0x01;
const COMMAND_PADDING_DIRECT: u8 = 0x02;

fn build_addon_bytes(flow: &str) -> Vec<u8> {
    let mut addon = Vec::new();
    addon.push(0x0A);
    addon.push(flow.len() as u8);
    addon.extend_from_slice(flow.as_bytes());
    addon
}

pub struct VlessStream {
    inner: AnyStream,
    handshake_done: bool,
    handshake_sent: bool,
    response_received: bool,
    handshake_pending: Option<BytesMut>,
    handshake_pending_pos: usize,
    handshake_ack_len: usize,
    response_header: [u8; 2],
    response_header_read: usize,
    response_additional_remaining: Option<usize>,
    uuid: uuid::Uuid,
    destination: SocksAddr,
    is_udp: bool,
    xudp: bool,
    flow: Option<String>,
}

impl VlessStream {
    pub fn new(
        stream: AnyStream,
        uuid: &str,
        destination: &SocksAddr,
        is_udp: bool,
        xudp: bool,
        flow: Option<String>,
    ) -> io::Result<Self> {
        let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid UUID format")
        })?;

        Ok(Self {
            inner: stream,
            handshake_done: false,
            handshake_sent: false,
            response_received: false,
            handshake_pending: None,
            handshake_pending_pos: 0,
            handshake_ack_len: 0,
            response_header: [0u8; 2],
            response_header_read: 0,
            response_additional_remaining: None,
            uuid,
            destination: destination.clone(),
            is_udp,
            xudp,
            flow,
        })
    }

    fn build_handshake_header(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(VLESS_VERSION);
        buf.put_slice(self.uuid.as_bytes());

        if let Some(flow) = &self.flow {
            let addon = build_addon_bytes(flow);
            buf.put_u8(addon.len() as u8);
            buf.put_slice(&addon);
        } else {
            buf.put_u8(0);
        }

        let command = if self.xudp {
            VLESS_COMMAND_MUX
        } else if self.is_udp {
            VLESS_COMMAND_UDP
        } else {
            VLESS_COMMAND_TCP
        };
        buf.put_u8(command);

        if command != VLESS_COMMAND_MUX {
            self.destination.write_to_buf_vmess(&mut buf);
        }
        buf
    }

    fn poll_receive_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.response_received {
            return Poll::Ready(Ok(()));
        }

        while self.response_header_read < self.response_header.len() {
            let mut read_buf = ReadBuf::new(&mut self.response_header[self.response_header_read..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "VLESS response eof")));
                    }
                    self.response_header_read += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.response_additional_remaining.is_none() {
            if self.response_header[0] != VLESS_VERSION {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "invalid VLESS version")));
            }
            self.response_additional_remaining = Some(self.response_header[1] as usize);
        }

        while let Some(remaining) = self.response_additional_remaining {
            if remaining == 0 {
                break;
            }
            let mut discard = [0u8; 256];
            let take = remaining.min(discard.len());
            let mut read_buf = ReadBuf::new(&mut discard[..take]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "VLESS addons eof")));
                    }
                    self.response_additional_remaining = Some(remaining - n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.response_received = true;
        self.handshake_done = true;
        Poll::Ready(Ok(()))
    }

    fn poll_send_handshake(
        &mut self,
        cx: &mut Context<'_>,
        payload: &[u8],
        ack_len: usize,
    ) -> Poll<io::Result<usize>> {
        if self.handshake_sent {
            return Poll::Ready(Ok(ack_len));
        }

        if self.handshake_pending.is_none() {
            let mut handshake = self.build_handshake_header();
            handshake.extend_from_slice(payload);
            self.handshake_pending = Some(handshake);
            self.handshake_pending_pos = 0;
            self.handshake_ack_len = ack_len;
        }

        while let Some(pending) = self.handshake_pending.as_ref() {
            if self.handshake_pending_pos >= pending.len() {
                break;
            }

            match Pin::new(&mut self.inner).poll_write(cx, &pending[self.handshake_pending_pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "VLESS write zero"))),
                Poll::Ready(Ok(n)) => self.handshake_pending_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.handshake_pending = None;
        self.handshake_sent = true;
        let ack = self.handshake_ack_len;
        self.handshake_ack_len = 0;
        Poll::Ready(Ok(ack))
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.handshake_sent && !self.response_received {
            match self.poll_receive_response(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let vision_flow = matches!(self.flow.as_deref(), Some("xtls-rprx-vision" | "xtls-rprx-vision-udp443"));

        if !self.handshake_sent {
            let payload = if vision_flow || self.xudp { &[][..] } else { buf };
            let ack_len = if vision_flow || self.xudp { 0 } else { buf.len() };
            match self.poll_send_handshake(cx, payload, ack_len) {
                Poll::Ready(Ok(n)) => {
                    if (!vision_flow && !self.xudp) || buf.is_empty() {
                        return Poll::Ready(Ok(n));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug, PartialEq)]
enum ReadState {
    Init,
    Header,
    Content { cmd: u8, content_len: usize, pad_len: usize },
    Padding { cmd: u8, pad_len: usize },
    Raw,
}

pub struct VisionStream {
    inner: VlessStream,
    uuid: [u8; 16],
    is_tls: bool,
    number_of_packet_to_filter: i32,
    is_tls12_or_above: bool,
    remaining_server_hello: i32,
    cipher: u16,
    enable_xtls: bool,

    is_padding: bool,
    write_uuid: bool,
    raw_mode_switched: bool,

    read_state: ReadState,
    read_pending: BytesMut,
    read_buf: BytesMut,
    write_pending: Option<WritePending>,
}

struct WritePending {
    orig_len: usize,
    data: BytesMut,
    pos: usize,
    switch_to_direct: bool,
    switch_done: bool,
    raw_tail: BytesMut,
    raw_tail_pos: usize,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl VisionStream {
    pub fn new(vless_stream: VlessStream) -> Self {
        let uuid = *vless_stream.uuid.as_bytes();
        Self {
            inner: vless_stream,
            uuid,
            is_tls: false,
            number_of_packet_to_filter: 8,
            is_tls12_or_above: false,
            remaining_server_hello: -1,
            cipher: 0,
            enable_xtls: false,
            is_padding: true,
            write_uuid: true,
            raw_mode_switched: false,
            read_state: ReadState::Init,
            read_pending: BytesMut::new(),
            read_buf: BytesMut::new(),
            write_pending: None,
        }
    }

    fn filter_tls(&mut self, data: &[u8]) {
        if self.number_of_packet_to_filter <= 0 || data.len() <= 6 { return; }
        self.number_of_packet_to_filter -= 1;

        if data.starts_with(&TLS_SERVER_HANDSHAKE_START) && data[5] == 0x02 {
            self.is_tls = true;
            self.is_tls12_or_above = true;
            self.remaining_server_hello = (((data[3] as i32) << 8) | data[4] as i32) + 5;
            if data.len() >= 79 && self.remaining_server_hello >= 79 {
                let session_id_len = data[43] as usize;
                let cipher_index = 43 + session_id_len + 1;
                if cipher_index + 1 < data.len() {
                    self.cipher = ((data[cipher_index] as u16) << 8) | data[cipher_index + 1] as u16;
                }
            }
        } else if data.starts_with(&TLS_CLIENT_HANDSHAKE_START) && data[5] == 0x01 {
            self.is_tls = true;
        }

        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(data.len());
            self.remaining_server_hello -= end as i32;
            if data[..end].windows(TLS13_SUPPORTED_VERSIONS.len()).any(|w| w == TLS13_SUPPORTED_VERSIONS) {
                self.enable_xtls = matches!(self.cipher, 0x1301 | 0x1302 | 0x1303 | 0x1304);
                self.number_of_packet_to_filter = 0;
            } else if self.remaining_server_hello == 0 {
                self.number_of_packet_to_filter = 0;
            }
        }
    }

    fn reshape_buffer(data: &[u8]) -> Vec<&[u8]> {
        const BUFFER_LIMIT: usize = 8192 - 21;
        if data.len() < BUFFER_LIMIT { return vec![data]; }
        let split = data.windows(TLS_APPLICATION_DATA_START.len())
            .rposition(|w| w == TLS_APPLICATION_DATA_START)
            .filter(|i| *i > 0).unwrap_or(8192 / 2).min(data.len());
        vec![&data[..split], &data[split..]]
    }

    fn padding_frame(&mut self, content: &[u8], command: u8) -> BytesMut {
        let content_len = content.len().min(u16::MAX as usize);
        let padding_len = if content_len < 900 && self.is_tls {
            let random = (rand::random::<u16>() % 500) as usize;
            (900 - content_len).min(u16::MAX as usize - random) + random
        } else {
            (rand::random::<u8>() as usize) % 256
        };

        let mut frame = BytesMut::with_capacity(16 + 5 + content_len + padding_len);
        if self.write_uuid {
            frame.extend_from_slice(&self.uuid);
            self.write_uuid = false;
        }
        frame.put_u8(command);
        frame.put_u16(content_len as u16);
        frame.put_u16(padding_len as u16);
        frame.extend_from_slice(&content[..content_len]);
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            for byte in &mut padding { *byte = rand::random(); }
            frame.extend_from_slice(&padding);
        }
        frame
    }

    fn make_write_pending(&mut self, data: &[u8]) -> WritePending {
        if self.number_of_packet_to_filter > 0 {
            self.filter_tls(data);
        }

        if !self.is_padding {
            return WritePending {
                orig_len: data.len(), data: BytesMut::from(data), pos: 0,
                switch_to_direct: false, switch_done: false,
                raw_tail: BytesMut::new(), raw_tail_pos: 0, sleep: None,
            };
        }

        let slices = Self::reshape_buffer(data);
        let mut framed = BytesMut::new();
        let mut spec_index = None;
        let mut trigger_raw = false;

        for (i, slice) in slices.iter().enumerate() {
            if self.is_tls && slice.len() > 6 && slice.starts_with(&TLS_APPLICATION_DATA_START) {
                self.is_padding = false;
                trigger_raw = true;
                framed.extend_from_slice(&self.padding_frame(slice, COMMAND_PADDING_END));
                spec_index = Some(i);
                break;
            } else if !self.is_tls12_or_above && self.number_of_packet_to_filter <= 1 {
                self.is_padding = false;
                trigger_raw = true;
                framed.extend_from_slice(&self.padding_frame(slice, COMMAND_PADDING_END));
                spec_index = Some(i);
                break;
            }
            framed.extend_from_slice(&self.padding_frame(slice, COMMAND_PADDING_CONTINUE));
        }

        let mut raw_tail = BytesMut::new();
        if let Some(idx) = spec_index {
            if idx + 1 < slices.len() {
                for slice in &slices[idx + 1..] { raw_tail.extend_from_slice(slice); }
            }
        }

        WritePending {
            orig_len: data.len(),
            data: framed,
            pos: 0,
            switch_to_direct: trigger_raw, // Флаг для переключения ПОСЛЕ отправки PADDING_END
            switch_done: false,
            raw_tail,
            raw_tail_pos: 0,
            sleep: None,
        }
    }

    fn poll_write_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, io::Error>> {
        let pending = self.write_pending.as_mut().unwrap();

        while pending.pos < pending.data.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &pending.data[pending.pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "vision write zero"))),
                Poll::Ready(Ok(n)) => pending.pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // БАГФИКС: Переключаем Raw Mode только когда буфер с PADDING_END полностью отправлен и сброшен
        if pending.switch_to_direct && !pending.switch_done {
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            if !self.raw_mode_switched {
                if let Err(e) = switch_reality_raw_modes(&mut self.inner.inner, true, true) {
                    warn!("Vision: failed to switch Reality raw mode: {}", e);
                }
                self.raw_mode_switched = true;
            }
            pending.switch_done = true;
            if !pending.raw_tail.is_empty() {
                pending.sleep = Some(Box::pin(sleep(Duration::from_millis(5))));
            }
        }

        if let Some(ref mut sleep_fut) = pending.sleep {
            match sleep_fut.as_mut().poll(cx) {
                Poll::Ready(()) => { pending.sleep = None; }
                Poll::Pending => return Poll::Pending,
            }
        }

        while pending.raw_tail_pos < pending.raw_tail.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &pending.raw_tail[pending.raw_tail_pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "vision tail zero"))),
                Poll::Ready(Ok(n)) => pending.raw_tail_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let ack = pending.orig_len;
        self.write_pending = None;
        Poll::Ready(Ok(ack))
    }

    fn parse_read_pending(&mut self) -> io::Result<bool> {
        loop {
            match self.read_state {
                ReadState::Init => {
                    if self.read_pending.len() >= 16 {
                        if self.read_pending[..16] != self.uuid {
                            self.read_state = ReadState::Raw;
                            continue;
                        } else if self.read_pending.len() >= 21 {
                            self.read_pending.advance(16);
                            self.read_state = ReadState::Header;
                            continue;
                        }
                    }
                    return Ok(false);
                }
                ReadState::Header => {
                    if self.read_pending.len() >= 5 {
                        let cmd = self.read_pending[0];
                        let content_len = ((self.read_pending[1] as usize) << 8) | self.read_pending[2] as usize;
                        let pad_len = ((self.read_pending[3] as usize) << 8) | self.read_pending[4] as usize;
                        self.read_pending.advance(5);
                        self.read_state = ReadState::Content { cmd, content_len, pad_len };
                        continue;
                    }
                    return Ok(false);
                }
                ReadState::Content { cmd, mut content_len, pad_len } => {
                    if content_len > 0 {
                        let take = content_len.min(self.read_pending.len());
                        if take > 0 {
                            let data = self.read_pending.split_to(take);
                            if self.number_of_packet_to_filter > 0 {
                                self.filter_tls(&data);
                            }
                            self.read_buf.extend_from_slice(&data);
                            content_len -= take;
                            self.read_state = ReadState::Content { cmd, content_len, pad_len };
                        }
                        if content_len > 0 {
                            return Ok(!self.read_buf.is_empty());
                        }
                    }
                    self.read_state = ReadState::Padding { cmd, pad_len };
                    continue;
                }
                ReadState::Padding { cmd, mut pad_len } => {
                    if pad_len > 0 {
                        let skip = pad_len.min(self.read_pending.len());
                        self.read_pending.advance(skip);
                        pad_len -= skip;
                        if pad_len > 0 {
                            self.read_state = ReadState::Padding { cmd, pad_len };
                            return Ok(!self.read_buf.is_empty());
                        }
                    }
                    if cmd == COMMAND_PADDING_END || cmd == COMMAND_PADDING_DIRECT {
                        self.read_state = ReadState::Raw;
                        if !self.raw_mode_switched {
                            let _ = switch_reality_raw_modes(&mut self.inner.inner, true, true);
                            self.raw_mode_switched = true;
                        }
                    } else {
                        self.read_state = ReadState::Header;
                    }
                    continue;
                }
                ReadState::Raw => {
                    if !self.read_pending.is_empty() {
                        let data = self.read_pending.split_to(self.read_pending.len());
                        if self.number_of_packet_to_filter > 0 {
                            self.filter_tls(&data);
                        }
                        self.read_buf.extend_from_slice(&data);
                        return Ok(true);
                    }
                    return Ok(!self.read_buf.is_empty());
                }
            }
        }
    }

    async fn fill_read_buf(&mut self) -> io::Result<()> {
        loop {
            if self.parse_read_pending()? {
                return Ok(());
            }

            let mut tmp = [0u8; 8192];
            let n = tokio::io::AsyncReadExt::read(&mut self.inner, &mut tmp).await?;
            if n == 0 {
                if !self.read_pending.is_empty() {
                    let data = self.read_pending.split_to(self.read_pending.len());
                    if self.number_of_packet_to_filter > 0 { self.filter_tls(&data); }
                    self.read_buf.extend_from_slice(&data);
                }
                return Ok(());
            }
            self.read_pending.extend_from_slice(&tmp[..n]);
        }
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.read_buf.is_empty() {
            let fut = self.fill_read_buf();
            tokio::pin!(fut);
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.read_buf.is_empty() { return Poll::Ready(Ok(())); }
        let to_copy = self.read_buf.len().min(buf.remaining());
        buf.put_slice(&self.read_buf[..to_copy]);
        self.read_buf.advance(to_copy);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        if self.write_pending.is_some() { return self.poll_write_pending(cx); }
        if self.is_padding {
            self.write_pending = Some(self.make_write_pending(buf));
            return self.poll_write_pending(cx);
        }
        if self.number_of_packet_to_filter > 0 { self.filter_tls(buf); }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}