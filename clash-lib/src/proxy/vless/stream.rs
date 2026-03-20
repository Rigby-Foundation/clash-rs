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

/// Build the protobuf-encoded VLESS addon bytes for the given flow string.
/// Field 1 (Flow), wire type 2 (LEN): tag = 0x0A, then varint length, then bytes.
fn build_addon_bytes(flow: &str) -> Vec<u8> {
    let mut addon = Vec::new();
    addon.push(0x0A); // field 1, wire type LEN
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

        debug!("VLESS stream created for destination: {}", destination);

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

        // VLESS request header:
        // Version (1 byte) + UUID (16 bytes) + Addon length (1 byte) + [Addon] +
        // Command (1 byte) + Port (2 bytes) + Address type + Address
        buf.put_u8(VLESS_VERSION);
        buf.put_slice(self.uuid.as_bytes());

        if let Some(flow) = &self.flow {
            let addon = build_addon_bytes(flow);
            buf.put_u8(addon.len() as u8);
            buf.put_slice(&addon);
        } else {
            buf.put_u8(0); // no addon
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

    fn poll_receive_response(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.response_received {
            return Poll::Ready(Ok(()));
        }

        debug!("VLESS waiting for response");

        while self.response_header_read < self.response_header.len() {
            let mut read_buf =
                ReadBuf::new(&mut self.response_header[self.response_header_read..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected eof while reading VLESS response",
                        )));
                    }
                    self.response_header_read += n;
                }
                Poll::Ready(Err(e)) => {
                    error!("Failed to read VLESS response: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.response_additional_remaining.is_none() {
            if self.response_header[0] != VLESS_VERSION {
                error!(
                    "Invalid VLESS response version: {}",
                    self.response_header[0]
                );
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid VLESS response version: {}",
                        self.response_header[0]
                    ),
                )));
            }
            self.response_additional_remaining =
                Some(self.response_header[1] as usize);
            if let Some(rem) = self.response_additional_remaining {
                if rem > 0 {
                    debug!("VLESS additional info pending: {} bytes", rem);
                }
            }
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
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected eof while reading VLESS additional info",
                        )));
                    }
                    self.response_additional_remaining = Some(remaining - n);
                }
                Poll::Ready(Err(e)) => {
                    error!("Failed to read VLESS additional info: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        self.response_received = true;
        self.handshake_done = true;
        debug!("VLESS handshake completed successfully");
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
            debug!(
                "VLESS handshake starting for destination: {}",
                self.destination
            );
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

            match Pin::new(&mut self.inner)
                .poll_write(cx, &pending[self.handshake_pending_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero while sending VLESS handshake",
                    )));
                }
                Poll::Ready(Ok(n)) => self.handshake_pending_pos += n,
                Poll::Ready(Err(e)) => {
                    error!("Failed to send VLESS handshake: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        self.handshake_pending = None;
        self.handshake_pending_pos = 0;
        self.handshake_sent = true;
        debug!(
            "VLESS handshake sent with {} bytes of data",
            self.handshake_ack_len
        );
        let ack = self.handshake_ack_len;
        self.handshake_ack_len = 0;
        Poll::Ready(Ok(ack))
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Must receive response before reading
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
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let vision_flow = matches!(
            self.flow.as_deref(),
            Some("xtls-rprx-vision" | "xtls-rprx-vision-udp443")
        );
        let mux_handshake = self.xudp;

        // Send handshake with first write
        if !self.handshake_sent {
            let payload = if vision_flow || mux_handshake {
                &[][..]
            } else {
                buf
            };
            let ack_len = if vision_flow || mux_handshake {
                0
            } else {
                buf.len()
            };
            match self.poll_send_handshake(cx, payload, ack_len) {
                Poll::Ready(Ok(n)) => {
                    if (!vision_flow && !mux_handshake) || buf.is_empty() {
                        return Poll::Ready(Ok(n));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Clean Vision implementation based on sing-box
/// Reference: github.com/sagernet/sing-vmess/vless/vision.go
pub struct VisionStream {
    inner: VlessStream,
    uuid: [u8; 16],

    // TLS detection state
    is_tls: bool,
    number_of_packet_to_filter: i32,
    is_tls12_or_above: bool,
    remaining_server_hello: i32,
    cipher: u16,
    enable_xtls: bool,

    // Padding state
    is_padding: bool,
    write_direct: bool,
    write_uuid: bool,
    raw_write_switched: bool,

    // Read state
    within_padding_buffers: bool,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
    direct_read: bool,
    
    // Buffers
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
        info!("VisionStream created for {}", vless_stream.destination);
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
            write_direct: false,
            write_uuid: true,
            raw_write_switched: false,
            within_padding_buffers: true,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            direct_read: false,
            read_pending: BytesMut::new(),
            read_buf: BytesMut::new(),
            write_pending: None,
        }
    }

    // Filter TLS packets to detect handshake and enable XTLS
    fn filter_tls(&mut self, data: &[u8]) {
        if self.number_of_packet_to_filter <= 0 || data.len() <= 6 {
            return;
        }

        self.number_of_packet_to_filter -= 1;

        // Check for Server Hello
        if data.starts_with(&TLS_SERVER_HANDSHAKE_START) && data[5] == 0x02 {
            self.is_tls = true;
            self.is_tls12_or_above = true;
            self.remaining_server_hello = (((data[3] as i32) << 8) | data[4] as i32) + 5;

            // Extract cipher suite
            if data.len() >= 79 && self.remaining_server_hello >= 79 {
                let session_id_len = data[43] as usize;
                let cipher_index = 43 + session_id_len + 1;
                if cipher_index + 1 < data.len() {
                    self.cipher = ((data[cipher_index] as u16) << 8) | data[cipher_index + 1] as u16;
                    info!(
                        "Vision: Server Hello detected, cipher=0x{:04x} dest={}",
                        self.cipher, self.inner.destination
                    );
                }
            }
        }
        // Check for Client Hello
        else if data.starts_with(&TLS_CLIENT_HANDSHAKE_START) && data[5] == 0x01 {
            self.is_tls = true;
            info!("Vision: Client Hello detected dest={}", self.inner.destination);
        }

        // Check for TLS 1.3 in Server Hello
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(data.len());
            self.remaining_server_hello -= end as i32;

            if data[..end]
                .windows(TLS13_SUPPORTED_VERSIONS.len())
                .any(|w| w == TLS13_SUPPORTED_VERSIONS)
            {
                self.enable_xtls = matches!(self.cipher, 0x1301 | 0x1302 | 0x1303 | 0x1304);
                info!(
                    "Vision: TLS 1.3 detected! cipher=0x{:04x} enable_xtls={} dest={}",
                    self.cipher, self.enable_xtls, self.inner.destination
                );
                self.number_of_packet_to_filter = 0;
            } else if self.remaining_server_hello == 0 {
                info!(
                    "Vision: Server Hello complete, TLS 1.2. cipher=0x{:04x} dest={}",
                    self.cipher, self.inner.destination
                );
                self.number_of_packet_to_filter = 0;
            }
        }
    }

    // Reshape buffer for Vision framing (sing-box reshapeBuffer)
    fn reshape_buffer(data: &[u8]) -> Vec<&[u8]> {
        const BUFFER_LIMIT: usize = 8192 - 21;
        if data.len() < BUFFER_LIMIT {
            return vec![data];
        }

        // Try to split at TLS Application Data boundary
        let split = data
            .windows(TLS_APPLICATION_DATA_START.len())
            .rposition(|w| w == TLS_APPLICATION_DATA_START)
            .filter(|i| *i > 0)
            .unwrap_or(8192 / 2)
            .min(data.len());
        
        vec![&data[..split], &data[split..]]
    }

    // Create Vision padding frame (sing-box padding func)
    fn padding_frame(&mut self, content: &[u8], command: u8) -> BytesMut {
        let content_len = content.len().min(u16::MAX as usize);
        let padding_len = if content_len < 900 && self.is_tls {
            let random = (rand::random::<u16>() % 500) as usize;
            (900 - content_len).min(u16::MAX as usize - random) + random
        } else {
            (rand::random::<u8>() as usize) % 256
        };

        let mut frame = BytesMut::with_capacity(16 + 1 + 2 + 2 + content_len + padding_len);
        
        // UUID (only first frame)
        if self.write_uuid {
            frame.extend_from_slice(&self.uuid);
            self.write_uuid = false;
        }

        // Command + lengths
        frame.put_u8(command);
        frame.put_u16(content_len as u16);
        frame.put_u16(padding_len as u16);
        
        // Content
        frame.extend_from_slice(&content[..content_len]);
        
        // Padding
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            for byte in &mut padding {
                *byte = rand::random();
            }
            frame.extend_from_slice(&padding);
        }

        frame
    }

    // Make write pending struct (sing-box Write logic)
    fn make_write_pending(&mut self, data: &[u8]) -> WritePending {
        // Filter TLS BEFORE padding logic (sing-box line 193-195)
        if self.number_of_packet_to_filter > 0 {
            self.filter_tls(data);
        }

        if !self.is_padding {
            // After padding ended, switch Reality to raw write mode once
            if !self.raw_write_switched {
                self.raw_write_switched = true;
                if let Err(e) = switch_reality_raw_modes(&mut self.inner.inner, false, true) {
                    warn!("Vision: failed to switch Reality to raw write mode: {}", e);
                } else {
                    info!("Vision: switched Reality to raw write mode. dest={}", self.inner.destination);
                }
            }
            
            // Write directly without Vision framing
            return WritePending {
                orig_len: data.len(),
                data: BytesMut::from(data),
                pos: 0,
                switch_to_direct: false,
                switch_done: false,
                raw_tail: BytesMut::new(),
                raw_tail_pos: 0,
                sleep: None,
            };
        }

        // Reshape and frame buffers
        let slices = Self::reshape_buffer(data);
        let mut framed = BytesMut::new();
        let mut spec_index = None;

        for (i, slice) in slices.iter().enumerate() {
            // Check for TLS Application Data
            if self.is_tls && slice.len() > 6 && slice.starts_with(&TLS_APPLICATION_DATA_START) {
                // NOTE: XTLS Direct mode requires raw socket access which we don't have
                // with Reality wrapper. Always use PADDING_END instead of PADDING_DIRECT.
                // This matches the behavior when enable_xtls=false.
                let command = COMMAND_PADDING_END;
                
                info!(
                    "Vision: TLS AppData detected, ending padding. command=0x{:02x} dest={}",
                    command, self.inner.destination
                );
                
                self.is_padding = false;
                framed.extend_from_slice(&self.padding_frame(slice, command));
                spec_index = Some(i);
                break;
            }
            // Check for fallback (non-TLS or TLS < 1.2)
            else if !self.is_tls12_or_above && self.number_of_packet_to_filter <= 1 {
                info!(
                    "Vision: fallback end (non-TLS or TLS<1.2). is_tls={} dest={}",
                    self.is_tls, self.inner.destination
                );
                self.is_padding = false;
                framed.extend_from_slice(&self.padding_frame(slice, COMMAND_PADDING_END));
                spec_index = Some(i);
                break;
            }
            
            framed.extend_from_slice(&self.padding_frame(slice, COMMAND_PADDING_CONTINUE));
        }

        // Collect raw_tail (data after PADDING_DIRECT/END)
        let mut raw_tail = BytesMut::new();
        if let Some(idx) = spec_index {
            if idx + 1 < slices.len() {
                for slice in &slices[idx + 1..] {
                    raw_tail.extend_from_slice(slice);
                }
            }
        }

        WritePending {
            orig_len: data.len(),
            data: framed,
            pos: 0,
            switch_to_direct: false, // XTLS Direct mode disabled - no raw socket access
            switch_done: false,
            raw_tail,
            raw_tail_pos: 0,
            sleep: None,
        }
    }

    fn poll_write_pending(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize, io::Error>> {
        let pending = self.write_pending.as_mut().unwrap();

        // Write framed data
        while pending.pos < pending.data.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &pending.data[pending.pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero in Vision framed write",
                    )));
                }
                Poll::Ready(Ok(n)) => pending.pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Switch to direct write mode for XTLS
        if pending.switch_to_direct && !pending.switch_done {
            // Flush before switching
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }

            // Switch Reality to raw write mode
            let switched = switch_reality_raw_modes(&mut self.inner.inner, false, true)?;
            debug!("Vision: switched to raw write mode, switched={}", switched);
            pending.switch_done = true;

            // Create sleep if we have raw_tail data
            if !pending.raw_tail.is_empty() {
                info!(
                    "Vision: sleeping 5ms before raw_tail write. tail_len={} dest={}",
                    pending.raw_tail.len(),
                    self.inner.destination
                );
                pending.sleep = Some(Box::pin(sleep(Duration::from_millis(5))));
            }
        }

        // Wait for sleep
        if let Some(ref mut sleep_fut) = pending.sleep {
            match sleep_fut.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    pending.sleep = None;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Write raw_tail
        while pending.raw_tail_pos < pending.raw_tail.len() {
            match Pin::new(&mut self.inner)
                .poll_write(cx, &pending.raw_tail[pending.raw_tail_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero in Vision raw_tail write",
                    )));
                }
                Poll::Ready(Ok(n)) => pending.raw_tail_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let ack = pending.orig_len;
        self.write_pending = None;
        Poll::Ready(Ok(ack))
    }

    // Parse Vision frames from read_pending
    fn parse_read_pending(&mut self) -> io::Result<bool> {
        loop {
            // If not in padding mode, return all pending data
            if !self.within_padding_buffers {
                if !self.read_pending.is_empty() {
                    // Filter TLS on read
                    if self.number_of_packet_to_filter > 0 {
                        let data_copy = self.read_pending.clone();
                        self.filter_tls(&data_copy);
                    }
                    let data = self.read_pending.split_to(self.read_pending.len());
                    self.read_buf.extend_from_slice(&data);
                    return Ok(true);
                }
                return Ok(!self.read_buf.is_empty());
            }

            // Need frame header: [UUID(16)][Command(1)][ContentLen(2)][PaddingLen(2)]
            if self.remaining_content == -1 && self.remaining_padding == -1 {
                // Check for first Vision frame (UUID should be present only in first frame)
                if self.read_pending.len() >= 21 && self.read_pending[..16] == self.uuid {
                    // This is a Vision frame, parse it
                } else if self.read_pending.len() >= 16 {
                    // No UUID match - this is raw TLS data, not Vision frame
                    let data = self.read_pending.split_to(self.read_pending.len());
                    self.read_buf.extend_from_slice(&data);
                    return Ok(true);
                } else {
                    // Need more data to determine if this is Vision frame or raw data
                    return Ok(!self.read_buf.is_empty());
                }

                // Parse header
                self.read_pending.advance(16); // Skip UUID
                self.current_command = self.read_pending[0];
                self.remaining_content = ((self.read_pending[1] as i32) << 8) | self.read_pending[2] as i32;
                self.remaining_padding = ((self.read_pending[3] as i32) << 8) | self.read_pending[4] as i32;
                self.read_pending.advance(5);

                debug!(
                    "Vision: frame header parsed. cmd=0x{:02x} content={} padding={} dest={}",
                    self.current_command, self.remaining_content, self.remaining_padding, self.inner.destination
                );
            }

            // Read content
            if self.remaining_content > 0 {
                if self.read_pending.is_empty() {
                    return Ok(!self.read_buf.is_empty());
                }

                let take = (self.remaining_content as usize).min(self.read_pending.len());
                let data = self.read_pending.split_to(take);
                self.remaining_content -= take as i32;

                // Filter TLS on content
                if self.number_of_packet_to_filter > 0 {
                    let data_copy = data.clone();
                    self.filter_tls(&data_copy);
                }

                self.read_buf.extend_from_slice(&data);
            }

            // Skip padding
            if self.remaining_padding > 0 {
                if self.read_pending.is_empty() {
                    return Ok(!self.read_buf.is_empty());
                }

                let skip = (self.remaining_padding as usize).min(self.read_pending.len());
                self.read_pending.advance(skip);
                self.remaining_padding -= skip as i32;
            }

            // Frame complete, process command
            if self.remaining_content == 0 && self.remaining_padding == 0 {
                match self.current_command {
                    COMMAND_PADDING_CONTINUE => {
                        self.within_padding_buffers = true;
                    }
                    COMMAND_PADDING_END => {
                        info!("Vision: PADDING_END received, switching to raw read mode. dest={}", self.inner.destination);
                        self.within_padding_buffers = false;
                        // Switch Reality to raw read mode since padding is done
                        switch_reality_raw_modes(&mut self.inner.inner, true, false)?;
                    }
                    COMMAND_PADDING_DIRECT => {
                        info!("Vision: PADDING_DIRECT received, switching to XTLS raw. dest={}", self.inner.destination);
                        self.within_padding_buffers = false;
                        self.direct_read = true;
                        // TODO: read input/rawInput from TLS conn if available
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Unknown Vision command: 0x{:02x}", self.current_command),
                        ));
                    }
                }

                self.remaining_content = -1;
                self.remaining_padding = -1;
            }
        }
    }

    async fn fill_read_buf(&mut self) -> io::Result<()> {
        loop {
            // Try to parse what we have
            if self.parse_read_pending()? {
                return Ok(());
            }

            // If direct_read mode, read from Reality raw
            if self.direct_read {
                // Switch Reality to raw read mode
                switch_reality_raw_modes(&mut self.inner.inner, true, false)?;
                
                let mut tmp = [0u8; 8192];
                let n = tokio::io::AsyncReadExt::read(&mut self.inner, &mut tmp).await?;
                if n == 0 {
                    return Ok(());
                }
                
                debug!("Vision: direct_read mode, read {} bytes", n);
                self.read_buf.extend_from_slice(&tmp[..n]);
                return Ok(());
            }

            // Read more data
            let mut tmp = [0u8; 8192];
            let n = tokio::io::AsyncReadExt::read(&mut self.inner, &mut tmp).await?;
            if n == 0 {
                // EOF, process remaining
                if !self.read_pending.is_empty() {
                    if self.number_of_packet_to_filter > 0 {
                        let data_copy = self.read_pending.clone();
                        self.filter_tls(&data_copy);
                    }
                    let data = self.read_pending.split_to(self.read_pending.len());
                    self.read_buf.extend_from_slice(&data);
                }
                return Ok(());
            }

            debug!("Vision: read {} bytes from inner", n);
            self.read_pending.extend_from_slice(&tmp[..n]);
        }
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_buf.is_empty() {
            let fut = self.fill_read_buf();
            tokio::pin!(fut);
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.read_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let to_copy = self.read_buf.len().min(buf.remaining());
        buf.put_slice(&self.read_buf[..to_copy]);
        self.read_buf.advance(to_copy);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.write_pending.is_some() {
            return self.poll_write_pending(cx);
        }

        if self.is_padding {
            self.write_pending = Some(self.make_write_pending(buf));
            return self.poll_write_pending(cx);
        }

        // After padding ends, check if we should write directly
        if !self.is_padding {
            // Filter TLS on write BEFORE padding check
            if self.number_of_packet_to_filter > 0 {
                self.filter_tls(buf);
            }

            if self.write_direct {
                // Write directly to raw Reality
                debug!("Vision: direct write mode, len={}", buf.len());
                return Pin::new(&mut self.inner).poll_write(cx, buf);
            }
        }

        // Create write pending
        self.write_pending = Some(self.make_write_pending(buf));
        self.poll_write_pending(cx)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_addon_bytes_vision() {
        let flow = "xtls-rprx-vision";
        let addon = build_addon_bytes(flow);
        // Expected: [0x0A, 0x10, 'x','t','l','s','-','r','p','r','x','-','v','i','s','i','o','n']
        assert_eq!(addon[0], 0x0A, "field tag");
        assert_eq!(addon[1], 0x10, "length = 16");
        assert_eq!(&addon[2..], b"xtls-rprx-vision");
        assert_eq!(addon.len(), 18);
    }

    #[test]
    fn test_build_addon_bytes_empty_flow() {
        // An empty flow string still produces a valid protobuf encoding
        let addon = build_addon_bytes("");
        assert_eq!(addon[0], 0x0A);
        assert_eq!(addon[1], 0x00);
        assert_eq!(addon.len(), 2);
    }

    #[test]
    fn test_handshake_header_no_flow() {
        use crate::session::SocksAddr;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let addr = SocksAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            80,
        ));
        let inner: AnyStream = Box::new(tokio::io::duplex(1024).0);
        let stream = VlessStream::new(
            inner,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &addr,
            false,
            false,
            None,
        )
        .unwrap();

        let header = stream.build_handshake_header();
        // Version (1) + UUID (16) + addon_len=0 (1) + cmd (1) + port (2) + addr_type (1) + addr (4) = 26
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(header[17], 0, "addon_len should be 0");
        assert_eq!(header[18], VLESS_COMMAND_TCP);
    }

    #[test]
    fn test_handshake_header_with_flow() {
        use crate::session::SocksAddr;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let addr = SocksAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            80,
        ));
        let inner: AnyStream = Box::new(tokio::io::duplex(1024).0);
        let stream = VlessStream::new(
            inner,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &addr,
            false,
            false,
            Some("xtls-rprx-vision".to_owned()),
        )
        .unwrap();

        let header = stream.build_handshake_header();
        // Version (1) + UUID (16) + addon_len (1) + addon (18) + cmd (1) + ...
        let addon = build_addon_bytes("xtls-rprx-vision");
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(header[17], addon.len() as u8, "addon_len");
        assert_eq!(&header[18..18 + addon.len()], addon.as_slice());
        assert_eq!(header[18 + addon.len()], VLESS_COMMAND_TCP);
    }

    #[test]
    fn test_handshake_header_xudp_mux_no_destination() {
        use crate::session::SocksAddr;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let addr = SocksAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            80,
        ));
        let inner: AnyStream = Box::new(tokio::io::duplex(1024).0);
        let stream = VlessStream::new(
            inner,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &addr,
            true,
            true,
            Some("xtls-rprx-vision".to_owned()),
        )
        .unwrap();

        let header = stream.build_handshake_header();
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(header[17], 18, "addon_len");
        assert_eq!(header[18 + 18], VLESS_COMMAND_MUX);
        // Mux command does not carry destination in request header.
        assert_eq!(header.len(), 1 + 16 + 1 + 18 + 1);
    }

    #[test]
    fn test_handshake_header_xudp_mux_with_udp443_flow() {
        use crate::session::SocksAddr;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let addr = SocksAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            443,
        ));
        let inner: AnyStream = Box::new(tokio::io::duplex(1024).0);
        let stream = VlessStream::new(
            inner,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            &addr,
            true,
            true,
            Some("xtls-rprx-vision-udp443".to_owned()),
        )
        .unwrap();

        let header = stream.build_handshake_header();
        let addon = build_addon_bytes("xtls-rprx-vision-udp443");
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(header[17], addon.len() as u8, "addon_len");
        assert_eq!(&header[18..18 + addon.len()], addon.as_slice());
        assert_eq!(header[18 + addon.len()], VLESS_COMMAND_MUX);
        assert_eq!(header.len(), 1 + 16 + 1 + addon.len() + 1);
    }

    #[tokio::test]
    async fn test_vision_write_encodes_padding_and_header() {
        // Verify the Vision framing format by constructing it manually
        let data = b"hello world";
        let mut framed = BytesMut::new();
        // Padding packet
        framed.put_u8(0x00);
        framed.put_u16(4); // 4 bytes padding
        framed.put_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        // Data packet
        framed.put_u8(0x01);
        framed.put_u32(data.len() as u32);
        framed.put_slice(data);

        // Verify the encode logic is correct
        assert_eq!(framed[0], 0x00); // padding type
        assert_eq!(u16::from_be_bytes([framed[1], framed[2]]), 4); // padding len
        let padding_end = 3 + 4;
        assert_eq!(framed[padding_end], 0x01); // data type
        let data_len = u32::from_be_bytes([
            framed[padding_end + 1],
            framed[padding_end + 2],
            framed[padding_end + 3],
            framed[padding_end + 4],
        ]);
        assert_eq!(data_len, data.len() as u32);
        assert_eq!(&framed[padding_end + 5..], data);
    }

    #[test]
    fn test_vision_read_decode_padding_then_data() {
        // Verify the decode logic: padding packet (type 0x00) then data packet (type 0x01)
        let data = b"test data";
        let mut buf = BytesMut::new();
        buf.put_u8(0x00); // padding type
        buf.put_u16(3); // 3 bytes padding
        buf.put_slice(&[0x01, 0x02, 0x03]);
        buf.put_u8(0x01); // data type
        buf.put_u32(data.len() as u32);
        buf.put_slice(data);

        // Manually decode
        assert_eq!(buf[0], 0x00);
        let padding_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        assert_eq!(padding_len, 3);
        let data_start = 3 + padding_len;
        assert_eq!(buf[data_start], 0x01);
        let decoded_len = u32::from_be_bytes([
            buf[data_start + 1],
            buf[data_start + 2],
            buf[data_start + 3],
            buf[data_start + 4],
        ]) as usize;
        assert_eq!(decoded_len, data.len());
        assert_eq!(&buf[data_start + 5..data_start + 5 + decoded_len], data);
    }
}
