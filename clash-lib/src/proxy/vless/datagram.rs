use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace};

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::SocksAddr,
};

const MAX_PACKET_LENGTH: usize = 1024 << 3; // 8KB max packet length

pub struct OutboundDatagramVless {
    inner: AnyStream,
    remote_addr: SocksAddr,

    // Write state
    write_buf: BytesMut,
    pending_packet: Option<UdpPacket>,

    // Read state
    read_buf: Vec<u8>,
    remaining_bytes: usize,
    length_buf: [u8; 2],

    // State tracking
    flushed: bool,
}

impl OutboundDatagramVless {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr) -> Self {
        Self {
            inner,
            remote_addr,
            write_buf: BytesMut::new(),
            pending_packet: None,
            read_buf: vec![0u8; 65536],
            remaining_bytes: 0,
            length_buf: [0; 2],
            flushed: true,
        }
    }

    fn write_packet(&mut self, payload: &[u8]) -> Result<(), io::Error> {
        self.write_buf.clear();

        // VLESS UDP packet format is simpler than expected:
        // Just 2-byte length + payload data
        // No address encoding in the packet data phase!

        if payload.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "packet too large: {} > {}",
                    payload.len(),
                    MAX_PACKET_LENGTH
                ),
            ));
        }

        // Write length header (big-endian)
        self.write_buf.put_u16(payload.len() as u16);

        // Write payload
        self.write_buf.put_slice(payload);

        trace!("encoded VLESS UDP packet: len={}", payload.len());
        Ok(())
    }
}

impl Sink<UdpPacket> for OutboundDatagramVless {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();

        if this.pending_packet.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous packet not yet sent",
            ));
        }

        // Handle large packets by chunking them
        let total_len = item.data.len();
        if total_len == 0 {
            return Ok(()); // Skip empty packets
        }

        // For now, handle first chunk or small packets
        let chunk_size = if total_len <= MAX_PACKET_LENGTH {
            total_len
        } else {
            MAX_PACKET_LENGTH
        };

        this.write_packet(&item.data[..chunk_size])?;
        this.pending_packet = Some(item);
        this.flushed = false;

        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();

        if this.write_buf.is_empty() {
            this.flushed = true;
            this.pending_packet = None;
            return Poll::Ready(Ok(()));
        }

        let mut inner = Pin::new(&mut this.inner);

        // Write the encoded packet
        while !this.write_buf.is_empty() {
            let n = ready!(inner.as_mut().poll_write(cx, &this.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write packet data",
                )));
            }
            this.write_buf.advance(n);
        }

        // Flush the underlying stream
        ready!(inner.poll_flush(cx))?;

        if let Some(packet) = &this.pending_packet {
            debug!("sent VLESS UDP packet, data_len={}", packet.data.len());
        }

        this.flushed = true;
        this.pending_packet = None;

        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for OutboundDatagramVless {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);

        loop {
            // If we have remaining bytes from a previous packet, read them
            if this.remaining_bytes > 0 {
                let to_read =
                    std::cmp::min(this.remaining_bytes, this.read_buf.len());
                let mut read_buf = ReadBuf::new(&mut this.read_buf[..to_read]);

                match ready!(inner.as_mut().poll_read(cx, &mut read_buf)) {
                    Ok(()) => {
                        let data = read_buf.filled();
                        if data.is_empty() {
                            return Poll::Ready(None); // Connection closed
                        }

                        this.remaining_bytes -= data.len();

                        trace!(
                            "received VLESS UDP packet chunk, len={}, remaining={}",
                            data.len(),
                            this.remaining_bytes
                        );

                        return Poll::Ready(Some(UdpPacket {
                            data: data.to_vec(),
                            src_addr: this.remote_addr.clone(),
                            dst_addr: this.remote_addr.clone(),
                        }));
                    }
                    Err(e) => {
                        debug!("failed to read packet data: {}", e);
                        return Poll::Ready(None);
                    }
                }
            }

            // Read the 2-byte length header
            let mut length_read_buf = ReadBuf::new(&mut this.length_buf);
            match ready!(inner.as_mut().poll_read(cx, &mut length_read_buf)) {
                Ok(()) => {
                    let data = length_read_buf.filled();
                    if data.len() < 2 {
                        if data.is_empty() {
                            return Poll::Ready(None); // Connection closed
                        }
                        debug!("incomplete length header: {} bytes", data.len());
                        return Poll::Ready(None);
                    }

                    let packet_len = u16::from_be_bytes([data[0], data[1]]) as usize;

                    if packet_len == 0 {
                        trace!("received empty packet");
                        continue; // Skip empty packets
                    }

                    if packet_len > MAX_PACKET_LENGTH {
                        debug!("packet too large: {} bytes", packet_len);
                        return Poll::Ready(None);
                    }

                    // Set up to read the packet data
                    this.remaining_bytes = packet_len;

                    trace!("expecting VLESS UDP packet of {} bytes", packet_len);
                }
                Err(e) => {
                    debug!("failed to read length header: {}", e);
                    return Poll::Ready(None);
                }
            }
        }
    }
}

const XUDP_STATUS_NEW: u8 = 1;
const XUDP_STATUS_KEEP: u8 = 2;
const XUDP_STATUS_END: u8 = 3;
const XUDP_STATUS_KEEPALIVE: u8 = 4;

const XUDP_OPTION_DATA: u8 = 1;
const XUDP_OPTION_ERROR: u8 = 2;

const XUDP_NETWORK_UDP: u8 = 2;
const XUDP_READ_CHUNK_SIZE: usize = 2048;

enum XudpDecodeResult {
    NeedMore,
    Skip,
    Packet(UdpPacket),
    End,
}

fn vmess_addr_len(addr: &SocksAddr) -> usize {
    match addr {
        SocksAddr::Ip(std::net::SocketAddr::V4(_)) => 2 + 1 + 4,
        SocksAddr::Ip(std::net::SocketAddr::V6(_)) => 2 + 1 + 16,
        SocksAddr::Domain(domain, _) => 2 + 1 + 1 + domain.len(),
    }
}

fn parse_vmess_addr(buf: &[u8]) -> io::Result<(SocksAddr, usize)> {
    if buf.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess addr too short",
        ));
    }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    match buf[2] {
        0x01 => {
            if buf.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vmess ipv4 addr too short",
                ));
            }
            let ip = std::net::Ipv4Addr::new(buf[3], buf[4], buf[5], buf[6]);
            Ok((SocksAddr::from((ip, port)), 7))
        }
        0x03 => {
            if buf.len() < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vmess ipv6 addr too short",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[3..19]);
            let ip = std::net::Ipv6Addr::from(octets);
            Ok((SocksAddr::from((ip, port)), 19))
        }
        0x02 => {
            if buf.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vmess domain addr too short",
                ));
            }
            let domain_len = buf[3] as usize;
            let end = 4 + domain_len;
            if buf.len() < end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vmess domain addr too short",
                ));
            }
            let domain = String::from_utf8(buf[4..end].to_vec()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid vmess domain: {e}"),
                )
            })?;
            Ok((SocksAddr::Domain(domain, port), end))
        }
        atyp => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported vmess atyp: {atyp}"),
        )),
    }
}

pub struct OutboundDatagramVlessXudp {
    inner: AnyStream,
    destination: SocksAddr,
    request_written: bool,
    write_buf: BytesMut,
    read_buf: BytesMut,
    pending_packet: Option<UdpPacket>,
    flushed: bool,
}

impl OutboundDatagramVlessXudp {
    pub fn new(inner: AnyStream, destination: SocksAddr) -> Self {
        Self {
            inner,
            destination,
            request_written: false,
            write_buf: BytesMut::new(),
            read_buf: BytesMut::new(),
            pending_packet: None,
            flushed: true,
        }
    }

    fn encode_packet(&mut self, item: &UdpPacket) -> io::Result<()> {
        self.write_buf.clear();

        if item.data.is_empty() {
            return Ok(());
        }

        let dst = &item.dst_addr;
        let addr_len = vmess_addr_len(dst);
        let frame_len = 5 + addr_len;

        if item.data.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "xudp payload too large",
            ));
        }

        self.write_buf.put_u16(frame_len as u16);
        self.write_buf.put_u8(0);
        self.write_buf.put_u8(0);
        self.write_buf.put_u8(if self.request_written {
            XUDP_STATUS_KEEP
        } else {
            XUDP_STATUS_NEW
        });
        self.write_buf.put_u8(XUDP_OPTION_DATA);
        self.write_buf.put_u8(XUDP_NETWORK_UDP);
        dst.write_to_buf_vmess(&mut self.write_buf);
        self.write_buf.put_u16(item.data.len() as u16);
        self.write_buf.put_slice(&item.data);

        self.request_written = true;
        Ok(())
    }

    fn try_decode_packet(&mut self) -> io::Result<XudpDecodeResult> {
        if self.read_buf.len() < 2 {
            return Ok(XudpDecodeResult::NeedMore);
        }

        let frame_len =
            u16::from_be_bytes([self.read_buf[0], self.read_buf[1]]) as usize;
        if frame_len < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid xudp frame length: {frame_len}"),
            ));
        }

        if self.read_buf.len() < 6 {
            return Ok(XudpDecodeResult::NeedMore);
        }

        let status = self.read_buf[4];
        let option = self.read_buf[5];
        let mut source = self.destination.clone();
        let mut payload_len = 0usize;
        let mut consumed = 6usize;

        match status {
            XUDP_STATUS_NEW => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected xudp frame status NEW from remote",
                ));
            }
            XUDP_STATUS_END => {
                let frame_total = 2 + frame_len;
                if self.read_buf.len() < frame_total {
                    return Ok(XudpDecodeResult::NeedMore);
                }
                self.read_buf.advance(frame_total);
                return Ok(XudpDecodeResult::End);
            }
            XUDP_STATUS_KEEP => {
                if frame_len == 4 {
                    if self.read_buf.len() < consumed + 2 {
                        return Ok(XudpDecodeResult::NeedMore);
                    }
                    payload_len = u16::from_be_bytes([
                        self.read_buf[consumed],
                        self.read_buf[consumed + 1],
                    ]) as usize;
                    consumed += 2;
                } else if frame_len > 2 {
                    let tail_len = frame_len - 2;
                    if self.read_buf.len() < consumed + tail_len {
                        return Ok(XudpDecodeResult::NeedMore);
                    }
                    if tail_len < 3 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid xudp frame tail length: {tail_len}"),
                        ));
                    }

                    let tail_start = consumed;
                    let tail_end = consumed + tail_len;
                    let tail = &self.read_buf[tail_start..tail_end];

                    if tail[0] != XUDP_NETWORK_UDP {
                        debug!("unexpected xudp network type: {}", tail[0]);
                    }

                    let addr_slice = &tail[1..tail.len() - 2];
                    match parse_vmess_addr(addr_slice) {
                        Ok((addr, addr_consumed))
                            if addr_consumed == addr_slice.len() =>
                        {
                            source = addr;
                        }
                        Ok((_addr, addr_consumed)) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "invalid xudp addr length: consumed={}, total={}",
                                    addr_consumed,
                                    addr_slice.len()
                                ),
                            ));
                        }
                        Err(e) => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("failed to parse xudp addr: {e}"),
                            ));
                        }
                    }

                    payload_len = u16::from_be_bytes([
                        tail[tail.len() - 2],
                        tail[tail.len() - 1],
                    ]) as usize;
                    consumed = tail_end;
                }
            }
            XUDP_STATUS_KEEPALIVE => {
                if frame_len > 4 {
                    let tail_len = frame_len - 4;
                    if self.read_buf.len() < consumed + tail_len {
                        return Ok(XudpDecodeResult::NeedMore);
                    }
                    consumed += tail_len;
                }
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected xudp frame status: {other}"),
                ));
            }
        }

        if option & XUDP_OPTION_ERROR != 0 {
            self.read_buf.advance(consumed);
            return Ok(XudpDecodeResult::End);
        }

        if option & XUDP_OPTION_DATA == 0 {
            self.read_buf.advance(consumed);
            return Ok(XudpDecodeResult::Skip);
        }

        if payload_len == 0 {
            self.read_buf.advance(consumed);
            return Ok(XudpDecodeResult::Skip);
        }

        let frame_total = consumed + payload_len;
        if self.read_buf.len() < frame_total {
            return Ok(XudpDecodeResult::NeedMore);
        }

        let payload = self.read_buf[consumed..frame_total].to_vec();
        self.read_buf.advance(frame_total);

        Ok(XudpDecodeResult::Packet(UdpPacket {
            data: payload,
            src_addr: source,
            dst_addr: SocksAddr::any_ipv4(),
        }))
    }
}

impl Sink<UdpPacket> for OutboundDatagramVlessXudp {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if this.pending_packet.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous packet not yet sent",
            ));
        }

        this.encode_packet(&item)?;
        this.pending_packet = Some(item);
        this.flushed = false;
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);

        while !this.write_buf.is_empty() {
            let n = ready!(inner.as_mut().poll_write(cx, &this.write_buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write xudp packet",
                )));
            }
            this.write_buf.advance(n);
        }

        ready!(inner.poll_flush(cx))?;

        if let Some(pkt) = &this.pending_packet {
            debug!(
                "sent VLESS XUDP packet, data_len={}, dst={}",
                pkt.data.len(),
                pkt.dst_addr
            );
        }

        this.pending_packet = None;
        this.flushed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for OutboundDatagramVlessXudp {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            match this.try_decode_packet() {
                Ok(XudpDecodeResult::Packet(pkt)) => return Poll::Ready(Some(pkt)),
                Ok(XudpDecodeResult::Skip) => continue,
                Ok(XudpDecodeResult::End) => return Poll::Ready(None),
                Ok(XudpDecodeResult::NeedMore) => {}
                Err(e) => {
                    debug!("failed to decode xudp frame: {e}");
                    return Poll::Ready(None);
                }
            }

            let mut chunk = [0u8; XUDP_READ_CHUNK_SIZE];
            let mut rb = ReadBuf::new(&mut chunk);
            let mut inner = Pin::new(&mut this.inner);
            match inner.as_mut().poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        if !this.read_buf.is_empty() {
                            debug!(
                                "xudp connection closed with incomplete frame: {} bytes buffered",
                                this.read_buf.len()
                            );
                        }
                        return Poll::Ready(None);
                    }
                    this.read_buf.extend_from_slice(&chunk[..n]);
                }
                Poll::Ready(Err(e)) => {
                    debug!("failed to read xudp frame: {e}");
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::{Duration, timeout},
    };

    fn v4(ip: [u8; 4], port: u16) -> SocksAddr {
        SocksAddr::from((std::net::Ipv4Addr::from(ip), port))
    }

    fn build_keep_frame_with_addr(src: &SocksAddr, payload: &[u8]) -> Vec<u8> {
        let mut frame = BytesMut::new();
        let addr_len = vmess_addr_len(src);
        frame.put_u16((5 + addr_len) as u16);
        frame.put_u8(0);
        frame.put_u8(0);
        frame.put_u8(XUDP_STATUS_KEEP);
        frame.put_u8(XUDP_OPTION_DATA);
        frame.put_u8(XUDP_NETWORK_UDP);
        src.write_to_buf_vmess(&mut frame);
        frame.put_u16(payload.len() as u16);
        frame.put_slice(payload);
        frame.to_vec()
    }

    fn build_keep_frame_without_addr(payload: &[u8]) -> Vec<u8> {
        let mut frame = BytesMut::new();
        frame.put_u16(4);
        frame.put_u8(0);
        frame.put_u8(0);
        frame.put_u8(XUDP_STATUS_KEEP);
        frame.put_u8(XUDP_OPTION_DATA);
        frame.put_u16(payload.len() as u16);
        frame.put_slice(payload);
        frame.to_vec()
    }

    #[tokio::test]
    async fn test_xudp_write_new_then_keep() {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut d =
            OutboundDatagramVlessXudp::new(Box::new(client), v4([9, 9, 9, 9], 53));
        let dst = v4([1, 2, 3, 4], 5353);

        d.send(UdpPacket {
            data: b"abc".to_vec(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: dst.clone(),
        })
        .await
        .unwrap();

        let mut first = vec![0u8; 19];
        server.read_exact(&mut first).await.unwrap();
        assert_eq!(u16::from_be_bytes([first[0], first[1]]), 12);
        assert_eq!(first[4], XUDP_STATUS_NEW);
        assert_eq!(first[5], XUDP_OPTION_DATA);
        assert_eq!(first[6], XUDP_NETWORK_UDP);
        assert_eq!(u16::from_be_bytes([first[7], first[8]]), 5353);
        assert_eq!(first[9], 0x01);
        assert_eq!(&first[10..14], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([first[14], first[15]]), 3);
        assert_eq!(&first[16..19], b"abc");

        d.send(UdpPacket {
            data: b"z".to_vec(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: dst,
        })
        .await
        .unwrap();

        let mut second = vec![0u8; 17];
        server.read_exact(&mut second).await.unwrap();
        assert_eq!(u16::from_be_bytes([second[0], second[1]]), 12);
        assert_eq!(second[4], XUDP_STATUS_KEEP);
        assert_eq!(u16::from_be_bytes([second[14], second[15]]), 1);
        assert_eq!(&second[16..17], b"z");
    }

    #[tokio::test]
    async fn test_xudp_read_keep_with_addr() {
        let (client, mut server) = tokio::io::duplex(4096);
        let fallback = v4([9, 9, 9, 9], 53);
        let src = v4([8, 8, 8, 8], 443);
        let mut d = OutboundDatagramVlessXudp::new(Box::new(client), fallback);
        let frame = build_keep_frame_with_addr(&src, b"hello");

        server.write_all(&frame).await.unwrap();

        let pkt = timeout(Duration::from_secs(1), d.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pkt.src_addr, src);
        assert_eq!(pkt.data, b"hello");
    }

    #[tokio::test]
    async fn test_xudp_read_keep_without_addr_uses_fallback() {
        let (client, mut server) = tokio::io::duplex(4096);
        let fallback = v4([4, 4, 4, 4], 8443);
        let mut d =
            OutboundDatagramVlessXudp::new(Box::new(client), fallback.clone());
        let frame = build_keep_frame_without_addr(b"ok");

        server.write_all(&frame).await.unwrap();

        let pkt = timeout(Duration::from_secs(1), d.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pkt.src_addr, fallback);
        assert_eq!(pkt.data, b"ok");
    }

    #[tokio::test]
    async fn test_xudp_read_fragmented_frame() {
        let (client, mut server) = tokio::io::duplex(4096);
        let fallback = v4([7, 7, 7, 7], 1234);
        let mut d =
            OutboundDatagramVlessXudp::new(Box::new(client), fallback.clone());
        let frame = build_keep_frame_without_addr(b"fragment");

        tokio::spawn(async move {
            for b in frame {
                server.write_all(&[b]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let pkt = timeout(Duration::from_secs(1), d.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pkt.src_addr, fallback);
        assert_eq!(pkt.data, b"fragment");
    }
}
