use std::{io, pin::Pin, task::{Context, Poll}, vec};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace};

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::SocksAddr,
};

const MAX_PACKET_LENGTH: usize = 1024 << 3; // 8KB max

pub struct OutboundDatagramVless {
    inner: AnyStream,
    remote_addr: SocksAddr,
    write_buf: BytesMut,
    pending_packet: Option<UdpPacket>,
    read_buf: vec::Vec<u8>,
    remaining_bytes: usize,
    length_buf: [u8; 2],
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
        if payload.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet too large"));
        }
        self.write_buf.put_u16(payload.len() as u16);
        self.write_buf.put_slice(payload);
        Ok(())
    }
}

impl Sink<UdpPacket> for OutboundDatagramVless {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            ready!(self.poll_flush(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if this.pending_packet.is_some() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "previous packet not yet sent"));
        }
        if item.data.is_empty() { return Ok(()); }
        let chunk_size = item.data.len().min(MAX_PACKET_LENGTH);
        this.write_packet(&item.data[..chunk_size])?;
        this.pending_packet = Some(item);
        this.flushed = false;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.flushed { return Poll::Ready(Ok(())); }
        if this.write_buf.is_empty() {
            this.flushed = true;
            this.pending_packet = None;
            return Poll::Ready(Ok(()));
        }

        let mut inner = Pin::new(&mut this.inner);
        while !this.write_buf.is_empty() {
            let n = ready!(inner.as_mut().poll_write(cx, &this.write_buf))?;
            if n == 0 { return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write UDP"))); }
            this.write_buf.advance(n);
        }

        ready!(inner.poll_flush(cx))?;
        this.flushed = true;
        this.pending_packet = None;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for OutboundDatagramVless {
    type Item = UdpPacket;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);

        loop {
            if this.remaining_bytes > 0 {
                let to_read = this.remaining_bytes.min(this.read_buf.len());
                let mut read_buf = ReadBuf::new(&mut this.read_buf[..to_read]);
                match ready!(inner.as_mut().poll_read(cx, &mut read_buf)) {
                    Ok(()) => {
                        let data = read_buf.filled();
                        if data.is_empty() { return Poll::Ready(None); }
                        this.remaining_bytes -= data.len();
                        return Poll::Ready(Some(UdpPacket {
                            data: data.to_vec(),
                            src_addr: this.remote_addr.clone(),
                            dst_addr: this.remote_addr.clone(),
                        }));
                    }
                    Err(_) => return Poll::Ready(None),
                }
            }

            let mut length_read_buf = ReadBuf::new(&mut this.length_buf);
            match ready!(inner.as_mut().poll_read(cx, &mut length_read_buf)) {
                Ok(()) => {
                    let data = length_read_buf.filled();
                    if data.len() < 2 { return Poll::Ready(None); }
                    let packet_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                    if packet_len == 0 { continue; }
                    if packet_len > MAX_PACKET_LENGTH { return Poll::Ready(None); }
                    this.remaining_bytes = packet_len;
                }
                Err(_) => return Poll::Ready(None),
            }
        }
    }
}

// XUDP implementation unchanged - standard protocol spec
const XUDP_STATUS_NEW: u8 = 1;
const XUDP_STATUS_KEEP: u8 = 2;
const XUDP_STATUS_END: u8 = 3;
const XUDP_STATUS_KEEPALIVE: u8 = 4;
const XUDP_OPTION_DATA: u8 = 1;
const XUDP_OPTION_ERROR: u8 = 2;
const XUDP_NETWORK_UDP: u8 = 2;
const XUDP_READ_CHUNK_SIZE: usize = 2048;

enum XudpDecodeResult {
    NeedMore, Skip, Packet(UdpPacket), End,
}

fn vmess_addr_len(addr: &SocksAddr) -> usize {
    match addr {
        SocksAddr::Ip(std::net::SocketAddr::V4(_)) => 7,
        SocksAddr::Ip(std::net::SocketAddr::V6(_)) => 19,
        SocksAddr::Domain(domain, _) => 4 + domain.len(),
    }
}

fn parse_vmess_addr(buf: &[u8]) -> io::Result<(SocksAddr, usize)> {
    if buf.len() < 3 { return Err(io::Error::new(io::ErrorKind::InvalidData, "too short")); }
    let port = u16::from_be_bytes([buf[0], buf[1]]);
    match buf[2] {
        0x01 => {
            if buf.len() < 7 { return Err(io::Error::new(io::ErrorKind::InvalidData, "ipv4 short")); }
            Ok((SocksAddr::from((std::net::Ipv4Addr::new(buf[3], buf[4], buf[5], buf[6]), port)), 7))
        }
        0x03 => {
            if buf.len() < 19 { return Err(io::Error::new(io::ErrorKind::InvalidData, "ipv6 short")); }
            let mut octets = [0u8; 16]; octets.copy_from_slice(&buf[3..19]);
            Ok((SocksAddr::from((std::net::Ipv6Addr::from(octets), port)), 19))
        }
        0x02 => {
            if buf.len() < 4 { return Err(io::Error::new(io::ErrorKind::InvalidData, "domain short")); }
            let domain_len = buf[3] as usize;
            let end = 4 + domain_len;
            if buf.len() < end { return Err(io::Error::new(io::ErrorKind::InvalidData, "domain short")); }
            let domain = String::from_utf8(buf[4..end].to_vec()).unwrap_or_default();
            Ok((SocksAddr::Domain(domain, port), end))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported atyp")),
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
            inner, destination, request_written: false,
            write_buf: BytesMut::new(), read_buf: BytesMut::new(),
            pending_packet: None, flushed: true,
        }
    }

    fn encode_packet(&mut self, item: &UdpPacket) -> io::Result<()> {
        self.write_buf.clear();
        if item.data.is_empty() { return Ok(()); }
        let dst = &item.dst_addr;
        let frame_len = 5 + vmess_addr_len(dst);
        self.write_buf.put_u16(frame_len as u16);
        self.write_buf.put_u8(0);
        self.write_buf.put_u8(0);
        self.write_buf.put_u8(if self.request_written { XUDP_STATUS_KEEP } else { XUDP_STATUS_NEW });
        self.write_buf.put_u8(XUDP_OPTION_DATA);
        self.write_buf.put_u8(XUDP_NETWORK_UDP);
        dst.write_to_buf_vmess(&mut self.write_buf);
        self.write_buf.put_u16(item.data.len() as u16);
        self.write_buf.put_slice(&item.data);
        self.request_written = true;
        Ok(())
    }

    fn try_decode_packet(&mut self) -> io::Result<XudpDecodeResult> {
        if self.read_buf.len() < 2 { return Ok(XudpDecodeResult::NeedMore); }
        let frame_len = u16::from_be_bytes([self.read_buf[0], self.read_buf[1]]) as usize;
        if frame_len < 4 { return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid xudp length")); }
        if self.read_buf.len() < 6 { return Ok(XudpDecodeResult::NeedMore); }

        let status = self.read_buf[4];
        let option = self.read_buf[5];
        let mut source = self.destination.clone();
        let mut payload_len = 0usize;
        let mut consumed = 6usize;

        match status {
            XUDP_STATUS_END => {
                if self.read_buf.len() < 2 + frame_len { return Ok(XudpDecodeResult::NeedMore); }
                self.read_buf.advance(2 + frame_len);
                return Ok(XudpDecodeResult::End);
            }
            XUDP_STATUS_KEEP => {
                if frame_len == 4 {
                    if self.read_buf.len() < consumed + 2 { return Ok(XudpDecodeResult::NeedMore); }
                    payload_len = u16::from_be_bytes([self.read_buf[consumed], self.read_buf[consumed + 1]]) as usize;
                    consumed += 2;
                } else if frame_len > 2 {
                    let tail_len = frame_len - 2;
                    if self.read_buf.len() < consumed + tail_len { return Ok(XudpDecodeResult::NeedMore); }
                    let tail = &self.read_buf[consumed..consumed + tail_len];
                    let addr_slice = &tail[1..tail.len() - 2];
                    if let Ok((addr, _)) = parse_vmess_addr(addr_slice) { source = addr; }
                    payload_len = u16::from_be_bytes([tail[tail.len() - 2], tail[tail.len() - 1]]) as usize;
                    consumed += tail_len;
                }
            }
            XUDP_STATUS_KEEPALIVE => {
                if frame_len > 4 {
                    let tail_len = frame_len - 4;
                    if self.read_buf.len() < consumed + tail_len { return Ok(XudpDecodeResult::NeedMore); }
                    consumed += tail_len;
                }
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported xudp status")),
        }

        if option & XUDP_OPTION_ERROR != 0 {
            self.read_buf.advance(consumed);
            return Ok(XudpDecodeResult::End);
        }
        if option & XUDP_OPTION_DATA == 0 || payload_len == 0 {
            self.read_buf.advance(consumed);
            return Ok(XudpDecodeResult::Skip);
        }

        if self.read_buf.len() < consumed + payload_len { return Ok(XudpDecodeResult::NeedMore); }
        let payload = self.read_buf[consumed..consumed + payload_len].to_vec();
        self.read_buf.advance(consumed + payload_len);
        Ok(XudpDecodeResult::Packet(UdpPacket { data: payload, src_addr: source, dst_addr: SocksAddr::any_ipv4() }))
    }
}

impl Sink<UdpPacket> for OutboundDatagramVlessXudp {
    type Error = io::Error;
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.flushed { ready!(self.poll_flush(cx))?; }
        Poll::Ready(Ok(()))
    }
    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.encode_packet(&item)?;
        this.pending_packet = Some(item);
        this.flushed = false;
        Ok(())
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.flushed { return Poll::Ready(Ok(())); }
        let mut inner = Pin::new(&mut this.inner);
        while !this.write_buf.is_empty() {
            let n = ready!(inner.as_mut().poll_write(cx, &this.write_buf))?;
            if n == 0 { return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "xudp write zero"))); }
            this.write_buf.advance(n);
        }
        ready!(inner.poll_flush(cx))?;
        this.pending_packet = None;
        this.flushed = true;
        Poll::Ready(Ok(()))
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for OutboundDatagramVlessXudp {
    type Item = UdpPacket;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.try_decode_packet() {
                Ok(XudpDecodeResult::Packet(pkt)) => return Poll::Ready(Some(pkt)),
                Ok(XudpDecodeResult::Skip) => continue,
                Ok(XudpDecodeResult::End) => return Poll::Ready(None),
                Ok(XudpDecodeResult::NeedMore) => {}
                Err(_) => return Poll::Ready(None),
            }
            let mut chunk = [0u8; XUDP_READ_CHUNK_SIZE];
            let mut rb = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 { return Poll::Ready(None); }
                    this.read_buf.extend_from_slice(&chunk[..n]);
                }
                Poll::Ready(Err(_)) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}