use anyhow::{Context, Result};
use pcap_parser::{
    LegacyPcapReader, Linktype, PcapBlockOwned, PcapError, traits::PcapReaderIterator,
};
use rustc_hash::FxHashMap;

use crate::playbook_capnp::HttpMethod;

/// A simplified HTTP request structure extracted from tcpdump.
pub struct HttpRequest {
    /// HTTP method like GET, POST, etc.
    pub method: HttpMethod,
    /// HTTP request endpoint with parameters like `/route` or `/route?json={...}`
    pub uri: Box<str>,
    /// HTTP request headers like `content-type:application/x-protobuf`.
    /// Headers are stored as `key:value` strings to minimize memory overhead
    /// when keeping hundreds of thousands of requests in memory during load testing.
    pub headers: Box<[Box<str>]>,
    /// HTTP request body.
    pub body: Box<[u8]>,
}

/// An iterator over HTTP requests in a pcap file.
pub struct TcpDumpReader<R: std::io::Read> {
    pcap_reader: LegacyPcapReader<R>,
    /// An offset to consume from the inner reader.
    offset: usize,
    /// The linktype of the pcap file.
    linktype: Linktype,
    /// Pending HTTP requests, keyed by (source port, TCP sequence number).
    pending_requests: FxHashMap<(u16, u32), (HttpHeader, Vec<u8>)>,
}

impl<R: std::io::Read> TcpDumpReader<R> {
    pub fn new(reader: R) -> Result<Self> {
        // pcap_parser::create_reader(65536, reader);

        let mut reader =
            LegacyPcapReader::new(65536, reader).context("Failed to create pcap reader")?;

        // Pcap starts with a global header, so we need to consume it first to resolve the linktype
        let Ok((offset, PcapBlockOwned::LegacyHeader(header))) = reader.next() else {
            return Err(anyhow::anyhow!("Failed to read pcap file header"));
        };

        Ok(Self {
            pcap_reader: reader,
            offset,
            linktype: header.network,
            pending_requests: Default::default(),
        })
    }
}

impl<R: std::io::Read> Iterator for TcpDumpReader<R> {
    type Item = HttpRequest;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Consume previous offset upfront to workaround borrow checker limitations as it will
            // not be possible to consume it in the match statement below.
            self.pcap_reader.consume(self.offset);
            self.offset = 0;

            match self.pcap_reader.next() {
                Ok((offset, PcapBlockOwned::Legacy(block))) => {
                    self.offset = offset;
                    let Some(tcp_packet) = read_tcp_packet(block.data, self.linktype) else {
                        continue;
                    };

                    // Try to parse HTTP header from this TCP packet first.
                    if let Some((header, content_length)) = parse_http_header(tcp_packet.data) {
                        if content_length == 0 {
                            // Request without body that is fully contained in this TCP packet.
                            return Some(HttpRequest {
                                method: header.method,
                                uri: header.uri,
                                headers: header.headers,
                                body: Default::default(),
                            });
                        }

                        // Next frame is expected with sequence number after the header
                        let next_seq = tcp_packet.sequence_number + tcp_packet.data.len() as u32;
                        self.pending_requests.insert(
                            (tcp_packet.src_port, next_seq),
                            (header, Vec::with_capacity(content_length)),
                        );
                        continue;
                    }

                    // Maybe it's a body of a pending request?
                    let key = (tcp_packet.src_port, tcp_packet.sequence_number);
                    if let Some((header, mut body)) = self.pending_requests.remove(&key) {
                        // We have a header for this request. Let's fill the body.
                        body.extend_from_slice(tcp_packet.data);
                        if body.len() == body.capacity() {
                            // that was the last one
                            return Some(HttpRequest {
                                method: header.method,
                                uri: header.uri,
                                headers: header.headers,
                                body: body.into(),
                            });
                        }

                        // Next frame is expected with sequence number after the current body
                        let next_seq = tcp_packet.sequence_number + tcp_packet.data.len() as u32;
                        self.pending_requests
                            .insert((tcp_packet.src_port, next_seq), (header, body));
                    }
                }
                Err(PcapError::Incomplete(_)) => {
                    if self.pcap_reader.refill().is_err() {
                        return None; // reading error
                    }
                }
                _ => {
                    return None; // EOF or any reading error
                }
            }
        }
    }
}

/// A simplified TCP packet structure that only contains fields relevant parsing HTTP requests.
struct TcpPacket<'a> {
    /// Source port. Together with sequence number, used to identify unique TCP streams.
    src_port: u16,
    /// TCP sequence number. Together with source port, used to identify unique TCP streams.
    sequence_number: u32,
    /// TCP payload data. Might contain HTTP request header or body.
    data: &'a [u8],
}

/// Reads a TCP packet from raw packet data, given the linktype.
/// Skips non-TCP packets and TCP packets with no payload.
fn read_tcp_packet(data: &[u8], linktype: Linktype) -> Option<TcpPacket<'_>> {
    let ip_packet = match linktype {
        Linktype::ETHERNET => {
            assert_eq!(u16::from_be_bytes([data[12], data[13]]), 0x0800);
            &data[14..]
        }
        Linktype::LINUX_SLL2 => {
            assert_eq!(u16::from_be_bytes([data[0], data[1]]), 0x0800);
            &data[20..]
        }
        _ => {
            todo!("Unsupported linktype: {linktype:?}");
        }
    };

    // https://en.wikipedia.org/wiki/IPv4#Header
    let ip_version_and_ihl = ip_packet[0];
    let version = ip_version_and_ihl >> 4;
    if version != 4 {
        println!("Not an IPv4 packet (Version: {}).", version);
        return None; // todo: Support IPv6
    }
    let ip_protocol = ip_packet[9];
    if ip_protocol != 6 {
        println!("Not a TCP packet (Protocol: {ip_protocol}).");
        return None;
    }

    let ihl = (ip_version_and_ihl & 0x0f) as usize * 4;
    let tcp_packet = &ip_packet[ihl..];

    // https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    let data_offset = (tcp_packet[12] >> 4) as usize * 4;
    if tcp_packet.len() <= data_offset {
        return None; // Skip TCP packets with no payload
    }

    Some(TcpPacket {
        src_port: u16::from_be_bytes([tcp_packet[0], tcp_packet[1]]),
        sequence_number: u32::from_be_bytes([
            tcp_packet[4],
            tcp_packet[5],
            tcp_packet[6],
            tcp_packet[7],
        ]),
        data: &tcp_packet[data_offset..],
    })
}

struct HttpHeader {
    method: HttpMethod,
    uri: Box<str>,
    headers: Box<[Box<str>]>,
}

/// Parses an HTTP request header from raw data. 'Content-Length' header is omitted and its value is returned instead.
fn parse_http_header(data: &[u8]) -> Option<(HttpHeader, usize)> {
    if !data.ends_with(b"\r\n\r\n") {
        return None;
    }

    let request_str = String::from_utf8_lossy(data);
    let mut lines = request_str.lines();

    let request_line = lines.next()?;
    let mut request_parts = request_line.split_whitespace();
    let method = match request_parts.next()? {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        "PATCH" => HttpMethod::Patch,
        "TRACE" => HttpMethod::Trace,
        _ => return None,
    };
    let uri = request_parts.next()?;

    let mut headers = Vec::new();
    let mut content_length = 0;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };

        let key = key.trim();
        let value = value.trim();
        match key {
            "Host" | "Connection" => (), // ignore as any HTTP client will override them anyway
            "Traceparent" | "Tracestate" | "Baggage" => (), // trace headers should be ignored
            "Content-Length" => {
                let Ok(length) = value.parse::<usize>() else {
                    println!("Invalid Content-Length: {}", value);
                    return None;
                };
                content_length = length;
            }
            key => headers.push(format!("{key}:{value}").into()),
        }
    }

    Some((
        HttpHeader {
            method,
            uri: uri.into(),
            headers: headers.into(),
        },
        content_length,
    ))
}
