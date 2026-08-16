//! Source-address and trusted-header authorization gate for shared ttyd.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use super::upload::{IMAGE_UPLOAD_PATH, ImageUploadErr, ImageUploadStore, MAX_IMAGE_BYTES};
use super::{Result, WebErr};

const MAX_REQUEST_HEAD: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;
const MAX_CHUNK_LINE: usize = 8 * 1024;
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const IMAGE_UPLOAD_HEADER: &str = "X-RimZ-Upload";
const IMAGE_UPLOAD_HEADER_VALUE: &[u8] = b"image";
const UNAUTHORIZED: &[u8] =
    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const FORBIDDEN: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const LENGTH_REQUIRED: &[u8] =
    b"HTTP/1.1 411 Length Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const METHOD_NOT_ALLOWED: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\nAllow: POST\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const PAYLOAD_TOO_LARGE: &[u8] =
    b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateAuth {
    pub header_name: String,
    pub allowed_users: Vec<String>,
    pub authorization: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayTarget {
    pub upstream: SocketAddr,
    pub authorization: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Cidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl Cidr {
    pub(super) fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value
            .split_once('/')
            .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
        let address = address
            .parse::<IpAddr>()
            .map_err(|err| invalid(value, err.to_string()))?;
        match address {
            IpAddr::V4(address) => {
                let prefix = parse_prefix(value, prefix, 32)?;
                Ok(Self::V4 {
                    network: address.to_bits(),
                    prefix,
                })
            }
            IpAddr::V6(address) => {
                let prefix = parse_prefix(value, prefix, 128)?;
                Ok(Self::V6 {
                    network: address.to_bits(),
                    prefix,
                })
            }
        }
    }

    pub(super) fn contains(&self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => prefix_matches(
                u128::from(*network),
                u128::from(address.to_bits()),
                *prefix,
                32,
            ),
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                prefix_matches(*network, address.to_bits(), *prefix, 128)
            }
            (Self::V4 { .. }, IpAddr::V6(_)) | (Self::V6 { .. }, IpAddr::V4(_)) => false,
        }
    }
}

fn parse_prefix(value: &str, prefix: Option<&str>, width: u8) -> Result<u8> {
    let Some(prefix) = prefix else {
        return Ok(width);
    };
    let prefix = prefix
        .parse::<u8>()
        .map_err(|err| invalid(value, format!("invalid prefix length: {err}")))?;
    if prefix > width {
        return Err(invalid(
            value,
            format!("prefix length {prefix} exceeds {width}"),
        ));
    }
    Ok(prefix)
}

fn prefix_matches(network: u128, address: u128, prefix: u8, width: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = u32::from(width - prefix);
    network >> shift == address >> shift
}

fn invalid(value: &str, reason: String) -> WebErr {
    WebErr::InvalidTrustedProxy {
        value: value.to_owned(),
        reason,
    }
}

pub(super) fn peer_allowed(peer: IpAddr, allow: &[Cidr]) -> bool {
    let peer = match peer {
        IpAddr::V6(address) => address.to_ipv4_mapped().map_or(peer, IpAddr::V4),
        IpAddr::V4(_) => peer,
    };
    peer.is_loopback() || allow.iter().any(|cidr| cidr.contains(peer))
}

/// 仅 Basic 的 public gate 未配置来源限制时保持 ttyd 的原有可达性。
fn peer_admitted(peer: IpAddr, allow: &[Cidr], restrict_peers: bool) -> bool {
    !restrict_peers || peer_allowed(peer, allow)
}

pub(super) fn serve(
    listen: SocketAddr,
    upstream: SocketAddr,
    allow: Vec<Cidr>,
    auth: Option<GateAuth>,
    uploads: Option<ImageUploadStore>,
    basic_authorization: Option<String>,
    tunnel_listen: Option<SocketAddr>,
) -> Result<()> {
    let listener = TcpListener::bind(listen).map_err(|source| WebErr::GateIo {
        action: "binding its listener",
        source,
    })?;
    if let Some(tunnel_listen) = tunnel_listen {
        let tunnel_listener =
            TcpListener::bind(tunnel_listen).map_err(|source| WebErr::GateIo {
                action: "binding its tunnel listener",
                source,
            })?;
        let tunnel_uploads = uploads.clone();
        let tunnel_authorization = basic_authorization.clone();
        std::thread::spawn(move || {
            let _ = serve_listener(
                tunnel_listener,
                upstream,
                Vec::new(),
                None,
                tunnel_uploads,
                tunnel_authorization,
                true,
            );
        });
    }
    let restrict_peers = auth.is_some() || !allow.is_empty();
    serve_listener(
        listener,
        upstream,
        allow,
        auth,
        uploads,
        basic_authorization,
        restrict_peers,
    )
}

/// 接受一个已绑定监听器，并按认证模式分派每条连接。
fn serve_listener(
    listener: TcpListener,
    upstream: SocketAddr,
    allow: Vec<Cidr>,
    auth: Option<GateAuth>,
    uploads: Option<ImageUploadStore>,
    basic_authorization: Option<String>,
    restrict_peers: bool,
) -> Result<()> {
    loop {
        let (client, peer) = match listener.accept() {
            Ok(connection) => connection,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(WebErr::GateIo {
                    action: "accepting a connection",
                    source,
                });
            }
        };
        if !peer_admitted(peer.ip(), &allow, restrict_peers) {
            continue;
        }
        let Ok(upstream) = TcpStream::connect_timeout(&upstream, UPSTREAM_CONNECT_TIMEOUT) else {
            continue;
        };
        if let Some(auth) = auth.clone() {
            let uploads = uploads.clone();
            std::thread::spawn(move || {
                relay_authorized(
                    client,
                    upstream,
                    Some(&auth.header_name),
                    &auth.allowed_users,
                    &auth.authorization,
                    uploads.as_ref(),
                );
            });
        } else if let (Some(uploads), Some(authorization)) =
            (uploads.clone(), basic_authorization.clone())
        {
            std::thread::spawn(move || {
                relay_basic_uploads(client, upstream, &authorization, &uploads);
            });
        } else {
            splice(client, upstream);
        }
    }
}

pub(super) fn serve_tunnel(listener: TcpListener, target: Arc<Mutex<RelayTarget>>) -> Result<()> {
    loop {
        let (client, peer) = match listener.accept() {
            Ok(connection) => connection,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(WebErr::GateIo {
                    action: "accepting a tunnel relay connection",
                    source,
                });
            }
        };
        if !peer_allowed(peer.ip(), &[]) {
            continue;
        }
        let target = target
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Ok(upstream) = TcpStream::connect_timeout(&target.upstream, UPSTREAM_CONNECT_TIMEOUT)
        else {
            continue;
        };
        std::thread::spawn(move || {
            relay_authorized(client, upstream, None, &[], &target.authorization, None);
        });
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RequestAction {
    Forward {
        head: Vec<u8>,
        content_length: u64,
        head_request: bool,
        upgrade: bool,
    },
    Upload {
        content_length: u64,
    },
    Unauthorized,
    Forbidden,
    LengthRequired,
    MethodNotAllowed,
    PayloadTooLarge,
    Close,
}

#[derive(Clone, Copy)]
enum RequestAuth<'a> {
    Basic {
        authorization: &'a str,
    },
    Inject {
        authorization: &'a str,
    },
    TrustedHeader {
        required_header: &'a str,
        allowed_users: &'a [String],
        authorization: &'a str,
    },
}

fn relay_authorized(
    client: TcpStream,
    upstream: TcpStream,
    required_header: Option<&str>,
    allowed_users: &[String],
    authorization: &str,
    uploads: Option<&ImageUploadStore>,
) {
    let auth = required_header.map_or(RequestAuth::Inject { authorization }, |required_header| {
        RequestAuth::TrustedHeader {
            required_header,
            allowed_users,
            authorization,
        }
    });
    relay_http(client, upstream, auth, uploads);
}

/// 保留普通 Basic Auth 请求，只在图片上传路径校验并消费请求体。
fn relay_basic_uploads(
    client: TcpStream,
    upstream: TcpStream,
    authorization: &str,
    uploads: &ImageUploadStore,
) {
    relay_http(
        client,
        upstream,
        RequestAuth::Basic { authorization },
        Some(uploads),
    );
}

/// 在同一 keep-alive 连接上分流 ttyd 请求和 RimZ 图片上传。
fn relay_http(
    mut client: TcpStream,
    mut upstream: TcpStream,
    auth: RequestAuth<'_>,
    uploads: Option<&ImageUploadStore>,
) {
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    let (Ok(client_read), Ok(upstream_read)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let mut client_read = BufReader::new(client_read);
    let mut upstream_read = BufReader::new(upstream_read);

    loop {
        let action = match read_request_head(&mut client_read) {
            Ok(Some(head)) => route_request_head(&head, auth, uploads.is_some()),
            Ok(None) => break,
            Err(_) => RequestAction::Close,
        };
        match action {
            RequestAction::Forward {
                head,
                content_length,
                head_request,
                upgrade,
            } => {
                if upstream.write_all(&head).is_err()
                    || copy_exact(&mut client_read, &mut upstream, content_length).is_err()
                {
                    break;
                }
                match relay_response(&mut upstream_read, &mut client, head_request, upgrade) {
                    Ok(ResponseAction::NextRequest) => {}
                    Ok(ResponseAction::Upgrade) => {
                        splice_buffered(client_read, upstream_read, client, upstream);
                        return;
                    }
                    Ok(ResponseAction::Close) | Err(_) => break,
                }
            }
            RequestAction::Upload { content_length } => {
                let Some(uploads) = uploads else {
                    break;
                };
                if handle_image_upload(&mut client_read, &mut client, content_length, uploads)
                    .is_err()
                {
                    break;
                }
            }
            RequestAction::Unauthorized => {
                let _ = client.write_all(UNAUTHORIZED);
                break;
            }
            RequestAction::Forbidden => {
                let _ = client.write_all(FORBIDDEN);
                break;
            }
            RequestAction::LengthRequired => {
                let _ = client.write_all(LENGTH_REQUIRED);
                break;
            }
            RequestAction::MethodNotAllowed => {
                let _ = client.write_all(METHOD_NOT_ALLOWED);
                break;
            }
            RequestAction::PayloadTooLarge => {
                let _ = client.write_all(PAYLOAD_TOO_LARGE);
                break;
            }
            RequestAction::Close => break,
        }
    }
    let _ = upstream.shutdown(Shutdown::Write);
    let _ = client.shutdown(Shutdown::Read);
}

/// 读取受限请求体、保存图片并返回不可缓存的 JSON 路径。
fn handle_image_upload(
    reader: &mut impl Read,
    client: &mut impl Write,
    content_length: u64,
    uploads: &ImageUploadStore,
) -> io::Result<()> {
    let length = usize::try_from(content_length)
        .map_err(|_| invalid_http("image upload length exceeds this platform"))?;
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    match uploads.store(&bytes) {
        Ok(path) => {
            let path = path
                .to_str()
                .ok_or_else(|| invalid_http("image upload path is not UTF-8"))?;
            let body = serde_json::to_vec(&serde_json::json!({
                "path": path,
            }))
            .map_err(|err| invalid_http(format!("image upload response failed: {err}")))?;
            write_json_response(client, 200, "OK", &body)
        }
        Err(ImageUploadErr::Empty) => {
            write_json_response(client, 400, "Bad Request", br#"{"error":"empty_image"}"#)
        }
        Err(ImageUploadErr::TooLarge { .. }) => write_json_response(
            client,
            413,
            "Content Too Large",
            br#"{"error":"image_too_large"}"#,
        ),
        Err(ImageUploadErr::Unsupported) => write_json_response(
            client,
            415,
            "Unsupported Media Type",
            br#"{"error":"unsupported_image"}"#,
        ),
        Err(err) => {
            tracing::warn!(error = %err, "browser image upload failed");
            write_json_response(
                client,
                500,
                "Internal Server Error",
                br#"{"error":"image_store_failed"}"#,
            )
        }
    }
}

/// 写出 keep-alive JSON 响应，供连续粘贴复用当前浏览器连接。
fn write_json_response(
    writer: &mut impl Write,
    status: u16,
    reason: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(
        writer,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )?;
    writer.write_all(body)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponseAction {
    NextRequest,
    Upgrade,
    Close,
}

fn relay_response(
    upstream: &mut impl BufRead,
    client: &mut impl Write,
    head_request: bool,
    upgrade_request: bool,
) -> io::Result<ResponseAction> {
    loop {
        let Some(head) = read_request_head(upstream)? else {
            return Ok(ResponseAction::Close);
        };
        let response = parse_response_head(&head)?;
        client.write_all(&head)?;
        if response.status == 101 {
            return Ok(if upgrade_request {
                ResponseAction::Upgrade
            } else {
                ResponseAction::Close
            });
        }
        if (100..200).contains(&response.status) {
            continue;
        }

        let no_body = head_request || matches!(response.status, 204 | 304);
        if !no_body {
            if response.chunked {
                relay_chunked(upstream, client)?;
            } else if let Some(content_length) = response.content_length {
                copy_exact(upstream, client, content_length)?;
            } else {
                io::copy(upstream, client)?;
                return Ok(ResponseAction::Close);
            }
        }
        return Ok(if response.connection_close {
            ResponseAction::Close
        } else {
            ResponseAction::NextRequest
        });
    }
}

struct ResponseHead {
    status: u16,
    content_length: Option<u64>,
    chunked: bool,
    connection_close: bool,
}

fn parse_response_head(head: &[u8]) -> io::Result<ResponseHead> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(parsed_len) = response
        .parse(head)
        .map_err(|err| invalid_http(format!("invalid HTTP response: {err}")))?
    else {
        return Err(invalid_http("incomplete HTTP response"));
    };
    if parsed_len != head.len() {
        return Err(invalid_http("HTTP response head has trailing bytes"));
    }
    let status = response
        .code
        .ok_or_else(|| invalid_http("HTTP response omitted its status"))?;
    let mut content_length = None;
    let mut chunked = false;
    let mut transfer_encoded = false;
    let mut connection_close = response.version == Some(0);
    for header in response.headers.iter() {
        if header.name.eq_ignore_ascii_case("Content-Length") {
            let text = std::str::from_utf8(trim_ascii(header.value))
                .map_err(|_| invalid_http("HTTP response Content-Length is not UTF-8"))?;
            let value = text
                .parse::<u64>()
                .map_err(|_| invalid_http("HTTP response Content-Length is invalid"))?;
            if content_length.is_some_and(|existing| existing != value) {
                return Err(invalid_http(
                    "HTTP response has conflicting Content-Length values",
                ));
            }
            content_length = Some(value);
        }
        if header.name.eq_ignore_ascii_case("Transfer-Encoding") {
            transfer_encoded = true;
            chunked |=
                header_tokens(header.value).any(|token| token.eq_ignore_ascii_case(b"chunked"));
        }
        if header.name.eq_ignore_ascii_case("Connection") {
            for token in header_tokens(header.value) {
                if token.eq_ignore_ascii_case(b"close") {
                    connection_close = true;
                } else if response.version == Some(0) && token.eq_ignore_ascii_case(b"keep-alive") {
                    connection_close = false;
                }
            }
        }
    }
    if transfer_encoded {
        content_length = None;
    }
    Ok(ResponseHead {
        status,
        content_length,
        chunked,
        connection_close,
    })
}

fn relay_chunked(reader: &mut impl BufRead, writer: &mut impl Write) -> io::Result<()> {
    loop {
        let line = read_crlf_line(reader, MAX_CHUNK_LINE)?;
        writer.write_all(&line)?;
        let size = line
            .strip_suffix(b"\r\n")
            .and_then(|line| line.split(|byte| *byte == b';').next())
            .and_then(|size| std::str::from_utf8(trim_ascii(size)).ok())
            .and_then(|size| u64::from_str_radix(size, 16).ok())
            .ok_or_else(|| invalid_http("HTTP response chunk size is invalid"))?;
        if size == 0 {
            loop {
                let trailer = read_crlf_line(reader, MAX_REQUEST_HEAD)?;
                writer.write_all(&trailer)?;
                if trailer == b"\r\n" {
                    return Ok(());
                }
            }
        }
        copy_exact(reader, writer, size)?;
        let mut ending = [0_u8; 2];
        reader.read_exact(&mut ending)?;
        if ending != *b"\r\n" {
            return Err(invalid_http("HTTP response chunk omitted its CRLF"));
        }
        writer.write_all(&ending)?;
    }
}

fn read_crlf_line(reader: &mut impl BufRead, limit: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP line ended before CRLF",
            ));
        }
        let mut consumed = 0;
        for byte in available {
            if line.len() == limit {
                return Err(invalid_http("HTTP line exceeds its size limit"));
            }
            line.push(*byte);
            consumed += 1;
            if line.ends_with(b"\r\n") {
                reader.consume(consumed);
                return Ok(line);
            }
        }
        reader.consume(consumed);
    }
}

fn copy_exact(reader: &mut impl Read, writer: &mut impl Write, length: u64) -> io::Result<()> {
    let copied = io::copy(&mut reader.take(length), writer)?;
    if copied == length {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("HTTP body ended after {copied} of {length} bytes"),
        ))
    }
}

fn invalid_http(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn splice_buffered(
    mut client_read: impl Read + Send + 'static,
    mut upstream_read: impl Read,
    mut client_write: TcpStream,
    mut upstream_write: TcpStream,
) {
    std::thread::spawn(move || {
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
}

fn read_request_head(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut head = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((!head.is_empty()).then_some(head));
        }
        let mut consumed = 0;
        let mut complete = false;
        for byte in available {
            if head.len() == MAX_REQUEST_HEAD {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP request head exceeds 64 KiB",
                ));
            }
            head.push(*byte);
            consumed += 1;
            if head.ends_with(b"\r\n\r\n") {
                complete = true;
                break;
            }
        }
        reader.consume(consumed);
        if complete {
            return Ok(Some(head));
        }
    }
}

fn rewrite_request_head(
    head: &[u8],
    required_header: Option<&str>,
    allowed_users: &[String],
    authorization: &str,
) -> RequestAction {
    let auth = required_header.map_or(RequestAuth::Inject { authorization }, |required_header| {
        RequestAuth::TrustedHeader {
            required_header,
            allowed_users,
            authorization,
        }
    });
    route_request_head(head, auth, false)
}

/// 解析认证、上传路由和 ttyd 转发元数据，保持 Basic 请求字节不变。
fn route_request_head(head: &[u8], auth: RequestAuth<'_>, image_paste: bool) -> RequestAction {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let Ok(httparse::Status::Complete(parsed_len)) = request.parse(head) else {
        return RequestAction::Close;
    };
    if parsed_len != head.len() {
        return RequestAction::Close;
    }
    let (Some(method), Some(path), Some(version)) = (request.method, request.path, request.version)
    else {
        return RequestAction::Close;
    };
    let image_upload = image_paste && path == IMAGE_UPLOAD_PATH;
    if let RequestAuth::TrustedHeader {
        required_header,
        allowed_users,
        ..
    } = auth
    {
        let mut identity_header_count = 0_usize;
        let mut identity = None;
        for header in request.headers.iter() {
            if header.name.eq_ignore_ascii_case(required_header) {
                identity_header_count += 1;
                if identity_header_count == 1 {
                    identity = Some(trim_ascii(header.value));
                }
            }
        }
        let Some(identity) = identity else {
            return RequestAction::Unauthorized;
        };
        if identity_header_count != 1
            || identity.is_empty()
            || (!allowed_users.is_empty()
                && !allowed_users
                    .iter()
                    .any(|allowed| allowed.as_bytes() == identity))
        {
            return RequestAction::Unauthorized;
        }
    }
    if image_upload
        && let RequestAuth::Basic { authorization } = auth
        && !single_header_matches(request.headers, "Authorization", authorization.as_bytes())
    {
        return RequestAction::Unauthorized;
    }
    if image_upload
        && !single_header_matches(
            request.headers,
            IMAGE_UPLOAD_HEADER,
            IMAGE_UPLOAD_HEADER_VALUE,
        )
    {
        return RequestAction::Forbidden;
    }

    let mut content_length = None;
    let mut upgrade = false;
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("Transfer-Encoding")
            && header_tokens(header.value).any(|token| token.eq_ignore_ascii_case(b"chunked"))
        {
            return RequestAction::Close;
        }
        if header.name.eq_ignore_ascii_case("Content-Length") {
            let Ok(text) = std::str::from_utf8(trim_ascii(header.value)) else {
                return RequestAction::Close;
            };
            let Ok(value) = text.parse::<u64>() else {
                return RequestAction::Close;
            };
            if content_length.is_some_and(|existing| existing != value) {
                return RequestAction::Close;
            }
            content_length = Some(value);
        }
        if header.name.eq_ignore_ascii_case("Upgrade")
            && trim_ascii(header.value).eq_ignore_ascii_case(b"websocket")
        {
            upgrade = true;
        }
    }
    if image_upload {
        if !method.eq_ignore_ascii_case("POST") {
            return RequestAction::MethodNotAllowed;
        }
        let Some(content_length) = content_length else {
            return RequestAction::LengthRequired;
        };
        if content_length == 0 {
            return RequestAction::LengthRequired;
        }
        if content_length > MAX_IMAGE_BYTES {
            return RequestAction::PayloadTooLarge;
        }
        return RequestAction::Upload { content_length };
    }

    if matches!(auth, RequestAuth::Basic { .. }) {
        return RequestAction::Forward {
            head: head.to_vec(),
            content_length: content_length.unwrap_or(0),
            head_request: method.eq_ignore_ascii_case("HEAD"),
            upgrade,
        };
    }
    let authorization = match auth {
        RequestAuth::Inject { authorization }
        | RequestAuth::TrustedHeader { authorization, .. } => authorization,
        RequestAuth::Basic { .. } => unreachable!("basic requests return before rewriting"),
    };
    let mut rewritten = Vec::with_capacity(head.len() + authorization.len() + 24);
    let _ = write!(rewritten, "{method} {path} HTTP/1.{version}\r\n");
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("Authorization") {
            continue;
        }
        let _ = write!(rewritten, "{}: ", header.name);
        rewritten.extend_from_slice(header.value);
        rewritten.extend_from_slice(b"\r\n");
    }
    let _ = write!(rewritten, "Authorization: {authorization}\r\n\r\n");
    RequestAction::Forward {
        head: rewritten,
        content_length: content_length.unwrap_or(0),
        head_request: method.eq_ignore_ascii_case("HEAD"),
        upgrade,
    }
}

/// 要求敏感认证头只出现一次，并用固定工作量比较其字节。
fn single_header_matches(headers: &[httparse::Header<'_>], name: &str, expected: &[u8]) -> bool {
    let mut matches = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let Some(header) = matches.next() else {
        return false;
    };
    matches.next().is_none() && constant_time_eq(trim_ascii(header.value), expected)
}

/// 比较等长凭据，避免从首个不同字节泄漏明显的时间差。
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (*left ^ *right)
        })
        == 0
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn header_tokens(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value.split(|byte| *byte == b',').map(trim_ascii)
}

fn splice(client: TcpStream, upstream: TcpStream) {
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    let (Ok(mut client_read), Ok(mut upstream_write)) = (client.try_clone(), upstream.try_clone())
    else {
        return;
    };
    std::thread::spawn(move || {
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    std::thread::spawn(move || {
        let mut upstream_read = upstream;
        let mut client_write = client;
        let _ = io::copy(&mut upstream_read, &mut client_write);
        let _ = client_write.shutdown(Shutdown::Write);
    });
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    fn parse(value: &str) -> Cidr {
        Cidr::parse(value).expect("valid CIDR")
    }

    fn auth() -> GateAuth {
        GateAuth {
            header_name: "X-Forwarded-User".to_owned(),
            allowed_users: Vec::new(),
            authorization: "Basic cmltejphYmNk".to_owned(),
        }
    }

    fn rewrite_trusted(head: &[u8]) -> RequestAction {
        let auth = auth();
        rewrite_request_head(
            head,
            Some(&auth.header_name),
            &auth.allowed_users,
            &auth.authorization,
        )
    }

    #[test]
    fn cidrs_match_their_address_family_and_prefix() {
        assert!(parse("10.20.0.0/16").contains("10.20.4.5".parse().expect("IP")));
        assert!(!parse("10.20.0.0/16").contains("10.21.4.5".parse().expect("IP")));
        assert!(parse("fd00::/8").contains("fd12::1".parse().expect("IP")));
        assert!(!parse("fd00::/8").contains("fe80::1".parse().expect("IP")));
        assert!(!parse("10.0.0.0/8").contains("::ffff:10.0.0.1".parse().expect("IP")));
    }

    #[test]
    fn bare_ips_and_zero_prefixes_parse() {
        assert!(parse("192.0.2.4").contains("192.0.2.4".parse().expect("IP")));
        assert!(!parse("192.0.2.4").contains("192.0.2.5".parse().expect("IP")));
        assert!(parse("2001:db8::1").contains("2001:db8::1".parse().expect("IP")));
        assert!(parse("0.0.0.0/0").contains("203.0.113.2".parse().expect("IP")));
        assert!(parse("::/0").contains("2001:db8::2".parse().expect("IP")));
    }

    #[test]
    fn invalid_cidrs_return_typed_errors() {
        for value in ["", "10.0.0.0/33", "2001:db8::/129", "10.0.0.0/nope"] {
            assert!(matches!(
                Cidr::parse(value),
                Err(WebErr::InvalidTrustedProxy { value: actual, .. }) if actual == value
            ));
        }
    }

    #[test]
    fn peers_require_a_match_except_for_loopback() {
        let allow = [parse("10.0.0.0/8")];
        assert!(peer_allowed("10.2.3.4".parse().expect("IP"), &allow));
        assert!(!peer_allowed("192.0.2.1".parse().expect("IP"), &allow));
        assert!(peer_allowed("127.0.0.1".parse().expect("IP"), &[]));
        assert!(peer_allowed("::1".parse().expect("IP"), &[]));
        assert!(peer_allowed("::ffff:127.0.0.1".parse().expect("IP"), &[]));
        assert!(peer_allowed("::ffff:10.2.3.4".parse().expect("IP"), &allow));
        assert!(peer_admitted("192.0.2.1".parse().expect("IP"), &[], false));
        assert!(!peer_admitted("192.0.2.1".parse().expect("IP"), &[], true));
    }

    #[test]
    fn trusted_header_rewrites_authorization_and_rejects_missing_or_chunked() {
        let RequestAction::Forward {
            head,
            content_length,
            head_request,
            upgrade,
        } = rewrite_trusted(
            b"POST /x HTTP/1.1\r\nHost: local\r\nX-Forwarded-User: alice\r\nAuthorization: Bearer attacker\r\nContent-Length: 4\r\n\r\n",
        ) else {
            panic!("trusted request forwards");
        };
        let head = String::from_utf8(head).expect("rewritten head");
        assert!(head.contains("Authorization: Basic cmltejphYmNk\r\n"));
        assert!(!head.contains("Bearer attacker"));
        assert_eq!(content_length, 4);
        assert!(!head_request);
        assert!(!upgrade);

        assert_eq!(
            rewrite_trusted(b"GET / HTTP/1.1\r\nHost: local\r\n\r\n"),
            RequestAction::Unauthorized
        );
        assert_eq!(
            rewrite_trusted(
                b"POST / HTTP/1.1\r\nX-Forwarded-User: alice\r\nTransfer-Encoding: chunked\r\n\r\n",
            ),
            RequestAction::Close
        );
    }

    #[test]
    fn basic_image_upload_requires_the_exact_single_credential() {
        let authorization = auth().authorization;
        let route = |head: &[u8]| {
            route_request_head(
                head,
                RequestAuth::Basic {
                    authorization: &authorization,
                },
                true,
            )
        };

        assert_eq!(
            route(
                b"POST /__rimz/upload/image HTTP/1.1\r\nAuthorization: Basic cmltejphYmNk\r\nX-RimZ-Upload: image\r\nContent-Length: 12\r\n\r\n"
            ),
            RequestAction::Upload { content_length: 12 }
        );
        for head in [
            &b"POST /__rimz/upload/image HTTP/1.1\r\nContent-Length: 12\r\n\r\n"[..],
            &b"POST /__rimz/upload/image HTTP/1.1\r\nAuthorization: Basic wrong\r\nContent-Length: 12\r\n\r\n"[..],
            &b"POST /__rimz/upload/image HTTP/1.1\r\nAuthorization: Basic cmltejphYmNk\r\nAuthorization: Basic cmltejphYmNk\r\nContent-Length: 12\r\n\r\n"[..],
        ] {
            assert_eq!(route(head), RequestAction::Unauthorized);
        }
        assert_eq!(
            route(
                b"POST /__rimz/upload/image HTTP/1.1\r\nAuthorization: Basic cmltejphYmNk\r\nContent-Length: 12\r\n\r\n"
            ),
            RequestAction::Forbidden
        );

        let ordinary = b"GET / HTTP/1.1\r\nHost: local\r\n\r\n";
        assert!(matches!(
            route(ordinary),
            RequestAction::Forward { head, .. } if head == ordinary
        ));
    }

    #[test]
    fn image_upload_rejects_wrong_methods_and_unbounded_bodies() {
        let authorization = auth().authorization;
        let route = |head: &[u8]| {
            route_request_head(
                head,
                RequestAuth::Basic {
                    authorization: &authorization,
                },
                true,
            )
        };
        assert_eq!(
            route(
                b"GET /__rimz/upload/image HTTP/1.1\r\nAuthorization: Basic cmltejphYmNk\r\nX-RimZ-Upload: image\r\n\r\n"
            ),
            RequestAction::MethodNotAllowed
        );
        assert_eq!(
            route(
                b"POST /__rimz/upload/image HTTP/1.1\r\nAuthorization: Basic cmltejphYmNk\r\nX-RimZ-Upload: image\r\n\r\n"
            ),
            RequestAction::LengthRequired
        );
        let oversized = format!(
            "POST {IMAGE_UPLOAD_PATH} HTTP/1.1\r\nAuthorization: Basic cmltejphYmNk\r\nX-RimZ-Upload: image\r\nContent-Length: {}\r\n\r\n",
            MAX_IMAGE_BYTES + 1
        );
        assert_eq!(route(oversized.as_bytes()), RequestAction::PayloadTooLarge);
    }

    #[test]
    fn trusted_header_auth_can_route_image_uploads() {
        let auth = auth();
        assert_eq!(
            route_request_head(
                b"POST /__rimz/upload/image HTTP/1.1\r\nX-Forwarded-User: alice\r\nX-RimZ-Upload: image\r\nContent-Length: 8\r\n\r\n",
                RequestAuth::TrustedHeader {
                    required_header: &auth.header_name,
                    allowed_users: &auth.allowed_users,
                    authorization: &auth.authorization,
                },
                true,
            ),
            RequestAction::Upload { content_length: 8 }
        );
    }

    #[test]
    fn trusted_header_enforces_the_user_allowlist_and_single_occurrence() {
        let mut allowlisted = auth();
        allowlisted.allowed_users = vec!["alice".to_owned()];

        assert!(matches!(
            rewrite_request_head(
                b"GET / HTTP/1.1\r\nX-Forwarded-User:  alice \t\r\n\r\n",
                Some(&allowlisted.header_name),
                &allowlisted.allowed_users,
                &allowlisted.authorization,
            ),
            RequestAction::Forward { .. }
        ));
        assert_eq!(
            rewrite_request_head(
                b"GET / HTTP/1.1\r\nX-Forwarded-User: Alice\r\n\r\n",
                Some(&allowlisted.header_name),
                &allowlisted.allowed_users,
                &allowlisted.authorization,
            ),
            RequestAction::Unauthorized
        );

        for auth in [auth(), allowlisted] {
            assert_eq!(
                rewrite_request_head(
                    b"GET / HTTP/1.1\r\nX-Forwarded-User: alice\r\nX-Forwarded-User: alice\r\n\r\n",
                    Some(&auth.header_name),
                    &auth.allowed_users,
                    &auth.authorization,
                ),
                RequestAction::Unauthorized
            );
        }
    }

    #[test]
    fn tunnel_relay_replaces_client_authorization_without_a_trusted_header() {
        let ignored_allowlist = ["nobody".to_owned()];
        let RequestAction::Forward { head, .. } = rewrite_request_head(
            b"GET / HTTP/1.1\r\nHost: local\r\nX-Forwarded-User: alice\r\nX-Forwarded-User: alice\r\nAuthorization: Bearer attacker\r\n\r\n",
            None,
            &ignored_allowlist,
            &auth().authorization,
        ) else {
            panic!("tunnel request forwards");
        };
        let head = String::from_utf8(head).expect("rewritten head");
        assert!(head.contains("Authorization: Basic cmltejphYmNk\r\n"));
        assert!(!head.contains("Bearer attacker"));
    }

    #[test]
    fn chunked_response_framing_is_relayed_without_rewriting() {
        let chunked = b"4\r\nWiki\r\n5;kind=test\r\npedia\r\n0\r\nTrailer: yes\r\n\r\n";
        let mut input = BufReader::new(std::io::Cursor::new(
            [chunked.as_slice(), b"next-response"].concat(),
        ));
        let mut output = Vec::new();

        relay_chunked(&mut input, &mut output).expect("relay chunked body");

        assert_eq!(output, chunked);
        let mut remaining = String::new();
        input
            .read_to_string(&mut remaining)
            .expect("read remaining response");
        assert_eq!(remaining, "next-response");
    }

    #[test]
    fn missing_trusted_header_returns_unauthorized() {
        let (mut client, gate_client) = tcp_pair();
        let (gate_upstream, upstream) = tcp_pair();
        let gate = std::thread::spawn(move || {
            let auth = auth();
            relay_authorized(
                gate_client,
                gate_upstream,
                Some(&auth.header_name),
                &auth.allowed_users,
                &auth.authorization,
                None,
            );
        });
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: local\r\n\r\n")
            .expect("write unauthenticated request");
        client
            .shutdown(Shutdown::Write)
            .expect("finish unauthenticated request");
        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("read unauthorized response");
        assert_eq!(response, String::from_utf8_lossy(UNAUTHORIZED));
        gate.join().expect("gate thread");
        drop(upstream);
    }

    #[test]
    fn keep_alive_requests_are_each_rewritten() {
        let (mut client, gate_client) = tcp_pair();
        let (gate_upstream, mut upstream) = tcp_pair();
        let gate = std::thread::spawn(move || {
            let auth = auth();
            relay_authorized(
                gate_client,
                gate_upstream,
                Some(&auth.header_name),
                &auth.allowed_users,
                &auth.authorization,
                None,
            );
        });
        let upstream_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(upstream.try_clone().expect("clone upstream"));
            for path in ["/one", "/two"] {
                let head = read_request_head(&mut reader)
                    .expect("read request")
                    .expect("request head");
                let text = String::from_utf8(head).expect("request text");
                assert!(
                    text.starts_with(&format!("GET {path} HTTP/1.1\r\n")),
                    "{text}"
                );
                assert!(
                    text.contains("Authorization: Basic cmltejphYmNk\r\n"),
                    "{text}"
                );
                upstream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .expect("write response");
            }
        });
        let mut reader = BufReader::new(client.try_clone().expect("clone client"));
        for path in ["/one", "/two"] {
            write!(
                client,
                "GET {path} HTTP/1.1\r\nHost: local\r\nX-Forwarded-User: alice\r\n\r\n"
            )
            .expect("write request");
            let response = read_request_head(&mut reader)
                .expect("read response")
                .expect("response head");
            assert!(response.starts_with(b"HTTP/1.1 204 No Content"));
        }
        client.shutdown(Shutdown::Both).expect("close client");
        upstream_thread.join().expect("upstream thread");
        gate.join().expect("gate thread");
    }

    #[test]
    fn tunnel_relay_rewrites_each_keep_alive_request() {
        let (mut client, gate_client) = tcp_pair();
        let (gate_upstream, mut upstream) = tcp_pair();
        let gate = std::thread::spawn(move || {
            relay_authorized(
                gate_client,
                gate_upstream,
                None,
                &[],
                &auth().authorization,
                None,
            );
        });
        let upstream_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(upstream.try_clone().expect("clone upstream"));
            for path in ["/one", "/two"] {
                let head = read_request_head(&mut reader)
                    .expect("read request")
                    .expect("request head");
                let text = String::from_utf8(head).expect("request text");
                assert!(text.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
                assert!(text.contains("Authorization: Basic cmltejphYmNk\r\n"));
                upstream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .expect("write response");
            }
        });
        let mut reader = BufReader::new(client.try_clone().expect("clone client"));
        for path in ["/one", "/two"] {
            write!(client, "GET {path} HTTP/1.1\r\nHost: local\r\n\r\n").expect("write request");
            let response = read_request_head(&mut reader)
                .expect("read response")
                .expect("response head");
            assert!(response.starts_with(b"HTTP/1.1 204 No Content"));
        }
        client.shutdown(Shutdown::Both).expect("close client");
        upstream_thread.join().expect("upstream thread");
        gate.join().expect("gate thread");
    }

    #[test]
    fn rejected_websocket_upgrade_keeps_rewriting_requests() {
        let (mut client, gate_client) = tcp_pair();
        let (gate_upstream, mut upstream) = tcp_pair();
        let gate = std::thread::spawn(move || {
            let auth = auth();
            relay_authorized(
                gate_client,
                gate_upstream,
                Some(&auth.header_name),
                &auth.allowed_users,
                &auth.authorization,
                None,
            );
        });
        let upstream_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(upstream.try_clone().expect("clone upstream"));
            let upgrade = read_request_head(&mut reader)
                .expect("read upgrade request")
                .expect("upgrade request");
            assert!(
                upgrade
                    .windows(b"Upgrade: websocket".len())
                    .any(|bytes| bytes == b"Upgrade: websocket")
            );
            upstream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .expect("reject upgrade");
            let second = read_request_head(&mut reader)
                .expect("read second request")
                .expect("second request");
            let second = String::from_utf8(second).expect("second request text");
            assert!(second.starts_with("GET /two HTTP/1.1\r\n"), "{second}");
            assert!(
                second.contains("Authorization: Basic cmltejphYmNk\r\n"),
                "{second}"
            );
            upstream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .expect("write second response");
        });
        let mut reader = BufReader::new(client.try_clone().expect("clone client"));
        client
            .write_all(b"GET /ws HTTP/1.1\r\nHost: local\r\nX-Forwarded-User: alice\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .expect("write upgrade request");
        let rejected = read_request_head(&mut reader)
            .expect("read rejected upgrade")
            .expect("rejected upgrade response");
        assert!(rejected.starts_with(b"HTTP/1.1 200 OK"));
        client
            .write_all(b"GET /two HTTP/1.1\r\nHost: local\r\nX-Forwarded-User: alice\r\n\r\n")
            .expect("write second request");
        let response = read_request_head(&mut reader)
            .expect("read second response")
            .expect("second response");
        assert!(response.starts_with(b"HTTP/1.1 204 No Content"));
        client.shutdown(Shutdown::Both).expect("close client");
        upstream_thread.join().expect("upstream thread");
        gate.join().expect("gate thread");
    }

    #[test]
    fn safari_websocket_without_authorization_is_injected_and_spliced() {
        let (mut client, gate_client) = tcp_pair();
        let (gate_upstream, mut upstream) = tcp_pair();
        let (sent, received) = mpsc::channel();
        let gate = std::thread::spawn(move || {
            relay_authorized(
                gate_client,
                gate_upstream,
                None,
                &[],
                &auth().authorization,
                None,
            );
        });
        let upstream_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(upstream.try_clone().expect("clone upstream"));
            let head = read_request_head(&mut reader)
                .expect("read upgrade")
                .expect("upgrade head");
            let head = String::from_utf8(head).expect("upgrade text");
            assert!(head.contains("Upgrade: websocket\r\n"), "{head}");
            assert!(
                head.contains("Authorization: Basic cmltejphYmNk\r\n"),
                "{head}"
            );
            upstream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nserver-frame")
                .expect("write upgrade response");
            let mut raw = [0_u8; 12];
            reader.read_exact(&mut raw).expect("read raw client frame");
            sent.send(raw).expect("report raw frame");
        });
        client
            .write_all(b"GET /ws HTTP/1.1\r\nHost: local\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nclient-frame")
            .expect("write upgrade");
        assert_eq!(received.recv().expect("raw client frame"), *b"client-frame");
        client
            .shutdown(Shutdown::Write)
            .expect("finish client frames");
        let mut response = String::new();
        client
            .read_to_string(&mut response)
            .expect("read raw response");
        assert!(response.ends_with("server-frame"), "{response:?}");
        upstream_thread.join().expect("upstream thread");
        gate.join().expect("gate thread");
    }

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind pair listener");
        let address = listener.local_addr().expect("pair address");
        let first = TcpStream::connect(address).expect("connect pair");
        let (second, _) = listener.accept().expect("accept pair");
        (first, second)
    }
}
