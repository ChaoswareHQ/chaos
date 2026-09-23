//! Client-side shipping: enrollment, batching, and the transport underneath.
//!
//! # Why this does not use an HTTP client library
//!
//! The agent runs on every endpoint in the estate, which makes its dependency
//! tree part of the attack surface: every transitive crate is code you shipped
//! to ten thousand machines and now have to patch. What this module needs from
//! HTTP is one request shape — `POST` a JSON body with a length, read a
//! response with a length. That is about a hundred lines, it is pinned by
//! tests, and it is fully auditable in one sitting.
//!
//! What it deliberately does *not* do is guess. Chunked transfer encoding is
//! rejected rather than half-supported, and `https://` is either carried over a
//! real TLS session or it fails — there is no path that quietly sends a
//! credential in the clear.
//!
//! # TLS
//!
//! TLS is [`TlsTransport`], and it is the platform's own implementation:
//! SChannel on Windows, Security.framework on macOS, OpenSSL on Linux. The
//! alternative — bundling `rustls` and a crypto backend — is a second TLS stack
//! to patch on every endpoint in the estate, and a trust store that is a copy
//! rather than the one Windows Update maintains. The cost is that verification
//! is the platform's, which is exactly the behaviour an operator expects from
//! every other program on the host.
//!
//! # The cleartext rule
//!
//! A host token is a bearer credential: whoever holds it can submit telemetry
//! as that host. So [`Endpoint`] refuses to send one anywhere except loopback
//! over `http://`. This is not a configuration option, because "we will turn
//! TLS on later" is how credentials end up on the wire in production. TLS
//! arrives as another [`Transport`] implementation; it does not relax this
//! check.

use model::{Alert, TelemetryEvent};
use ports::{EventSink, SinkError};
use protocol::{API_VERSION, ApiError, HostToken, INGEST_PATH, IngestRequest, IngestResponse};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// How long any single request may take, end to end.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Largest response we will read. The server never legitimately sends more, and
/// a client with no cap will happily allocate whatever it is told to.
const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Largest response *header block* we will buffer while looking for its end.
const MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("could not reach {endpoint}: {source}")]
    Connect {
        endpoint: String,
        #[source]
        source: std::io::Error,
    },

    #[error("request failed: {0}")]
    Io(String),

    #[error("malformed endpoint `{0}`")]
    BadEndpoint(String),

    #[error(
        "refusing to send a credential over cleartext to {0}; \
         only loopback may use http://, and everything else needs TLS"
    )]
    CleartextRefused(String),

    #[error("TLS handshake with {endpoint} failed: {detail}")]
    Tls { endpoint: String, detail: String },

    #[error("malformed response: {0}")]
    BadResponse(String),

    #[error("server returned {status}: {error}")]
    Server { status: u16, error: String },

    #[error("could not serialise the request: {0}")]
    Encode(String),
}

pub type Result<T> = std::result::Result<T, TransportError>;

// ---------------------------------------------------------------------------
// endpoints
// ---------------------------------------------------------------------------

/// A parsed base URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    scheme: String,
    host: String,
    port: u16,
}

impl Endpoint {
    /// Parse `http://host:port`. A missing port defaults to 80 for `http` and
    /// 443 for `https`, matching what every other client does.
    pub fn parse(raw: &str) -> Result<Self> {
        let (scheme, rest) = raw
            .split_once("://")
            .ok_or_else(|| TransportError::BadEndpoint(raw.to_string()))?;
        let scheme = scheme.to_ascii_lowercase();

        // The base URL is an origin; any path is ignored rather than rejected,
        // because a trailing slash is not a mistake worth failing on.
        let authority = rest.split('/').next().unwrap_or(rest);
        if authority.is_empty() {
            return Err(TransportError::BadEndpoint(raw.to_string()));
        }

        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| TransportError::BadEndpoint(raw.to_string()))?;
                (host.to_string(), port)
            }
            None => {
                let port = if scheme == "https" { 443 } else { 80 };
                (authority.to_string(), port)
            }
        };

        if host.is_empty() {
            return Err(TransportError::BadEndpoint(raw.to_string()));
        }
        if scheme != "http" && scheme != "https" {
            return Err(TransportError::BadEndpoint(raw.to_string()));
        }

        Ok(Self { scheme, host, port })
    }

    /// Whether this endpoint may carry a credential.
    ///
    /// Loopback over `http` is the development case: the bytes never leave the
    /// machine, so there is no wire to be on. Anything else must be `https`.
    pub fn allows_credential(&self) -> bool {
        self.scheme == "https" || is_loopback_host(&self.host)
    }

    /// Whether this endpoint must be reached over TLS.
    ///
    /// The scheme is what selects the transport, and the transport is what
    /// decides whether a credential may go on the wire, so this is the one place
    /// the two are connected.
    pub fn uses_tls(&self) -> bool {
        self.scheme == "https"
    }

    pub fn host_header(&self) -> String {
        if self.port == 80 || self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn socket_addr(&self) -> Result<SocketAddr> {
        let target = format!("{}:{}", self.host, self.port);
        target
            .to_socket_addrs()
            .map_err(|source| TransportError::Connect {
                endpoint: target.clone(),
                source,
            })?
            .next()
            .ok_or_else(|| TransportError::Connect {
                endpoint: target,
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses resolved"),
            })
    }
}

// ---------------------------------------------------------------------------
// responses
// ---------------------------------------------------------------------------

/// A raw HTTP response, already fully read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| TransportError::BadResponse(format!("expected JSON: {e}")))
    }

    /// Turn a non-2xx into the server's own error, which is the only place the
    /// caller learns *why* it was refused.
    pub fn into_success(self) -> Result<Self> {
        if (200..300).contains(&self.status) {
            return Ok(self);
        }
        let error = serde_json::from_slice::<ApiError>(&self.body)
            .map(|e| e.error)
            .unwrap_or_else(|_| "unparseable error body".to_string());
        Err(TransportError::Server {
            status: self.status,
            error,
        })
    }
}

/// Parse an HTTP/1.1 response.
///
/// Insists on `Content-Length`. `Transfer-Encoding: chunked` is rejected rather
/// than guessed at: a client that mishandles chunk boundaries corrupts JSON in
/// ways that look like a server bug, and the server is ours to change.
fn parse_response(raw: &[u8]) -> Result<HttpResponse> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| TransportError::BadResponse("no header terminator".to_string()))?;

    let head = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| TransportError::BadResponse("headers are not UTF-8".to_string()))?;
    let body = &raw[header_end + 4..];

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| TransportError::BadResponse("empty response".to_string()))?;

    let mut parts = status_line.split(' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(TransportError::BadResponse(format!(
            "unsupported protocol `{version}`"
        )));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TransportError::BadResponse(format!("bad status line `{status_line}`")))?;

    let mut content_length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => {
                content_length = Some(value.parse().map_err(|_| {
                    TransportError::BadResponse(format!("bad Content-Length `{value}`"))
                })?);
            }
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => {
                return Err(TransportError::BadResponse(
                    "chunked responses are not supported".to_string(),
                ));
            }
            _ => {}
        }
    }

    let length = content_length
        .ok_or_else(|| TransportError::BadResponse("response has no Content-Length".to_string()))?;

    if body.len() < length {
        return Err(TransportError::BadResponse(format!(
            "truncated body: {} of {length} bytes",
            body.len()
        )));
    }

    Ok(HttpResponse {
        status,
        body: body[..length].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------

/// How requests are carried.
///
/// Exists so TLS is an additive change: [`TlsTransport`] sits beside
/// [`CleartextTransport`] and nothing above this line moves.
pub trait Transport: Send {
    fn post_json(
        &mut self,
        endpoint: &Endpoint,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse>;
}

/// Everything the framing code needs from a byte stream.
///
/// A trait object rather than a generic parameter, because the request and
/// response framing is identical whether the bytes go through a socket or a TLS
/// session, and making it generic would duplicate the code this client's
/// correctness rests on. `Debug` is in the bound so a connection can still be
/// printed when something goes wrong.
trait Stream: Read + Write + Send + std::fmt::Debug {}

impl<T: Read + Write + Send + std::fmt::Debug> Stream for T {}

/// Plain HTTP/1.1, loopback only.
///
/// Holds the connection between calls. The first version opened and closed one
/// per request, which pays a TCP handshake per batch — on a host producing a
/// batch every couple of seconds, a handshake every couple of seconds for no
/// reason. The connection is dropped whenever a response is not framed the way
/// this client expects, so a protocol surprise costs one request rather than
/// every request after it.
#[derive(Debug)]
pub struct CleartextTransport {
    exchange: Exchange,
}

/// HTTPS/1.1 over the platform's TLS.
///
/// Separate from [`CleartextTransport`] rather than a flag on it, because the two
/// differ in a way that matters: this one is allowed to carry a credential to a
/// routable host, and the cleartext one is not. A single type with a `secure:
/// bool` is how the wrong branch gets taken.
#[derive(Debug)]
pub struct TlsTransport {
    exchange: Exchange,
    connector: native_tls::TlsConnector,
}

/// One open connection, and whatever arrived on it that a response has not
/// consumed yet. A TCP read returns what arrived, which is not the same thing as
/// one response.
#[derive(Debug)]
struct Connection {
    endpoint: Endpoint,
    stream: Box<dyn Stream>,
    buffer: Vec<u8>,
}

/// The request/response dance, independent of what carries the bytes.
///
/// Both transports own one of these and hand it a way to open a connection. The
/// framing, the keep-alive, and the compression are then written once — which
/// matters more than it sounds, because this is the code that decides where one
/// response ends and the next begins.
#[derive(Debug)]
struct Exchange {
    timeout: Duration,
    conn: Option<Connection>,
}

impl Exchange {
    fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            conn: None,
        }
    }

    /// POST `body` to `path`, reusing the held connection when it is already for
    /// this origin.
    ///
    /// `open` is called only when a new connection is needed, so a TLS handshake
    /// is paid once per origin rather than once per batch.
    fn post(
        &mut self,
        endpoint: &Endpoint,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        open: impl FnOnce(&Endpoint, Duration) -> Result<Box<dyn Stream>>,
    ) -> Result<HttpResponse> {
        // A connection is only reusable for the origin it was opened to.
        if self.conn.as_ref().is_some_and(|c| &c.endpoint != endpoint) {
            self.conn = None;
        }
        if self.conn.is_none() {
            self.conn = Some(Connection {
                endpoint: endpoint.clone(),
                stream: open(endpoint, self.timeout)?,
                buffer: Vec::with_capacity(1024),
            });
        }

        let attempt = self.exchange(path, headers, body);
        if attempt.is_err() {
            // Whatever went wrong, this connection's framing can no longer be
            // trusted. Drop it so the next attempt starts clean rather than
            // reading a stray body as the next response's headers.
            self.conn = None;
        }
        attempt
    }

    /// One request and response on the held connection.
    fn exchange(
        &mut self,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse> {
        let conn = self.conn.as_mut().expect("the connection was opened above");

        let mut request = Vec::with_capacity(body.len() + 256);
        write!(
            request,
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Encoding: {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
            conn.endpoint.host_header(),
            protocol::GZIP_ENCODING,
            body.len()
        )
        .map_err(|e| TransportError::Io(e.to_string()))?;
        for (name, value) in headers {
            write!(request, "{name}: {value}\r\n")
                .map_err(|e| TransportError::Io(e.to_string()))?;
        }
        request.extend_from_slice(b"\r\n");
        request.extend_from_slice(body);

        conn.stream
            .write_all(&request)
            .and_then(|()| conn.stream.flush())
            .map_err(|e| TransportError::Io(e.to_string()))?;

        read_response(conn)
    }
}

impl CleartextTransport {
    pub fn new() -> Self {
        Self {
            exchange: Exchange::new(REQUEST_TIMEOUT),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            exchange: Exchange::new(timeout),
        }
    }
}

impl Default for CleartextTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for CleartextTransport {
    fn post_json(
        &mut self,
        endpoint: &Endpoint,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse> {
        // The scheme decides the transport, and the caller picked this one.
        // Using it for an https endpoint would send the credential in the clear,
        // so it is refused rather than followed.
        if endpoint.scheme == "https" {
            return Err(TransportError::CleartextRefused(endpoint.host.clone()));
        }
        if !endpoint.allows_credential() && headers.iter().any(|(k, _)| is_credential_header(k)) {
            return Err(TransportError::CleartextRefused(endpoint.host.clone()));
        }

        let compressed = protocol::gzip(body).map_err(|e| TransportError::Io(e.to_string()))?;
        self.exchange
            .post(endpoint, path, headers, &compressed, connect_plain)
    }
}

/// A TCP connection with this client's timeouts applied.
///
/// The timeouts are set on the socket before any TLS handshake, so they cover
/// the handshake as well as everything after it: a server that accepts a
/// connection and then never speaks must not hold the agent's writer thread for
/// longer than any other kind of request would.
fn connect_tcp(endpoint: &Endpoint, timeout: Duration) -> Result<TcpStream> {
    let addr = endpoint.socket_addr()?;
    let stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|source| TransportError::Connect {
            endpoint: endpoint.host_header(),
            source,
        })?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| TransportError::Io(e.to_string()))?;
    Ok(stream)
}

fn connect_plain(endpoint: &Endpoint, timeout: Duration) -> Result<Box<dyn Stream>> {
    Ok(Box::new(connect_tcp(endpoint, timeout)?))
}

impl TlsTransport {
    /// The platform's verifier, with the platform's trust store.
    pub fn new() -> Result<Self> {
        Self::with_timeout(REQUEST_TIMEOUT)
    }

    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        let connector = native_tls::TlsConnector::new().map_err(|e| TransportError::Tls {
            endpoint: "the platform verifier".to_string(),
            detail: e.to_string(),
        })?;
        Ok(Self {
            exchange: Exchange::new(timeout),
            connector,
        })
    }
}

impl Transport for TlsTransport {
    fn post_json(
        &mut self,
        endpoint: &Endpoint,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse> {
        if endpoint.scheme != "https" {
            return Err(TransportError::BadEndpoint(format!(
                "`http://{}` needs a cleartext transport, not a TLS one",
                endpoint.host
            )));
        }

        let compressed = protocol::gzip(body).map_err(|e| TransportError::Io(e.to_string()))?;
        let connector = self.connector.clone();
        self.exchange.post(
            endpoint,
            path,
            headers,
            &compressed,
            move |endpoint, timeout| {
                let socket = connect_tcp(endpoint, timeout)?;
                // The handshake happens here, before the request is written, so a
                // certificate that does not verify fails this request rather than
                // a later one — and the body never reaches a server that has not
                // proved who it is.
                let session =
                    connector
                        .connect(&endpoint.host, socket)
                        .map_err(|e| TransportError::Tls {
                            endpoint: endpoint.host_header(),
                            detail: e.to_string(),
                        })?;
                Ok(Box::new(session) as Box<dyn Stream>)
            },
        )
    }
}

/// Read one length-delimited response, leaving anything past it in the buffer.
///
/// `Content-Length` is required rather than optional. On a connection that stays
/// open there is no end of stream to read to, so a response framed any other way
/// cannot be bounded — and guessing where one response ends is how a client
/// starts reading the next response's headers as this one's body.
fn read_response(conn: &mut Connection) -> Result<HttpResponse> {
    let header_end = loop {
        if let Some(position) = find_subslice(&conn.buffer, b"\r\n\r\n") {
            break position;
        }
        if conn.buffer.len() > MAX_HEADER_BYTES {
            return Err(TransportError::BadResponse(
                "response headers exceeded the client's limit".to_string(),
            ));
        }
        read_more(conn)?;
    };

    let length = content_length_of(&conn.buffer[..header_end])?;
    if length > MAX_RESPONSE_BYTES {
        return Err(TransportError::BadResponse(
            "response exceeded the client's limit".to_string(),
        ));
    }

    // Read until the whole response is present, then hand it to the one parser —
    // the same one the framing tests exercise, so an unparseable response is
    // rejected in exactly one place.
    let total = header_end + 4 + length;
    while conn.buffer.len() < total {
        read_more(conn)?;
    }
    let complete: Vec<u8> = conn.buffer[..total].to_vec();
    conn.buffer.drain(..total);

    parse_response(&complete)
}

/// The `Content-Length` a header block declares.
///
/// Separate from the parser because *this* caller needs it before the response
/// is complete: without it there is no way to tell how many more bytes belong to
/// this response rather than to the next one.
fn content_length_of(head: &[u8]) -> Result<usize> {
    let head = String::from_utf8_lossy(head);
    for line in head.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
            && let Ok(length) = value.trim().parse::<usize>()
        {
            return Ok(length);
        }
    }
    Err(TransportError::BadResponse(
        "response carried no Content-Length, so its end cannot be found on a \
         connection that stays open"
            .to_string(),
    ))
}

fn read_more(conn: &mut Connection) -> Result<()> {
    let mut chunk = [0u8; 8192];
    let read = conn
        .stream
        .read(&mut chunk)
        .map_err(|e| TransportError::Io(e.to_string()))?;
    if read == 0 {
        return Err(TransportError::Io(
            "the server closed the connection mid-response".to_string(),
        ));
    }
    conn.buffer.extend_from_slice(&chunk[..read]);
    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Whether a URL host is loopback.
///
/// Parses rather than string-matches, because the ways to write loopback are
/// more numerous than they look and a miss here is a credential sent in
/// cleartext. An IPv6 literal arrives bracketed (`[::1]`), which is the case a
/// naive `== "::1"` gets wrong, and `127.0.0.0/8` is entirely loopback rather
/// than just `.0.1`.
fn is_loopback_host(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if bare.eq_ignore_ascii_case("localhost") {
        return true;
    }
    bare.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Headers whose value is a secret. Used to decide whether cleartext is allowed.
fn is_credential_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "authorization" || name == protocol::ENROLLMENT_HEADER
}

// ---------------------------------------------------------------------------
// enrollment
// ---------------------------------------------------------------------------

/// A host credential, as returned by enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCredential {
    pub host_id: String,
    pub token: String,
}

impl HostCredential {
    /// Refuse to hold a credential we would not be able to use.
    pub fn new(token: String) -> Option<Self> {
        let parsed = HostToken::parse(&token)?;
        Some(Self {
            host_id: parsed.host_id,
            token,
        })
    }
}

/// Exchange the bootstrap secret for a host credential.
pub fn enroll(
    transport: &mut dyn Transport,
    endpoint: &Endpoint,
    enrollment_token: &str,
    request: &protocol::EnrollRequest,
) -> Result<HostCredential> {
    let body = serde_json::to_vec(request).map_err(|e| TransportError::Encode(e.to_string()))?;
    let response = transport
        .post_json(
            endpoint,
            protocol::ENROLL_PATH,
            &[(protocol::ENROLLMENT_HEADER, enrollment_token)],
            &body,
        )?
        .into_success()?;

    let enrolled: protocol::EnrollResponse = response.json()?;
    HostCredential::new(enrolled.host_token)
        .ok_or_else(|| TransportError::BadResponse("server issued a malformed host token".into()))
}

// ---------------------------------------------------------------------------
// the sink
// ---------------------------------------------------------------------------

/// Batches telemetry and alerts to the server.
///
/// Delivery is at-least-once: a batch that fails is retried with the same
/// `batch_id`, which is what lets the server drop the duplicate rather than
/// double-count it.
///
/// That makes the batch id load-bearing in both directions, and it has to be
/// unique per batch *and* stable across retries of one batch. Deriving it from
/// `shipped` satisfies neither: a batch carrying only alerts moves no events, so
/// the id would repeat and the server would discard the following batch as a
/// duplicate — losing events while the client recorded a success.
pub struct IngestSink {
    endpoint: Endpoint,
    transport: Box<dyn Transport>,
    token: String,
    host_id: String,
    /// Distinguishes this process's batch sequence from every other run's.
    session: String,
    events: Vec<TelemetryEvent>,
    alerts: Vec<Alert>,
    max_batch: usize,
    shipped: u64,
    failed: u64,
    /// Batch ids handed out. Incremented when a batch is *formed*, not when one
    /// is attempted, so an id can be reused by that batch's own retries.
    issued: u64,
    /// The id of a batch that failed and is waiting to go again.
    in_flight: Option<String>,
    last_error: Option<String>,
}

impl IngestSink {
    pub fn new(
        endpoint: Endpoint,
        transport: Box<dyn Transport>,
        credential: &HostCredential,
        max_batch: usize,
    ) -> Self {
        Self {
            endpoint,
            transport,
            token: credential.token.clone(),
            host_id: credential.host_id.clone(),
            session: session_nonce(),
            events: Vec::new(),
            alerts: Vec::new(),
            max_batch: max_batch.clamp(1, protocol::MAX_BATCH_EVENTS),
            shipped: 0,
            failed: 0,
            issued: 0,
            in_flight: None,
            last_error: None,
        }
    }

    /// The id for the batch about to be sent.
    ///
    /// A batch that failed already has one, and must keep it: the server
    /// recognises the second copy by id, so a retry arriving under a fresh id
    /// would be counted as new events rather than dropped as a duplicate.
    fn next_batch_id(&mut self) -> String {
        if let Some(id) = self.in_flight.take() {
            return id;
        }
        self.issued += 1;
        new_batch_id(&self.host_id, &self.session, self.issued)
    }

    /// Queue an alert. Alerts ride along with the next batch rather than going
    /// out on their own, so a burst of detections is not a burst of requests.
    pub fn enqueue_alert(&mut self, alert: Alert) {
        self.alerts.push(alert);
    }

    /// Queue one event, submitting automatically once the batch is full.
    pub fn enqueue(&mut self, event: TelemetryEvent) -> Result<usize> {
        let before = self.shipped;
        self.events.push(event);
        if self.events.len() >= self.max_batch {
            self.submit()?;
        }
        Ok((self.shipped - before) as usize)
    }

    /// Send everything queued. Returns how many events the server accepted.
    pub fn submit(&mut self) -> Result<usize> {
        if self.events.is_empty() && self.alerts.is_empty() {
            return Ok(0);
        }

        let batch_id = self.next_batch_id();
        let request = IngestRequest {
            batch_id: batch_id.clone(),
            sent_at: chrono::Utc::now(),
            events: std::mem::take(&mut self.events),
            alerts: std::mem::take(&mut self.alerts),
        };
        let batch_len = request.events.len();

        let body = match serde_json::to_vec(&request) {
            Ok(body) => body,
            Err(e) => {
                // A batch we cannot serialise will never succeed; drop it
                // rather than retry it forever.
                self.failed += 1;
                self.last_error = Some(e.to_string());
                return Err(TransportError::Encode(e.to_string()));
            }
        };

        let authorization = format!("{} {}", protocol::BEARER_SCHEME, self.token);
        let attempt = self
            .transport
            .post_json(
                &self.endpoint,
                INGEST_PATH,
                &[("Authorization", authorization.as_str())],
                &body,
            )
            .and_then(HttpResponse::into_success)
            .and_then(|response| response.json::<IngestResponse>());

        match attempt {
            Ok(response) => {
                // A duplicate is success, not a failure: the server already has
                // this batch. Counting it as zero would leave the sequence
                // counter stuck, so the client would resend the same batch id
                // forever and the server would reject it as a duplicate every
                // time — a retry loop that loses data while reporting no errors.
                let delivered = if response.duplicate {
                    batch_len
                } else {
                    response.accepted_events
                };
                self.shipped += delivered as u64;
                self.last_error = None;
                Ok(delivered)
            }
            Err(e) => {
                // Put the batch back so a retry can reuse it, in the original
                // order, which matters for the server's timeline — and keep its
                // id so that retry is recognised as the same batch.
                self.events = request.events;
                self.alerts = request.alerts;
                self.in_flight = Some(batch_id);
                self.failed += 1;
                self.last_error = Some(e.to_string());
                Err(e)
            }
        }
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    pub fn shipped(&self) -> u64 {
        self.shipped
    }

    pub fn failed(&self) -> u64 {
        self.failed
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn pending(&self) -> usize {
        self.events.len()
    }
}

impl EventSink for IngestSink {
    /// Queue a batch, submitting once the batch target is reached.
    ///
    /// An `Err` here means a *submission* failed, not that the events are gone:
    /// [`IngestSink::submit`] puts the batch back before returning, so a later
    /// `flush` retries it. A caller that does not care about the distinction
    /// can ignore the result and call `flush` before shutdown.
    fn write(&mut self, events: Vec<TelemetryEvent>) -> std::result::Result<(), SinkError> {
        self.events.extend(events);
        if self.events.len() >= self.max_batch {
            self.submit()
                .map_err(|e| SinkError::Temporary(e.to_string()))?;
        }
        Ok(())
    }

    fn flush(&mut self) -> std::result::Result<(), SinkError> {
        self.submit()
            .map(|_| ())
            .map_err(|e| SinkError::Temporary(e.to_string()))
    }

    fn buffered_count(&self) -> u64 {
        self.events.len() as u64
    }
}

/// A batch identifier, unique per host, per process run, and monotonic within
/// the run.
///
/// The session component is not decoration. A bare per-host counter restarts at
/// zero every time the agent does, and the server's deduplication window spans
/// runs — so a restarted agent would have its first batch silently swallowed as
/// a duplicate of the previous run's, and then every batch after it, because
/// the counter only advances when a batch is accepted.
///
/// Deliberately *not* random: two retries of the same batch within one run must
/// produce the same id, and the server must be able to recognise the retry
/// without trusting the client's clock.
fn new_batch_id(host_id: &str, session: &str, sequence: u64) -> String {
    format!("{host_id}-{session}-{sequence:012}")
}

/// Distinguishes one process run from the next.
///
/// Nanoseconds since the epoch at start-up: two runs cannot begin in the same
/// nanosecond, and this needs no entropy source, which keeps the agent free of
/// a random-number dependency it would otherwise carry only for this.
fn session_nonce() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => format!("{:032x}", elapsed.as_nanos()),
        Err(_) => "00000000000000000000000000000000".to_string(),
    }
}

impl std::fmt::Debug for IngestSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngestSink")
            .field("endpoint", &self.endpoint.host_header())
            .field("host_id", &self.host_id)
            .field("pending", &self.events.len())
            .field("shipped", &self.shipped)
            .field("failed", &self.failed)
            .finish()
    }
}

/// The API version this client speaks, so a mismatch can be refused rather
/// than misread.
pub fn api_version() -> u16 {
    API_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_parse_with_and_without_ports() {
        assert_eq!(
            Endpoint::parse("http://127.0.0.1:8787").unwrap(),
            Endpoint {
                scheme: "http".into(),
                host: "127.0.0.1".into(),
                port: 8787
            }
        );
        assert_eq!(Endpoint::parse("http://127.0.0.1").unwrap().port, 80);
        assert_eq!(
            Endpoint::parse("https://siem.example.com").unwrap().port,
            443
        );
        assert_eq!(
            Endpoint::parse("http://127.0.0.1:8787/").unwrap().port,
            8787
        );
    }

    #[test]
    fn malformed_endpoints_are_rejected() {
        for bad in [
            "",
            "127.0.0.1:8787",
            "http://",
            "http://127.0.0.1:notaport",
            "http://:8787",
            "ftp://127.0.0.1",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn host_header_omits_default_ports() {
        assert_eq!(
            Endpoint::parse("http://127.0.0.1").unwrap().host_header(),
            "127.0.0.1"
        );
        assert_eq!(
            Endpoint::parse("http://127.0.0.1:8787")
                .unwrap()
                .host_header(),
            "127.0.0.1:8787"
        );
    }

    #[test]
    fn only_loopback_or_tls_may_carry_a_credential() {
        for okay in [
            "http://127.0.0.1:8787",
            // The whole 127/8 block is loopback, not just .0.1.
            "http://127.0.0.2:8787",
            "http://localhost:8787",
            "http://LOCALHOST:8787",
            // IPv6 arrives bracketed, which a plain string match gets wrong.
            "http://[::1]:8787",
            "http://[0:0:0:0:0:0:0:1]:8787",
            "https://siem.example.com",
        ] {
            assert!(
                Endpoint::parse(okay).unwrap().allows_credential(),
                "{okay} should be allowed to carry a credential"
            );
        }

        // The case that matters: an agent pointed at a routable address over
        // cleartext must not silently ship its bearer token.
        for refused in [
            "http://10.0.0.5:8787",
            "http://siem.example.com",
            "http://172.16.0.1",
            "http://[fe80::1]:8787",
            // Almost-loopback is not loopback.
            "http://127.0.0.1.evil.com",
        ] {
            assert!(
                !Endpoint::parse(refused).unwrap().allows_credential(),
                "{refused} must not carry a credential"
            );
        }
    }

    #[test]
    fn cleartext_to_a_routable_host_is_refused_even_with_a_token() {
        // A short timeout on purpose: the second half of this test connects to a
        // routable address that will not answer, and there is nothing to learn
        // from waiting out the production timeout to find that out.
        let mut transport = CleartextTransport::with_timeout(Duration::from_millis(500));
        let endpoint = Endpoint::parse("http://10.0.0.5:8787").unwrap();

        let error = transport
            .post_json(
                &endpoint,
                INGEST_PATH,
                &[("Authorization", "Bearer a.b")],
                b"{}",
            )
            .unwrap_err();
        assert!(
            matches!(error, TransportError::CleartextRefused(_)),
            "{error:?}"
        );

        // Without a credential the call is allowed to try, and fails for a
        // different reason.
        let error = transport
            .post_json(&endpoint, INGEST_PATH, &[], b"{}")
            .unwrap_err();
        assert!(
            !matches!(error, TransportError::CleartextRefused(_)),
            "{error:?}"
        );
    }

    #[test]
    fn cleartext_refuses_an_https_endpoint_rather_than_downgrading() {
        // The scheme chose the transport, so the cleartext one must not follow an
        // https URL down to port 443 and send a token over it.
        let mut transport = CleartextTransport::new();
        let endpoint = Endpoint::parse("https://siem.example.com").unwrap();
        let error = transport
            .post_json(&endpoint, INGEST_PATH, &[], b"{}")
            .unwrap_err();
        assert!(
            matches!(error, TransportError::CleartextRefused(_)),
            "{error:?}"
        );
    }

    #[test]
    fn a_tls_transport_refuses_a_plaintext_endpoint() {
        // And the converse: naming a TLS transport for an http:// endpoint is a
        // configuration mistake, and quietly treating it as cleartext is how the
        // mistake survives.
        let mut transport = TlsTransport::new().expect("the platform verifier");
        let endpoint = Endpoint::parse("http://127.0.0.1:8787").unwrap();
        let error = transport
            .post_json(&endpoint, INGEST_PATH, &[], b"{}")
            .unwrap_err();
        assert!(matches!(error, TransportError::BadEndpoint(_)), "{error:?}");
    }

    /// A server that is not speaking TLS must fail the handshake, and must never
    /// receive the request.
    ///
    /// This is the property the cleartext rule exists for: an agent that believes
    /// it is talking to a TLS endpoint and is not is the worst outcome available
    /// here, so the failure has to happen before the body — which carries the host
    /// token — is written.
    #[test]
    fn tls_against_a_plaintext_server_fails_before_the_request_is_written() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));

        let recorder = Arc::clone(&seen);
        let server = std::thread::spawn(move || {
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            socket
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut buf = [0u8; 4096];
            // Read whatever is offered, answering the first read with a plaintext
            // HTTP response: exactly what a cleartext server on the TLS port looks
            // like.
            for turn in 0..2 {
                match socket.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        recorder.lock().unwrap().extend_from_slice(&buf[..n]);
                        if turn == 0 {
                            let _ =
                                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                            let _ = socket.flush();
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let endpoint = Endpoint::parse(&format!("https://127.0.0.1:{port}")).unwrap();
        let mut transport =
            TlsTransport::with_timeout(Duration::from_secs(5)).expect("the platform verifier");
        let error = transport
            .post_json(
                &endpoint,
                INGEST_PATH,
                &[("Authorization", "Bearer a.b.secret")],
                b"{\"telemetry\":\"must-not-be-sent\"}",
            )
            .unwrap_err();
        server.join().expect("the recorder thread");

        assert!(matches!(error, TransportError::Tls { .. }), "{error:?}");
        let seen = String::from_utf8_lossy(&seen.lock().unwrap()).to_string();
        assert!(
            !seen.contains("must-not-be-sent"),
            "the body reached a server that never proved who it was: {seen:?}"
        );
        assert!(
            !seen.contains("secret"),
            "the credential reached a server that never proved who it was: {seen:?}"
        );
    }

    /// Build a response with a correct `Content-Length`, so these tests exercise
    /// the parser rather than my ability to count bytes by hand.
    fn response(status: &str, body: &[u8]) -> Vec<u8> {
        let mut out =
            format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\n").into_bytes();
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        out.extend_from_slice(body);
        out
    }

    /// A loopback server that serves `responses` on the first connection it
    /// accepts, recording every request header block it saw.
    fn serve_one_connection(
        responses: usize,
    ) -> (
        u16,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<std::sync::Mutex<String>>,
    ) {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        let listener = TcpListener::bind("127.0.0.1:0").expect("binds a loopback port");
        let port = listener.local_addr().expect("an address").port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let headers = Arc::new(Mutex::new(String::new()));

        let counter = Arc::clone(&accepts);
        let seen = Arc::clone(&headers);
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let mut reader = BufReader::new(stream.try_clone().expect("clones the socket"));

            for _ in 0..responses {
                let mut length = 0usize;
                let mut block = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if line == "\r\n" {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(rest) = lower.strip_prefix("content-length:") {
                        length = rest.trim().parse().unwrap_or(0);
                    }
                    block.push_str(&lower);
                }
                if let Ok(mut seen) = seen.lock() {
                    seen.push_str(&block);
                }

                let mut body = vec![0u8; length];
                if reader.read_exact(&mut body).is_err() {
                    return;
                }

                let payload = b"{\"ok\":true}";
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(payload);
                let _ = stream.flush();
            }
        });

        (port, accepts, headers)
    }

    #[test]
    fn two_posts_reuse_one_connection_and_carry_gzip() {
        // The two properties keep-alive depends on: the second request goes down
        // the same socket, and the body is declared as gzip so the server knows
        // to inflate it. A client that opened a connection per batch would pass
        // every other test in this file and fail this one.
        let (port, accepts, headers) = serve_one_connection(2);
        let endpoint =
            Endpoint::parse(&format!("http://127.0.0.1:{port}")).expect("a valid endpoint");
        let mut transport = CleartextTransport::new();

        for _ in 0..2 {
            let response = transport
                .post_json(&endpoint, INGEST_PATH, &[], b"{\"events\":[]}")
                .expect("the request succeeds");
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"{\"ok\":true}");
        }

        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the second post must reuse the connection rather than open another"
        );
        assert!(
            headers
                .lock()
                .expect("not poisoned")
                .contains("content-encoding: gzip"),
            "the body must be declared as gzip"
        );
    }

    #[test]
    fn a_typical_response_parses() {
        let body = b"{\"status\":\"ok\"}";
        let response = parse_response(&response("200 OK", body)).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, body);
    }

    #[test]
    fn response_parsing_rejects_what_it_cannot_be_certain_about() {
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\n").is_err(),
            "no terminator"
        );
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nX: y\r\n\r\nbody").is_err(),
            "no length"
        );
        assert!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n"
            )
            .is_err(),
            "chunked"
        );
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort").is_err(),
            "truncated"
        );
        assert!(parse_response(b"GARBAGE\r\n\r\n").is_err(), "not HTTP");
        assert!(
            parse_response(b"HTTP/1.1 abc OK\r\nContent-Length: 0\r\n\r\n").is_err(),
            "bad status"
        );
    }

    #[test]
    fn an_empty_body_is_valid_when_declared() {
        let response = parse_response(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .expect("204 with an explicit zero length");
        assert_eq!(response.status, 204);
        assert!(response.body.is_empty());
    }

    #[test]
    fn non_2xx_becomes_the_servers_error() {
        let body = b"{\"error\":\"unauthorized\"}";
        let error = parse_response(&response("401 Unauthorized", body))
            .unwrap()
            .into_success()
            .unwrap_err();
        match error {
            TransportError::Server { status, error } => {
                assert_eq!(status, 401);
                assert_eq!(error, "unauthorized");
            }
            other => panic!("expected a server error, got {other:?}"),
        }
    }

    #[test]
    fn batch_ids_are_unique_across_runs_but_stable_within_one() {
        let session = "0123456789abcdef0123456789abcdef";
        // Stable within a run, so a retry is recognised.
        assert_eq!(
            new_batch_id("abc", session, 41),
            new_batch_id("abc", session, 41)
        );
        // Distinct hosts do not collide on the same sequence.
        assert_ne!(
            new_batch_id("abc", session, 1),
            new_batch_id("def", session, 1)
        );
        // A new run gets a new session, which is what stops a restarted agent's
        // first batch from being mistaken for its previous run's.
        assert_ne!(
            new_batch_id("abc", "aaaa", 0),
            new_batch_id("abc", "bbbb", 0)
        );
    }

    #[test]
    fn session_nonces_differ_between_calls() {
        let first = session_nonce();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let second = session_nonce();
        assert_ne!(first, second);
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn credential_construction_validates_shape() {
        let good = format!("0123456789abcdef.{}", "e".repeat(64));
        let credential = HostCredential::new(good.clone()).expect("valid");
        assert_eq!(credential.host_id, "0123456789abcdef");
        assert_eq!(credential.token, good);

        assert!(HostCredential::new("nonsense".to_string()).is_none());
        assert!(HostCredential::new(String::new()).is_none());
    }

    #[test]
    fn credential_headers_are_recognised_case_insensitively() {
        assert!(is_credential_header("Authorization"));
        assert!(is_credential_header("authorization"));
        assert!(is_credential_header(protocol::ENROLLMENT_HEADER));
        assert!(is_credential_header("X-Enrollment-Token"));
        assert!(!is_credential_header("content-type"));
    }

    #[test]
    fn an_empty_sink_submits_nothing_and_touches_no_network() {
        let credential =
            HostCredential::new(format!("0123456789abcdef.{}", "a".repeat(64))).unwrap();
        let endpoint = Endpoint::parse("http://10.0.0.5:8787").unwrap();
        // A transport pointed at an unreachable host proves `submit` returns
        // early rather than trying to send.
        let mut sink = IngestSink::new(
            endpoint,
            Box::new(CleartextTransport::new()),
            &credential,
            10,
        );

        assert_eq!(sink.submit().unwrap(), 0);
        assert_eq!(sink.pending(), 0);
        assert_eq!(sink.shipped(), 0);
    }

    fn credential() -> HostCredential {
        HostCredential::new(format!("0123456789abcdef.{}", "a".repeat(64))).unwrap()
    }

    fn alert() -> Alert {
        Alert::new(
            model::AlertId::new("a-1").unwrap(),
            model::RuleId::new("R1").unwrap(),
            "a title".into(),
            "a description".into(),
            model::Severity::Medium,
            chrono::Utc::now(),
            model::HostId::new("0123456789abcdef").unwrap(),
            Vec::new(),
            Vec::new(),
        )
    }

    #[test]
    fn a_batch_of_alerts_alone_does_not_hand_out_a_repeated_id() {
        // The id used to be derived from the shipped-event count, so a batch
        // holding only alerts left that count exactly where it was and the next
        // batch reused the id. The server drops a repeated id as a duplicate,
        // so those events were discarded while the client recorded a success —
        // the worst shape a delivery bug can take.
        let endpoint = Endpoint::parse("http://10.0.0.5:8787").unwrap();
        let mut sink = IngestSink::new(
            endpoint,
            Box::new(CleartextTransport::new()),
            &credential(),
            10,
        );

        let ids: Vec<String> = (0..5).map(|_| sink.next_batch_id()).collect();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), ids.len(), "ids repeated: {ids:?}");
        assert!(
            ids[0].ends_with("-000000000001"),
            "the sequence starts at one: {}",
            ids[0]
        );
    }

    #[test]
    fn a_failed_submit_hands_its_id_back_for_the_retry() {
        // A retry has to claim the same batch. If it went out under a new id the
        // server would count the second copy as new events, which is the one
        // direction at-least-once delivery must never be wrong in.
        let endpoint = Endpoint::parse("http://10.0.0.5:8787").unwrap();
        let mut sink = IngestSink::new(
            endpoint,
            Box::new(CleartextTransport::new()),
            &credential(),
            10,
        );
        sink.enqueue_alert(alert());

        // Refused before a socket is opened, so this failure is deterministic
        // and completely offline.
        assert!(
            sink.submit().is_err(),
            "cleartext to a routable host is refused"
        );

        let retry = sink.next_batch_id();
        assert!(
            retry.ends_with("-000000000001"),
            "the retry must claim the batch that failed: {retry}"
        );
        let next = sink.next_batch_id();
        assert!(
            next.ends_with("-000000000002"),
            "a claimed id must not be handed out twice: {next}"
        );
    }
}
