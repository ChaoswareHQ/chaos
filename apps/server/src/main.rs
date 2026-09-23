//! The Chaos ingest server.
//!
//! Three jobs, in order of importance:
//!
//! 1. Decide who is allowed to talk to it ([`auth`]).
//! 2. Accept batches and store them once, retries included ([`store`]).
//! 3. Show an operator what arrived ([`dashboard`]).
//!
//! # The shape of the surface
//!
//! Two of the four routes are open. `/health` answers with a constant body and
//! no counts, because an unauthenticated endpoint that reports "3,412 hosts" is
//! a reconnaissance service. `/static/app.css` is a fixed byte string.
//! Everything else requires a credential.
//!
//! Every failure returns the same JSON shape and the same body for every
//! authentication outcome, so a caller cannot use the API to learn which host
//! ids exist.
//!
//! # What is deliberately not here yet
//!
//! TLS. The server binds loopback by default and refuses to start on a routable
//! address unless you pass `--allow-cleartext`, which prints a warning and is
//! meant for a container behind a TLS-terminating proxy. This is the same
//! fail-closed rule the client enforces from the other side, and it exists for
//! the same reason: the bearer tokens on this endpoint are the security of the
//! whole fleet, and "we will add TLS later" is how they end up on a wire.

mod auth;
mod dashboard;
mod journal;
mod store;

use auth::{EnrollmentAuthority, TokenVerifier};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, RawQuery, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use journal::{Journal, Record};
use protocol::{
    API_VERSION, ApiError, ENROLL_PATH, ENROLLMENT_HEADER, EnrollRequest, EnrollResponse,
    HEALTH_PATH, HealthResponse, INGEST_PATH, IngestRequest, IngestResponse,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use store::{HostRecord, IncomingAlert, IngestOutcome, MemoryStore, Store};

/// Bodies larger than this are refused before they are read into memory.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
struct AppState {
    store: Arc<MemoryStore>,
    enrollment: Arc<EnrollmentAuthority>,
    verifier: Arc<TokenVerifier>,
    max_batch_events: usize,
    /// The console's shared secret, when one was configured.
    ///
    /// `None` leaves the console open, which is the same trust model the rest of
    /// the product uses for a loopback bind: put it behind something that
    /// authenticates, or name a token here.
    console_token: Option<Arc<String>>,
    /// The durable log, when `--data` asked for one.
    ///
    /// `None` means state lives only in memory and a restart is a reset. A
    /// failure to append is never fatal to a request; see [`append_best_effort`].
    journal: Option<Arc<Mutex<Journal>>>,
    /// Where the journal lives, for the console to print.
    data_dir: Option<PathBuf>,
    /// When this process started, so the console can say how long it has been up.
    started: DateTime<Utc>,
}

impl AppState {
    /// What the console shows about the server itself.
    ///
    /// Built per request rather than cached, because every number in it moves:
    /// the journal's record count, the store's occupancy, the counters. The one
    /// cost worth naming is the journal's lock, which is taken, read for four
    /// integers, and released before anything is rendered.
    fn status(&self) -> dashboard::Status {
        dashboard::Status {
            started: self.started,
            store_cap: self.store.alert_cap(),
            batch_cap: self.store.batch_cap(),
            host_cap: self.enrollment.max_hosts,
            journal: self.journal.as_ref().map(|journal| {
                let stats = journal.lock().unwrap_or_else(|e| e.into_inner()).stats();
                dashboard::JournalFacts {
                    path: self
                        .data_dir
                        .as_ref()
                        .map(|dir| dir.display().to_string())
                        .unwrap_or_default(),
                    segments: stats.segments,
                    replayed: stats.replayed,
                    skipped: stats.skipped,
                    bytes: stats.bytes,
                }
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/// The one error type the API returns.
struct Failure {
    status: StatusCode,
    body: ApiError,
}

impl Failure {
    /// Client-facing: says what went wrong with the request, nothing about us.
    fn client(status: StatusCode, error: &str) -> Self {
        Self {
            status,
            body: ApiError::new(error),
        }
    }

    /// Logged, and answered with a generic message.
    ///
    /// `detail` never reaches the caller: it is written to the server's log so
    /// an operator can debug, while the response stays uninformative.
    fn internal(error: &str, detail: impl std::fmt::Display) -> Self {
        eprintln!("error: {error}: {detail}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: ApiError::new(error),
        }
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

type ApiResult<T> = Result<T, Failure>;

/// A body that would inflate past this is refused *while* inflating, so the
/// buffer is never built. Sized well above a full batch of typed events and well
/// below anything that would matter to a host.
const MAX_INFLATED_BYTES: usize = 32 * 1024 * 1024;

/// The request body, decompressed if the headers say it is compressed.
///
/// Shared by every handler that takes a body, which is the point. When this
/// lived inside `ingest`, `enroll` did not have it, and a client that compresses
/// everything — which is what a client with one POST path does — got
/// `400 malformed_request` on enrollment, naming nothing that pointed at the
/// cause. A shared function makes forgetting cost a compile error instead.
///
/// Decompression happens in the handler rather than in a layer so each handler's
/// own size limit is enforced on the *decompressed* request: a layer that
/// inflated first would let a small compressed body expand into something the
/// handler's limits do not describe.
fn inflated(headers: &HeaderMap, body: Bytes) -> ApiResult<Bytes> {
    match headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
    {
        Some(encoding) if encoding.eq_ignore_ascii_case(protocol::GZIP_ENCODING) => {
            let body = protocol::gunzip(&body, MAX_INFLATED_BYTES)
                .map_err(|_| Failure::client(StatusCode::BAD_REQUEST, "bad_gzip"))?;
            Ok(Bytes::from(body))
        }
        // Fail closed on an encoding we do not implement, rather than reading it
        // as if it were absent and parsing compressed bytes as JSON.
        Some(_) => Err(Failure::client(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_content_encoding",
        )),
        None => Ok(body),
    }
}

/// Parse a JSON body, keeping the error opaque.
fn parse_json<T: serde::de::DeserializeOwned>(body: &Bytes) -> ApiResult<T> {
    serde_json::from_slice(body)
        // The parse error is logged, not returned: it names field paths and
        // types, which is a description of our internals.
        .map_err(|e| {
            eprintln!("warning: rejected a body that did not parse: {e}");
            Failure::client(StatusCode::BAD_REQUEST, "malformed_request")
        })
}

// ---------------------------------------------------------------------------
// journaling
// ---------------------------------------------------------------------------

/// Append to the journal without letting a disk problem fail the request.
///
/// By the time this runs the events are already in memory and the host has
/// already been told they were accepted, so turning a full disk into a 500 would
/// be a lie about what happened. The honest answer is to say so on stderr and
/// keep serving: the journal being a few seconds behind is exactly what the
/// agent's own at-least-once retry covers.
fn append_best_effort(journal: &Mutex<Journal>, record: &Record) {
    let result = match journal.lock() {
        Ok(mut journal) => journal.append(record),
        // A panic while appending is not a reason to stop journaling forever.
        Err(poisoned) => poisoned.into_inner().append(record),
    };
    if let Err(e) = result {
        eprintln!("error: could not append to the journal: {e}");
    }
}

/// Apply a batch and, unless it was a retry, journal it exactly once.
///
/// The clock is read here and used for both the state and the journal. If the
/// two disagreed, a replay would rebuild rows stamped with a different instant
/// than the ones they replaced, and "identical after a restart" would be off by
/// however long the append took.
fn apply_batch(
    store: &MemoryStore,
    journal: Option<&Mutex<Journal>>,
    host_id: &str,
    batch_id: &str,
    events: usize,
    alerts: Vec<IncomingAlert>,
) -> IngestOutcome {
    // Without a journal there is nothing that needs the instant, so this is the
    // plain store path — the same one a caller that never asked for durability
    // has always used.
    let Some(journal) = journal else {
        return store.record_ingest(host_id, batch_id, events, alerts);
    };

    let at = Utc::now();
    let for_journal = alerts.clone();
    let outcome = store.apply_ingest(host_id, batch_id, events, alerts, at);

    if !outcome.duplicate {
        append_best_effort(
            journal,
            &Record::Ingest {
                host_id: host_id.to_string(),
                batch_id: batch_id.to_string(),
                events,
                alerts: for_journal,
                at,
            },
        );
    }
    outcome
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

/// Liveness. Deliberately says nothing about what the server holds.
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        api_version: API_VERSION,
    })
}

/// Exchange the bootstrap secret for a host credential.
async fn enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<EnrollResponse>> {
    let presented = headers
        .get(ENROLLMENT_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    if !state.enrollment.accepts(presented) {
        // One message for every failure here, including a missing header.
        return Err(Failure::client(StatusCode::UNAUTHORIZED, "unauthorized"));
    }

    if state.store.enrollment_count() >= state.enrollment.max_hosts {
        return Err(Failure::client(
            StatusCode::TOO_MANY_REQUESTS,
            "enrollment_limit_reached",
        ));
    }

    let body = inflated(&headers, body)?;
    let request: EnrollRequest = parse_json(&body)?;

    // Length caps before anything is stored: a hostname is not a place to put
    // a megabyte of data.
    if request.hostname.is_empty() || request.hostname.len() > 255 {
        return Err(Failure::client(StatusCode::BAD_REQUEST, "bad_hostname"));
    }
    if request.os.len() > 64 || request.agent_version.len() > 64 {
        return Err(Failure::client(StatusCode::BAD_REQUEST, "bad_metadata"));
    }

    let issued = auth::issue_credential()
        .map_err(|e| Failure::internal("credential_generation_failed", e))?;

    let now = Utc::now();
    let record = HostRecord {
        host_id: issued.host_id.clone(),
        hostname: request.hostname,
        os: request.os,
        secret_hash: issued.secret_hash,
        enrolled_at: now,
        last_seen: now,
        events: 0,
        alerts: 0,
    };

    if !state.store.insert_host(record.clone()) {
        // A collision on a random 64-bit id. Retrying is the right answer.
        return Err(Failure::internal(
            "host_id_collision",
            "rng produced an id already in use",
        ));
    }

    // Journaled only after the store accepts it: a collision never reached the
    // store, so writing it down would replay a host this process refused.
    if let Some(journal) = state.journal.as_deref() {
        append_best_effort(journal, &Record::Host { record });
    }

    // Logged without the secret: this line is audit trail, not a credential
    // store.
    println!("enroll: host {} enrolled", issued.host_id);

    Ok(Json(EnrollResponse {
        host_id: issued.host_id,
        host_token: issued.token,
        server_time: now,
    }))
}

/// Accept one batch of telemetry and alerts.
async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<IngestResponse>> {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    let store = Arc::clone(&state.store);
    let verified = state
        .verifier
        .verify(authorization, |host_id| store.secret_hash(host_id))
        .ok_or_else(|| Failure::client(StatusCode::UNAUTHORIZED, "unauthorized"))?;

    // A body that would inflate past this is refused while inflating, so the
    // buffer is never built. Sized well above a full batch of typed events and
    // well below anything that would matter to the host.
    let body = inflated(&headers, body)?;

    let request: IngestRequest = parse_json(&body)?;

    if request.events.len() > state.max_batch_events {
        return Err(Failure::client(
            StatusCode::PAYLOAD_TOO_LARGE,
            "batch_too_large",
        ));
    }

    // Everything is truncated here rather than in the store, because the store
    // is where these strings become keys and rows. The console renders them and
    // a client is untrusted, so an unbounded string is both a rendering problem
    // and a memory one.
    let alerts: Vec<IncomingAlert> = request
        .alerts
        .iter()
        .map(|alert| IncomingAlert {
            // Kept as sent: a restatement names an id the store has already
            // folded in, and recognising it is what stops the count inflating.
            alert_id: alert.id.as_str().chars().take(128).collect(),
            rule_id: alert.rule_id.as_str().chars().take(64).collect(),
            severity: alert.severity,
            title: alert.title.chars().take(256).collect(),
            description: alert.description.chars().take(512).collect(),
            technique: alert
                .mitre_techniques
                .first()
                .map(|t| t.chars().take(32).collect())
                .unwrap_or_default(),
            count: alert.count.max(1),
        })
        .collect();

    let outcome = apply_batch(
        &store,
        state.journal.as_deref(),
        &verified.host_id,
        &request.batch_id,
        request.events.len(),
        alerts,
    );

    Ok(Json(IngestResponse {
        accepted_events: outcome.accepted_events,
        accepted_alerts: outcome.accepted_alerts,
        duplicate: outcome.duplicate,
        server_time: Utc::now(),
    }))
}

/// The console.
///
/// The query string is the whole interface state: view, and the facets that
/// narrow the queue. Without scripting there is nowhere else for a filter to
/// live, so a filtered view is a URL an analyst can bookmark or send to a
/// colleague.
///
async fn console(State(state): State<AppState>, RawQuery(query): RawQuery) -> Html<String> {
    let filters = dashboard::Filters::parse(query.as_deref().unwrap_or_default());
    Html(dashboard::page(
        &state.store.snapshot(),
        &state.status(),
        &filters,
        Utc::now(),
    ))
}

/// The stylesheet, served from this origin so the CSP can say `'self'`.
async fn stylesheet() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
        dashboard::stylesheet(),
    )
}

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

/// Security headers, applied to every response.
///
/// The CSP is the load-bearing one and it is strict by construction: there is
/// no `script-src`, which means `default-src 'none'` covers it and no script
/// from any origin may run. Nothing in the console needs one.
async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; img-src 'self'; \
             base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    // Telemetry is sensitive and the console is not a cache. `no-store` also
    // keeps a shared proxy from holding alert bodies.
    headers.insert("cache-control", HeaderValue::from_static("no-store"));

    response
}

// ---------------------------------------------------------------------------
// wiring
// ---------------------------------------------------------------------------

fn app(state: AppState) -> Router {
    // The console is the only surface a person reaches, so it is the only one
    // that gets a credential of its own. Enrollment and ingest authenticate with
    // the protocol's own tokens and have to stay reachable by hosts.
    let console = Router::new()
        .route("/", get(console))
        .route("/static/app.css", get(stylesheet))
        .layer(middleware::from_fn_with_state(state.clone(), console_auth));

    Router::new()
        .route(HEALTH_PATH, get(health))
        .route(ENROLL_PATH, post(enroll))
        .route(INGEST_PATH, post(ingest))
        .merge(console)
        .layer(middleware::from_fn(security_headers))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Require the console token, when one is configured.
///
/// A shared secret rather than a login, deliberately. There is still no notion of
/// *who* an operator is — which is why the console has no acknowledge button to
/// attribute a write to — so a login form would be inventing an identity to
/// justify itself. What this does instead is make the console not-open, which is
/// the honest description of a token.
///
/// The token may arrive in the query string, which is the only way to reach a
/// page from a browser with no JavaScript and no session. When it does, it is
/// remembered in a cookie so the page's own stylesheet and every link it renders
/// work without the token being pasted onto each one.
async fn console_auth(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(expected) = state.console_token.clone() else {
        return next.run(request).await;
    };

    let from_query = token_from_query(request.uri().query());
    let presented = from_query
        .clone()
        .or_else(|| token_from_cookie(request.headers()));

    let authorised = presented
        .as_ref()
        .is_some_and(|token| constant_time_eq(token, expected.as_str()));
    if !authorised {
        // No body and no detail: a wrong token and a missing one are the same
        // answer, because telling them apart tells an attacker which half they
        // got right.
        return (StatusCode::UNAUTHORIZED, "console: a token is required\n").into_response();
    }

    let mut response = next.run(request).await;
    if from_query.is_some() && !response.headers().contains_key("set-cookie") {
        // `HttpOnly` so a script cannot read it back out; `SameSite=Strict` so a
        // link from somewhere else cannot carry it. Not `Secure`, because the
        // server may legitimately be speaking cleartext to a loopback or proxied
        // caller — the deployment that needs `Secure` is the one terminating TLS
        // in front, and that is where it belongs.
        if let Ok(value) = HeaderValue::from_str(&format!(
            "{CONSOLE_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict",
            expected.as_str()
        )) {
            response.headers_mut().insert("set-cookie", value);
        }
    }
    response
}

/// The cookie the console remembers its token in.
const CONSOLE_COOKIE: &str = "chaos_console";

fn token_from_query(query: Option<&str>) -> Option<String> {
    let query = query?;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == "token" && !value.is_empty()).then(|| value.to_string())
    })
}

fn token_from_cookie(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get("cookie")?.to_str().ok()?;
    cookies.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == CONSOLE_COOKIE && !value.is_empty()).then(|| value.to_string())
    })
}

/// Compare two secrets without leaking how much of one matched through timing.
///
/// The length check is not constant time, and does not need to be: the length of
/// a token is not the secret. The byte comparison is, because that is where a
/// byte-at-a-time oracle would otherwise live.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

struct Args {
    bind: SocketAddr,
    enrollment_token: String,
    generated_token: bool,
    max_hosts: usize,
    max_batch_events: usize,
    /// Shared secret for the console, when one was asked for.
    console_token: Option<String>,
    /// Directory for the durable journal, when one was asked for. Without it the
    /// server keeps everything in memory and a restart is a reset.
    data_dir: Option<PathBuf>,
    segment_mb: u64,
    retain_segments: usize,
}

impl Args {
    /// The rotation bound in bytes. At least one, so a nonsensical `--segment-mb`
    /// rotates on every record rather than dividing by zero.
    fn segment_bytes(&self) -> u64 {
        self.segment_mb.saturating_mul(1024 * 1024).max(1)
    }
}

fn parse_args() -> std::result::Result<Args, String> {
    let mut bind: SocketAddr = "127.0.0.1:8787".parse().expect("valid default");
    let mut token = std::env::var("CHAOS_ENROLLMENT_TOKEN").ok();
    let mut max_hosts = 500usize;
    let mut max_batch_events = protocol::MAX_BATCH_EVENTS;
    let mut console_token = std::env::var("CHAOS_CONSOLE_TOKEN").ok();
    let mut data_dir = std::env::var_os("CHAOS_DATA_DIR").map(PathBuf::from);
    let mut segment_mb = 64u64;
    let mut retain_segments = 8usize;

    let mut args = std::env::args().skip(1);
    let mut allow_cleartext = false;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--bind" => {
                let value = args.next().ok_or("--bind needs an address")?;
                bind = value
                    .parse()
                    .map_err(|e| format!("bad --bind `{value}`: {e}"))?;
            }
            "--enrollment-token" => {
                token = Some(args.next().ok_or("--enrollment-token needs a value")?);
            }
            "--max-hosts" => {
                max_hosts = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--max-hosts needs a number")?;
            }
            "--max-batch-events" => {
                max_batch_events = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--max-batch-events needs a number")?;
            }
            "--console-token" => {
                console_token = Some(args.next().ok_or("--console-token needs a value")?);
            }
            "--data" => {
                data_dir = Some(PathBuf::from(
                    args.next().ok_or("--data needs a directory")?,
                ));
            }
            "--segment-mb" => {
                segment_mb = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--segment-mb needs a number")?;
            }
            "--retain-segments" => {
                retain_segments = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--retain-segments needs a number")?;
            }
            "--allow-cleartext" => allow_cleartext = true,
            "--help" | "-h" => return Err(usage()),
            other => return Err(format!("unknown argument `{other}`\n\n{}", usage())),
        }
    }

    // Refuse to expose bearer-token authentication on a routable address
    // without TLS, unless someone has said out loud that a proxy is in front.
    if !bind.ip().is_loopback() && !allow_cleartext {
        return Err(format!(
            "refusing to bind {bind}: this server authenticates with bearer tokens \
             and has no TLS of its own.\n\
             Bind a loopback address, terminate TLS in front of it, or pass \
             --allow-cleartext if you have already done so."
        ));
    }
    if !bind.ip().is_loopback() {
        eprintln!(
            "warning: listening on {bind} in cleartext; tokens are only as safe as the network"
        );
    }

    let (enrollment_token, generated_token) = match token {
        Some(token) => (token, false),
        None => (
            auth::new_enrollment_token().map_err(|e| e.to_string())?,
            true,
        ),
    };

    Ok(Args {
        bind,
        enrollment_token,
        generated_token,
        max_hosts,
        max_batch_events,
        console_token,
        data_dir,
        segment_mb,
        retain_segments,
    })
}

fn usage() -> String {
    "chaos ingest server\n\
     \n\
     usage: server [--bind ADDR] [--enrollment-token TOKEN] [--max-hosts N]
     \x20              [--max-batch-events N] [--console-token TOKEN] [--allow-cleartext]
     \x20              [--data DIR] [--segment-mb N] [--retain-segments N]
     \n\
     --bind                 default 127.0.0.1:8787
     --enrollment-token     bootstrap secret; a random one is generated if omitted
                            (env: CHAOS_ENROLLMENT_TOKEN)
     --max-hosts            cap on enrolled hosts, default 500
     --max-batch-events     per-batch event cap, default 5000
     --console-token        require this token on the console (env:
                            CHAOS_CONSOLE_TOKEN); without it the console is open
     --data                 directory for a journal that survives a restart
                            (env: CHAOS_DATA_DIR); without it state is memory-only
     --segment-mb           rotate the journal at this many MiB, default 64
     --retain-segments      segments to keep, oldest deleted, default 8
     --allow-cleartext      permit a non-loopback bind without TLS"
        .to_string()
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let verifier = match TokenVerifier::new() {
        Ok(verifier) => Arc::new(verifier),
        Err(e) => {
            eprintln!("fatal: no entropy source: {e}");
            std::process::exit(1);
        }
    };

    let store = Arc::new(MemoryStore::default());

    // Opened and replayed before the listener exists, so the console's first
    // request already sees the state the last run ended with.
    let mut journal: Option<Arc<Mutex<Journal>>> = None;
    let mut journal_summary = "off — in-memory only, nothing survives a restart".to_string();
    if let Some(dir) = args.data_dir.as_deref() {
        match Journal::open(dir, args.segment_bytes(), args.retain_segments) {
            Ok((opened, records)) => {
                let replayed = store.replay(&records);
                if replayed.unknown_hosts > 0 {
                    eprintln!(
                        "warning: {} journal records named a host that was never enrolled; skipped",
                        replayed.unknown_hosts
                    );
                }
                let stats = opened.stats();
                journal_summary = format!(
                    "{} ({} records replayed, {} skipped, {} segments)",
                    dir.display(),
                    stats.replayed,
                    stats.skipped,
                    stats.segments
                );
                journal = Some(Arc::new(Mutex::new(opened)));
            }
            Err(e) => {
                // Fatal on purpose: the journal is the whole reason state
                // outlives the process, and starting without it would silently
                // discard everything it holds.
                eprintln!("fatal: cannot open the journal at {}: {e}", dir.display());
                eprintln!("  refusing to start rather than pretending to persist");
                std::process::exit(1);
            }
        }
    }

    let state = AppState {
        store,
        enrollment: Arc::new(EnrollmentAuthority::new(
            &args.enrollment_token,
            args.max_hosts,
        )),
        verifier,
        max_batch_events: args.max_batch_events,
        console_token: args.console_token.as_ref().map(|t| Arc::new(t.clone())),
        journal,
        data_dir: args.data_dir.clone(),
        started: Utc::now(),
    };

    let listener = match tokio::net::TcpListener::bind(args.bind).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("fatal: cannot bind {}: {e}", args.bind);
            // The socket error says the port is taken; it does not say by what,
            // or what to do about it. On a machine where the server is left
            // running in another window, "already in use" is a five-second
            // problem and "os error 10048" reads like a bug.
            if e.kind() == std::io::ErrorKind::AddrInUse {
                eprintln!();
                eprintln!(
                    "  Something is already listening on {}. Either it is another",
                    args.bind
                );
                eprintln!("  copy of this server — in which case the console is already up at");
                eprintln!(
                    "  http://{}/ and you do not need a second one — or it is a",
                    args.bind
                );
                eprintln!("  different process, and you should pick another port:");
                eprintln!();
                eprintln!("    server --bind 127.0.0.1:8788 --enrollment-token ...");
                eprintln!();
                eprintln!("  To find the holder on Windows:");
                eprintln!("    netstat -ano | findstr :{}", args.bind.port());
                eprintln!("    taskkill /PID <the pid in the last column> /F");
            }
            std::process::exit(1);
        }
    };

    println!("chaos server listening on http://{}", args.bind);
    println!("  console        http://{}/", args.bind);
    if args.generated_token {
        println!("  enrollment     {}", args.enrollment_token);
        println!("                 (generated for this run; set --enrollment-token or");
        println!("                  CHAOS_ENROLLMENT_TOKEN to keep it stable)");
    } else {
        println!("  enrollment     (from configuration)");
    }
    println!("  max hosts      {}", args.max_hosts);
    println!("  max batch      {} events", args.max_batch_events);
    println!("  journal        {journal_summary}");
    println!(
        "  console        {}",
        if args.console_token.is_some() {
            "requires the configured token"
        } else {
            "open — reach it over loopback or behind something that authenticates"
        }
    );
    println!();
    println!("  enrollment is a shared bootstrap secret: hand it to a host once, over a");
    println!("  channel you trust, and you get a unique host token back.");

    if args.generated_token {
        println!();
        println!("  this run's secret was generated, so it changes on every restart.");
        println!("  pass --enrollment-token (or CHAOS_ENROLLMENT_TOKEN) to keep it stable.");
    }

    println!("\n  to connect an agent on this machine:\n");
    println!(
        "    client --enroll http://{} --enrollment-token {} --token-file dev-host.token",
        args.bind, args.enrollment_token
    );
    // The agent reads this machine's ETW stream, so the second command needs an
    // elevated prompt. Saying so here rather than letting it fail with an
    // access-denied from the trace API is the difference between a five-second
    // fix and a bug report.
    println!(
        "    client --ship   http://{} --token-file dev-host.token --etw 60",
        args.bind
    );
    println!();
    println!("  run the second command from an ADMIN prompt: collecting ETW needs an");
    println!("  elevated token. Without --etw SECONDS it runs until you stop it.");
    println!();
    println!("  --token-file keeps the credential in the working directory; the default");
    println!("  location is machine-wide and may need elevation to write.");
    println!();
    println!(
        "  the console at http://{}/ is empty until a host enrols and ships data,",
        args.bind
    );
    println!("  which is the correct answer rather than a failure.");

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        println!("\nshutting down");
    };

    if let Err(e) = axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown)
        .await
    {
        eprintln!("fatal: server error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(bytes: &[u8]) -> Bytes {
        Bytes::from(protocol::gzip(bytes).expect("the test can compress"))
    }

    fn headers(content_encoding: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(encoding) = content_encoding {
            headers.insert("content-encoding", encoding.parse().unwrap());
        }
        headers
    }

    /// `Failure` carries no `Debug`, so the tests match rather than unwrap. Which
    /// is the right shape anyway: each of these asserts on *which* refusal.
    fn accepted(headers: &HeaderMap, body: Bytes) -> Vec<u8> {
        match inflated(headers, body) {
            Ok(body) => body.to_vec(),
            Err(_) => panic!("expected this body to be accepted"),
        }
    }

    fn refusal(headers: &HeaderMap, body: Bytes) -> StatusCode {
        match inflated(headers, body) {
            Ok(_) => panic!("expected this body to be refused"),
            Err(failure) => failure.status,
        }
    }

    /// The bug this function exists to prevent.
    ///
    /// The client compresses every body, enrollment included. When decompression
    /// lived inside `ingest`, enrolling returned `400 malformed_request` because
    /// gzip bytes are not JSON — a message that names nothing and points at the
    /// agent rather than the server. Both handlers now call this, and this test
    /// is what says the enrollment path inflates.
    #[test]
    fn a_gzipped_body_is_inflated_whatever_handler_reads_it() {
        let body = gzip(br#"{"hostname":"a-host"}"#);
        assert_ne!(&body[..1], b"{", "the fixture must really be compressed");

        let body = accepted(&headers(Some("gzip")), body);
        assert_eq!(&body[..], br#"{"hostname":"a-host"}"#);
    }

    #[test]
    fn an_uncompressed_body_passes_through() {
        let body = accepted(&headers(None), Bytes::from_static(b"{\"a\":1}"));
        assert_eq!(&body[..], b"{\"a\":1}");
    }

    #[test]
    fn an_encoding_we_do_not_implement_is_refused_rather_than_parsed_as_json() {
        // Fail closed: `br` is not `gzip`, and reading it as though the body were
        // plain would parse compressed bytes as JSON and report a malformed
        // request instead of an unsupported encoding.
        let status = refusal(&headers(Some("br")), Bytes::from_static(b"\x00\x01"));
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn a_body_that_claims_gzip_and_is_not_is_a_client_error() {
        let status = refusal(
            &headers(Some("gzip")),
            Bytes::from_static(b"not gzip at all"),
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// The decompression bomb guard, which is the reason the limit is checked
    /// while inflating rather than after.
    #[test]
    fn an_expanding_body_is_refused_at_the_limit() {
        // Highly compressible, so the wire body is tiny and the inflated one is
        // not — which is exactly the shape of the attack.
        let bomb = gzip(&vec![0u8; MAX_INFLATED_BYTES + 1024]);
        // Not a claim about deflate's best case, which is nearer 1000:1, only that
        // this body is far smaller on the wire than it inflates to — which is the
        // shape of the attack, whatever the ratio.
        assert!(
            bomb.len() * 64 < MAX_INFLATED_BYTES,
            "the fixture must be far smaller on the wire than it inflates to: {} bytes",
            bomb.len()
        );

        let status = refusal(&headers(Some("gzip")), bomb);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
