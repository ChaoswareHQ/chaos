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
mod store;

use auth::{EnrollmentAuthority, TokenVerifier};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use protocol::{
    API_VERSION, ApiError, ENROLL_PATH, ENROLLMENT_HEADER, EnrollRequest, EnrollResponse,
    HEALTH_PATH, HealthResponse, INGEST_PATH, IngestRequest, IngestResponse,
};
use std::net::SocketAddr;
use std::sync::Arc;
use store::{HostRecord, IncomingAlert, MemoryStore, Store};

/// Bodies larger than this are refused before they are read into memory.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
struct AppState {
    store: Arc<MemoryStore>,
    enrollment: Arc<EnrollmentAuthority>,
    verifier: Arc<TokenVerifier>,
    max_batch_events: usize,
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

    if !state.store.insert_host(record) {
        // A collision on a random 64-bit id. Retrying is the right answer.
        return Err(Failure::internal(
            "host_id_collision",
            "rng produced an id already in use",
        ));
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

    let outcome = state.store.record_ingest(
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
    Router::new()
        .route(HEALTH_PATH, get(health))
        .route(ENROLL_PATH, post(enroll))
        .route(INGEST_PATH, post(ingest))
        .route("/", get(console))
        .route("/static/app.css", get(stylesheet))
        .layer(middleware::from_fn(security_headers))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

struct Args {
    bind: SocketAddr,
    enrollment_token: String,
    generated_token: bool,
    max_hosts: usize,
    max_batch_events: usize,
}

fn parse_args() -> std::result::Result<Args, String> {
    let mut bind: SocketAddr = "127.0.0.1:8787".parse().expect("valid default");
    let mut token = std::env::var("CHAOS_ENROLLMENT_TOKEN").ok();
    let mut max_hosts = 500usize;
    let mut max_batch_events = protocol::MAX_BATCH_EVENTS;

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
    })
}

fn usage() -> String {
    "chaos ingest server\n\
     \n\
     usage: server [--bind ADDR] [--enrollment-token TOKEN] [--max-hosts N]\n\
     \x20              [--max-batch-events N] [--allow-cleartext]\n\
     \n\
     --bind                 default 127.0.0.1:8787\n\
     --enrollment-token     bootstrap secret; a random one is generated if omitted\n\
                            (env: CHAOS_ENROLLMENT_TOKEN)\n\
     --max-hosts            cap on enrolled hosts, default 500\n\
     --max-batch-events     per-batch event cap, default 5000\n\
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

    let state = AppState {
        store: Arc::new(MemoryStore::default()),
        enrollment: Arc::new(EnrollmentAuthority::new(
            &args.enrollment_token,
            args.max_hosts,
        )),
        verifier,
        max_batch_events: args.max_batch_events,
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
