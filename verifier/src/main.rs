//! Verifier web-service: issues nonces and verifies signed attestations.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
use crypto::{verify, PublicKeyBytes, SignatureBytes};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::RwLock};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

/// ── constants
const NONCE_TTL: Duration = Duration::from_secs(300); // every nonce valid for 5 min
const PK_LEN:  usize = std::mem::size_of::<PublicKeyBytes>();  // 32 byte pk
const SIG_LEN: usize = std::mem::size_of::<SignatureBytes>(); // 64 byte sig

/// shared state
#[derive(Clone)]
struct AppState {
    // UUID → expiry‐Instant
    nonces: Arc<RwLock<HashMap<Uuid, Instant>>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            nonces: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

/// JSON payloads 
#[derive(Serialize)]
struct NonceRes<'a> {
    nonce: &'a str,
    expires_at: String, // RFC-3339 timestamp
}

#[derive(Deserialize)]
struct AttestReq {
    nonce: String,
    public_key: String, // Base64
    signature: String,  // Base64
}

/// handlers 
async fn healthz() -> &'static str {
    "ok"
}

async fn issue_nonce(
    State(state): State<AppState>,
) -> Result<Json<NonceRes<'static>>, StatusCode> {
    // generate UUID + expiry
    let uuid = Uuid::new_v4();
    let exp_instant = Instant::now() + NONCE_TTL;

    // store in table
    state.nonces.write().await.insert(uuid, exp_instant);

    // human-readable expiry for the response
    let exp_ts = Utc::now() + ChronoDuration::from_std(NONCE_TTL).unwrap();

    let body = NonceRes {
        nonce: Box::leak(uuid.to_string().into_boxed_str()), // &'static str for Json
        expires_at: exp_ts.to_rfc3339_opts(SecondsFormat::Secs, true),
    };
    Ok(Json(body))
}

async fn attest(
    State(state): State<AppState>,
    Json(req): Json<AttestReq>,
) -> Result<StatusCode, StatusCode> {
    // parse & decode
    let nonce = Uuid::parse_str(&req.nonce).map_err(|_| StatusCode::BAD_REQUEST)?;

    let pk_vec  = STANDARD.decode(req.public_key).map_err(|_| StatusCode::BAD_REQUEST)?;
    let sig_vec = STANDARD.decode(req.signature ).map_err(|_| StatusCode::BAD_REQUEST)?;

    if pk_vec.len() != PK_LEN || sig_vec.len() != SIG_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }
    let pk:  &PublicKeyBytes  = pk_vec.as_slice().try_into().unwrap();
    let sig: &SignatureBytes  = sig_vec.as_slice().try_into().unwrap();

    // nonce lookup / expiry
    let mut table = state.nonces.write().await;
    let expiry = table.remove(&nonce).ok_or(StatusCode::BAD_REQUEST)?;
    if Instant::now() > expiry {
        return Err(StatusCode::GONE);
    }

    // cryptographic verification
    verify(pk, req.nonce.as_bytes(), sig).map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(StatusCode::NO_CONTENT)
}

///  run a background task that wakes every 30 s, removes expired nonces, and then goes back to sleep
fn spawn_janitor(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            let now = Instant::now();
            let mut map = state.nonces.write().await;
            map.retain(|_, &mut exp| exp > now);
        }
    });
}

/// main 
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = AppState::new();
    spawn_janitor(state.clone());

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/nonce",   post(issue_nonce))
        .route("/attest",  post(attest))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    tracing::info!("listening on http://{}", listener.local_addr()?);

    axum::serve(listener, app).await?;
    Ok(())
}