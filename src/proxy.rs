// SPDX-License-Identifier: Unlicense

//! Wiring and shared HTTP policy. Every request is handled by a Rune script,
//! but where it goes and what auth it carries is decided here, not in Rune.

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use url::Url;

use crate::config::{Config, Router, TargetConfig};

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("building the upstream client")]
    Build(#[from] reqwest::Error),
    #[error("reading target.ca_path {path}")]
    ReadCa {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("target.ca_path {path} holds no usable certificate")]
    ParseCa {
        path: std::path::PathBuf,
        #[source]
        source: Option<reqwest::Error>,
    },
    #[error(
        "target.accept_invalid_certs and target.ca_path contradict each other, so set \
         accept_invalid_certs = false to verify against the CA"
    )]
    ContradictoryTls,
}

/// Builds the client every request to the BMC goes through. Reads the config
/// rather than owning a copy, since `AppState` already holds it.
fn upstream_client(config: &TargetConfig) -> Result<reqwest::Client, UpstreamError> {
    // Silently ignoring the CA because verification is off is how an
    // operator concludes their certificates are being checked.
    if config.ca_path.is_some() && config.accept_invalid_certs {
        return Err(UpstreamError::ContradictoryTls);
    }

    let mut builder = reqwest::Client::builder()
        // BMC certificates are self-signed essentially universally.
        .danger_accept_invalid_certs(config.accept_invalid_certs)
        // One bound for the whole request. reqwest's total timeout already
        // covers connecting, so a separate connect timeout adds nothing.
        .timeout(config.timeout)
        // Never follow redirects. A streamed body cannot be replayed, and
        // chasing a `Location` would reach a host nobody configured.
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(4);

    if let Some(path) = &config.ca_path {
        let pem = std::fs::read(path).map_err(|source| UpstreamError::ReadCa {
            path: path.clone(),
            source,
        })?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|source| {
            UpstreamError::ParseCa {
                path: path.clone(),
                source: Some(source),
            }
        })?;
        // `from_pem_bundle` answers Ok with an empty list rather than erroring,
        // and dropping the public roots then leaves nothing at all to trust.
        if certs.is_empty() {
            return Err(UpstreamError::ParseCa {
                path: path.clone(),
                source: None,
            });
        }

        // Trust the site CA and nothing else. A BMC is never certified by a
        // public root, so keeping those would only widen what can vouch.
        builder = builder.tls_built_in_root_certs(false);
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }

    Ok(builder.build()?)
}

/// Everything a request handler needs.
pub struct AppState {
    pub config: Config,
    pub client: reqwest::Client,
    /// The proxy's externally visible base, which every link is rewritten to.
    pub external_base: Url,
    /// Which environment variables a script may read. `None` denies every one.
    pub env_allow: Option<regex::Regex>,
    pub routes: Router,
    pub scripts: crate::rune_host::ScriptStore,
    /// Whatever the scripts have kept between requests. Survives a script
    /// reload, since a reload swaps units and changes nothing a script decided.
    pub store: crate::script_store::Store,
}

pub type SharedState = Arc<AppState>;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error(transparent)]
    Route(#[from] crate::config::RouteError),
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
    #[error(transparent)]
    Rune(#[from] crate::rune_host::RuneError),
}

impl AppState {
    /// Builds everything a running proxy needs, failing on whatever an operator
    /// can fix before traffic arrives.
    pub fn build(config: Config) -> Result<SharedState, BuildError> {
        let routes = Router::build(&config.route)?;
        let env_allow = config.rune.env_matcher()?;
        let client = upstream_client(&config.target)?;
        let (script_dir, scripts) = crate::rune_host::load_for(&config)?;

        Ok(Arc::new(Self {
            external_base: config.rewrite.external_base_url.clone(),
            scripts: crate::rune_host::ScriptStore::new(script_dir, scripts),
            env_allow,
            client,
            routes,
            config,
            store: crate::script_store::Store::new(),
        }))
    }
}

/// Everything the forwarding path can refuse a request for. Rendered by
/// [`IntoResponse`], so handlers use `?` rather than a built error arm.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("reading the request body failed: {0}")]
    RequestBody(String),

    #[error("{message}")]
    Script { status: StatusCode, message: String },

    #[error("method {0} is not allowed on this path")]
    MethodNotAllowed(String),
}

impl ProxyError {
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::RequestBody(_) => StatusCode::BAD_REQUEST,
            Self::Script { status, .. } => *status,
            Self::MethodNotAllowed(_) => StatusCode::METHOD_NOT_ALLOWED,
        }
    }
}

impl IntoResponse for ProxyError {
    /// A Redfish-shaped body, so a Redfish client can parse the failure.
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": {
                "code": "Base.1.0.GeneralError",
                "message": self.to_string(),
            }
        });
        (self.status(), axum::Json(body)).into_response()
    }
}

/// Single entry point for every request that arrives on the listener.
pub async fn handle(
    State(state): State<SharedState>,
    request: axum::extract::Request,
) -> Result<Response, ProxyError> {
    let (parts, body) = request.into_parts();

    // Fixed at startup. Nothing a caller sends can point this elsewhere.
    let target = state.config.target.address;

    let base = &state.external_base;

    // Every body is buffered, whatever its size, so every request can reach a
    // script and every upstream request declares a length.
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|error| ProxyError::RequestBody(error.to_string()))?;

    // Every request is a script now. One that matches no route gets the
    // configured default, which is the pass-through this used to do in Rust.
    let script = match state.routes.resolve(&parts.method, parts.uri.path()) {
        Some(route) => route.script.as_path(),
        // A route claiming the path for other methods means the operator
        // restricted it, so relaying the write instead would invert the intent.
        None if state.routes.claims_path(parts.uri.path()) => {
            return Err(ProxyError::MethodNotAllowed(parts.method.to_string()));
        }
        None => state.config.rune.default_script.as_path(),
    };

    crate::rune_host::run_script(&state, target, base, script, parts, body).await
}

/// Builds the service every connection is served with. One fallback route,
/// since which paths a script handles is a config glob, not a compiled route.
pub fn router(state: SharedState) -> axum::Router {
    axum::Router::new().fallback(handle).with_state(state)
}
