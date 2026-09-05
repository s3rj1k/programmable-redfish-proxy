// SPDX-License-Identifier: Unlicense

//! The Rune host. Script compilation and reload, the per-request context every
//! script helper reads, the `resp` module, and dispatch.

//! Rune is not a security boundary, so the invariants are structural.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use rune::runtime::RuntimeContext;
use rune::{Context, Diagnostics, Module, Source, Sources, Unit, Vm};
use url::Url;

use crate::http::{is_hop_by_hop, is_redacted, rewrite_response, script_forbidden_headers};
use crate::proxy::{self, SharedState};
use crate::script_bmc::{Forwarded, ForwardedBody, ScriptRequest, bmc_module};
use crate::script_store::store_module;
use crate::script_util::{log_module, log_response, util_module};

/// Every script exposes one handler by this name, since one script serves one
/// route. Nothing configurable, so nothing to get wrong.
const ENTRY: &str = "handle";

#[derive(Debug, thiserror::Error)]
pub enum RuneError {
    #[error("building the rune context")]
    Context(#[from] rune::ContextError),
    #[error("reading script directory {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("compiling scripts: {0}")]
    Compile(String),
}

/// The system and manager a script operates on. Resolved together because the
/// manager is read off whichever system turned out to carry a `Bios` resource.
#[derive(Clone)]
pub(crate) struct Ids {
    pub(crate) system: String,
    pub(crate) manager: String,
}

pub(crate) struct RequestCtx {
    pub(crate) state: SharedState,
    pub(crate) target: SocketAddrV4,
    /// Relayed verbatim to the BMC and never shown to the script.
    pub(crate) relay_headers: HeaderMap,
    pub(crate) base: Url,
    /// The inbound request, so `bmc::forward` can mirror it without taking an
    /// argument a script could substitute.
    pub(crate) parts: http::request::Parts,
    pub(crate) body: Bytes,
    /// Resolved on first use, since a script asking twice would otherwise walk
    /// the service root twice.
    pub(crate) ids: Mutex<Option<Ids>>,
}

tokio::task_local! {
    /// The linchpin of the security model. A script has no syntax that can name
    /// a task-local, so it cannot read, replace or forge what `bmc::*` reads.
    static REQUEST: Arc<RequestCtx>;
}

/// The per-request context, or an error saying why there is none.
pub(crate) fn request_ctx(what: &str) -> Result<Arc<RequestCtx>, String> {
    REQUEST
        .try_with(Arc::clone)
        .map_err(|_| format!("{what} is only callable from inside a request handler"))
}

/// Headers forwarded on a script's subrequests. A fixed set, since the script
/// controls the body and an inherited `Content-Length` would be a lie.
fn relay_headers(headers: &HeaderMap) -> HeaderMap {
    // No `accept`. It is content negotiation rather than a credential, and
    // relaying it would overwrite what a script asked its subrequest for.
    const RELAYED: &[&str] = &["authorization", "x-auth-token", "odata-version"];
    let mut out = HeaderMap::new();
    for name in RELAYED {
        for value in headers.get_all(*name) {
            if let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) {
                out.append(name, value.clone());
            }
        }
    }
    out
}

/// What a handler returns, being the response the caller will see.
#[derive(rune::Any)]
#[rune(item = ::resp)]
pub struct ScriptResponse {
    status: u16,
    content_type: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

impl ScriptResponse {
    fn with_header(mut self, name: String, value: String) -> Self {
        self.headers.push((name, value));
        self
    }

    /// As [`Forwarded::log`], for a response the handler built itself.
    fn log(self, level: &str, with_body: bool) -> Result<Self, String> {
        let ctx = request_ctx("log")?;
        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(&self.content_type) {
            headers.insert(http::header::CONTENT_TYPE, value);
        }
        let body = with_body.then_some(self.body.as_slice());
        log_response(level, self.status, ctx.target, &headers, body)?;
        Ok(self)
    }

    /// As [`Forwarded::rewrite`]. A handler that synthesises a link has to ask.
    fn rewrite(mut self) -> Result<Self, String> {
        let ctx = request_ctx("rewrite")?;

        // The script's own headers go through the same swap, so a `Location`
        // it set is fixed alongside the body.
        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(&self.content_type) {
            headers.insert(http::header::CONTENT_TYPE, value);
        }
        for (name, value) in &self.headers {
            if let (Ok(name), Ok(value)) = (
                http::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.append(name, value);
            }
        }

        if let Some(rewritten) = rewrite_response(ctx.target, &ctx.base, &mut headers, &self.body)?
        {
            self.body = rewritten;
        }

        self.headers = headers
            .iter()
            .filter(|(name, _)| *name != http::header::CONTENT_TYPE)
            .filter_map(|(name, value)| {
                Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
            })
            .collect();
        Ok(self)
    }
}

fn clamp_status(status: i64) -> u16 {
    u16::try_from(status)
        .ok()
        .filter(|code| (100..600).contains(code))
        .unwrap_or(500)
}

fn resp_module() -> Result<Module, rune::ContextError> {
    let mut module = Module::with_crate("resp")?;
    module.ty::<ScriptResponse>()?;
    module.associated_function("with_header", ScriptResponse::with_header)?;
    module.associated_function("rewrite", ScriptResponse::rewrite)?;
    module.associated_function("log", ScriptResponse::log)?;

    // Infallible on purpose. A fallible one returns a `Result`, making
    // `.with_header(..)` fail on the most obvious line a script can write.
    module
        .function(
            "json",
            |status: i64, value: rune::Value| match serde_json::to_vec(&value) {
                Ok(body) => ScriptResponse {
                    status: clamp_status(status),
                    content_type: "application/json".to_string(),
                    body,
                    headers: Vec::new(),
                },
                Err(error) => ScriptResponse {
                    status: 500,
                    content_type: "application/json".to_string(),
                    body: serde_json::to_vec(&serde_json::json!({
                        "error": {
                            "code": "Base.1.0.GeneralError",
                            "message": format!("script value is not serialisable as JSON: {error}"),
                        }
                    }))
                    .unwrap_or_else(|_| b"{}".to_vec()),
                    headers: Vec::new(),
                },
            },
        )
        .build()?;
    module
        .function("text", |status: i64, body: String| ScriptResponse {
            status: clamp_status(status),
            content_type: "text/plain; charset=utf-8".to_string(),
            body: body.into_bytes(),
            headers: Vec::new(),
        })
        .build()?;
    module
        .function("status", |status: i64| ScriptResponse {
            status: clamp_status(status),
            content_type: "application/json".to_string(),
            body: Vec::new(),
            headers: Vec::new(),
        })
        .build()?;

    Ok(module)
}

/// Compiled scripts plus their runtime, one `Unit` per file. Rune inserts every
/// source at `ItemId::ROOT`, so a shared unit would collide on `pub fn handle`.
pub struct Scripts {
    pub runtime: Arc<RuntimeContext>,
    units: HashMap<PathBuf, Arc<Unit>>,
}

impl Scripts {
    fn unit_for(&self, script: &Path) -> Option<Arc<Unit>> {
        self.units.get(script).map(Arc::clone)
    }

    /// Named `count` rather than `len`, since this is a keyed store of compiled
    /// units and not a collection anyone iterates.
    pub fn count(&self) -> usize {
        self.units.len()
    }
}

fn compile_one(context: &Context, name: &str, text: &str) -> Result<Unit, RuneError> {
    let mut set = Sources::new();
    let source = Source::new(name, text).map_err(|e| RuneError::Compile(format!("{name}: {e}")))?;
    set.insert(source)
        .map_err(|e| RuneError::Compile(format!("{name}: {e}")))?;

    let mut diagnostics = Diagnostics::new();
    let built = rune::prepare(&mut set)
        .with_context(context)
        .with_diagnostics(&mut diagnostics)
        .build();

    if !diagnostics.is_empty() {
        let mut buffer = rune::termcolor::Buffer::no_color();
        if diagnostics.emit(&mut buffer, &set).is_ok() {
            let rendered = String::from_utf8_lossy(buffer.as_slice()).to_string();
            if built.is_err() {
                return Err(RuneError::Compile(rendered));
            }
            tracing::warn!(script = name, diagnostics = %rendered, "rune compilation warnings");
        }
    }

    built.map_err(|e| RuneError::Compile(format!("{name}: {e}")))
}

/// Compiles named sources, one `Unit` each. The three script modules are
/// installed here, and per-request state reaches them through [`REQUEST`].
fn compile(sources: &[(PathBuf, String, String)]) -> Result<Scripts, RuneError> {
    let mut context = Context::with_default_modules()?;
    context.install(bmc_module()?)?;
    context.install(resp_module()?)?;
    context.install(util_module()?)?;
    context.install(log_module()?)?;
    context.install(store_module()?)?;

    let runtime = Arc::new(
        context
            .runtime()
            .map_err(|e| RuneError::Compile(format!("building runtime context: {e}")))?,
    );

    let mut units = HashMap::new();
    for (key, name, text) in sources {
        let unit = compile_one(&context, name, text)?;
        units.insert(key.clone(), Arc::new(unit));
    }

    Ok(Scripts { runtime, units })
}

/// Every `.rn` under `dir`, nested directories included, keyed by its path
/// relative to `dir` so a route names `supermicro/systems.rn` unambiguously.
fn collect_scripts(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(PathBuf, String, String)>,
) -> Result<(), RuneError> {
    let entries = std::fs::read_dir(dir).map_err(|source| RuneError::Read {
        path: dir.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| RuneError::Read {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_scripts(root, &path, out)?;
            continue;
        }
        if path.extension().is_some_and(|ext| ext == "rn") {
            let text = std::fs::read_to_string(&path).map_err(|source| RuneError::Read {
                path: path.clone(),
                source,
            })?;
            let key = path
                .strip_prefix(root)
                .map_or_else(|_| path.clone(), PathBuf::from);
            out.push((key, path.display().to_string(), text));
        }
    }
    Ok(())
}

/// Compiles every `.rn` file in `dir` into its own `Unit`.
fn compile_dir(dir: &Path) -> Result<Scripts, RuneError> {
    let mut sources = Vec::new();
    collect_scripts(dir, dir, &mut sources)?;
    compile(&sources)
}

/// Holds the live `Scripts` so SIGHUP can swap them under running requests. A
/// reload that fails to compile keeps the previous units.
pub struct ScriptStore {
    dir: Option<PathBuf>,
    current: arc_swap::ArcSwap<Scripts>,
}

impl ScriptStore {
    pub fn new(dir: Option<PathBuf>, scripts: Scripts) -> Self {
        Self {
            dir,
            current: arc_swap::ArcSwap::from_pointee(scripts),
        }
    }

    /// Cheap per-request snapshot, lock-free, so there is no guard to hold
    /// across an await and no poisoning to recover from.
    pub fn current(&self) -> Arc<Scripts> {
        self.current.load_full()
    }

    /// Recompiles from disk. On failure the previous units keep serving.
    pub fn reload(&self) {
        let Some(dir) = &self.dir else {
            tracing::info!("no rune.script_dir configured; nothing to reload");
            return;
        };
        match compile_dir(dir) {
            Ok(scripts) => {
                let count = scripts.count();
                self.current.store(Arc::new(scripts));
                tracing::info!(scripts = count, dir = %dir.display(), "reloaded rune scripts");
            }
            Err(error) => {
                tracing::error!(%error, "reload failed; keeping the previously compiled scripts");
            }
        }
    }
}

/// Compiles the script directory, which must exist, since a request that
/// matches no route still needs `rune.default_script` to handle it.
pub fn load_for(config: &crate::config::Config) -> Result<(Option<PathBuf>, Scripts), RuneError> {
    let dir = &config.rune.script_dir;

    if !dir.is_dir() {
        return Err(RuneError::Compile(format!(
            "rune.script_dir {} does not exist, and every request needs a script",
            dir.display()
        )));
    }

    let scripts = compile_dir(dir)?;
    if scripts.unit_for(&config.rune.default_script).is_none() {
        return Err(RuneError::Compile(format!(
            "rune.default_script names {}, which was not found in {}",
            config.rune.default_script.display(),
            dir.display()
        )));
    }
    for route in &config.route {
        if scripts.unit_for(&route.script).is_none() {
            return Err(RuneError::Compile(format!(
                "route {:?} names script {}, which was not found in {}",
                route.path,
                route.script.display(),
                dir.display()
            )));
        }
    }

    Ok((Some(dir.clone()), scripts))
}

struct Failure {
    status: StatusCode,
    message: String,
}

impl Failure {
    fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: message.into(),
        }
    }
}

/// The two shapes a handler may end with, a response it built or one it
/// forwarded. The second can still be streaming, which is why they differ.
enum Returned {
    Script(ScriptResponse),
    Forwarded(Forwarded),
}

fn render(value: &rune::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unrenderable value>".to_string())
}

/// Builds the value the script receives, with every credential header removed.
fn script_request(parts: &http::request::Parts, body: &Bytes) -> ScriptRequest {
    let headers = parts
        .headers
        .iter()
        .filter(|(name, _)| !is_redacted(name.as_str()))
        .filter_map(|(name, value)| {
            Some((
                name.as_str().to_ascii_lowercase(),
                value.to_str().ok()?.to_string(),
            ))
        })
        .collect();

    ScriptRequest {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().unwrap_or_default().to_string(),
        headers,
        body: body.clone(),
    }
}

/// Accepts either shape a handler can end with, a bare `resp::*` value or a
/// `Result` carrying one.
fn returned(value: rune::Value) -> Result<Returned, Failure> {
    use rune::runtime::TypeHash as _;

    // Unwrap a top-level `Result` first. `from_value` on an `Any` type *takes*
    // the value even when it fails, so a guessed conversion poisons the next.
    let value = match rune::from_value::<Result<rune::Value, rune::Value>>(value.clone()) {
        Ok(Ok(inner)) => inner,
        Ok(Err(error)) => {
            return Err(Failure::bad_gateway(format!(
                "handler returned an error: {}",
                render(&error)
            )));
        }
        Err(_) => value,
    };

    // Then dispatch on the type hash rather than by trying each conversion,
    // for the same reason.
    let hash = value.type_hash();
    if hash == ScriptResponse::HASH {
        return rune::from_value::<ScriptResponse>(value)
            .map(Returned::Script)
            .map_err(|error| Failure::bad_gateway(format!("reading the response: {error}")));
    }
    if hash == Forwarded::HASH {
        return rune::from_value::<Forwarded>(value)
            .map(Returned::Forwarded)
            .map_err(|error| Failure::bad_gateway(format!("reading the response: {error}")));
    }
    Err(Failure::bad_gateway(
        "handler must return a resp::* or bmc::forward value, got something else".to_string(),
    ))
}

/// Turns a forwarded response into the caller's. A streaming body is handed
/// straight through, so `text/event-stream` is never held.
fn finish_forwarded(forwarded: Forwarded) -> Response<Body> {
    let status =
        StatusCode::from_u16(forwarded.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut headers = forwarded.headers;

    let body = match forwarded.body {
        ForwardedBody::Buffered(bytes) => {
            // The rewrite changed the length, so the inherited one is a lie.
            headers.remove(http::header::CONTENT_LENGTH);
            headers.insert(http::header::CONTENT_LENGTH, bytes.len().into());
            Body::from(bytes)
        }
        ForwardedBody::Streaming(response) => Body::from_stream(response.bytes_stream()),
    };

    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

fn finish_script_response(script: ScriptResponse) -> Response<Body> {
    let status = StatusCode::from_u16(script.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut headers = HeaderMap::new();
    if let Ok(value) = http::HeaderValue::from_str(&script.content_type) {
        headers.insert(http::header::CONTENT_TYPE, value);
    }

    let forbidden = script_forbidden_headers();
    for (name, value) in script.headers {
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        // Rune decides content, never auth. Setting these would forge a
        // credential onward or leak one back.
        if forbidden.contains(&name) || is_hop_by_hop(name.as_str()) {
            tracing::warn!(header = %name, "script tried to set a forbidden header; dropped");
            continue;
        }
        if let Ok(value) = http::HeaderValue::from_str(&value) {
            headers.append(name, value);
        }
    }

    let body = script.body;

    headers.insert(http::header::CONTENT_LENGTH, body.len().into());

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

async fn execute(
    state: &SharedState,
    target: SocketAddrV4,
    base: &Url,
    script: &Path,
    parts: http::request::Parts,
    body: Bytes,
) -> Result<Response<Body>, Failure> {
    let scripts = state.scripts.current();
    let unit = scripts.unit_for(script).ok_or_else(|| {
        Failure::bad_gateway(format!("no compiled script named {}", script.display()))
    })?;

    let request = script_request(&parts, &body);

    let ctx = Arc::new(RequestCtx {
        state: Arc::clone(state),
        target,
        relay_headers: relay_headers(&parts.headers),
        base: base.clone(),
        parts,
        body,
        ids: Mutex::new(None),
    });

    let vm = Vm::new(Arc::clone(&scripts.runtime), unit);
    let execution = vm
        .send_execute([ENTRY], (request,))
        .map_err(|error| Failure::bad_gateway(format!("calling {ENTRY}: {error}")))?;

    // A handler runs for as long as it runs. What bounds it is `target.timeout`
    // on each `bmc::*` call, and the caller hanging up, which drops this future.
    let completed = REQUEST.scope(ctx, execution.async_complete()).await;

    let value = completed
        .into_result()
        .map_err(|error| Failure::bad_gateway(format!("script execution failed: {error}")))?;

    match returned(value)? {
        Returned::Script(script) => Ok(finish_script_response(script)),
        Returned::Forwarded(forwarded) => Ok(finish_forwarded(forwarded)),
    }
}

/// Runs the Rune handler registered for this route.
pub async fn run_script(
    state: &SharedState,
    target: SocketAddrV4,
    base: &Url,
    script: &Path,
    parts: http::request::Parts,
    body: Bytes,
) -> Result<Response<Body>, proxy::ProxyError> {
    match execute(state, target, base, script, parts, body).await {
        Ok(response) => Ok(response),
        Err(failure) => {
            tracing::warn!(
                script = %script.display(),
                error = %failure.message,
                "rune handler failed",
            );
            // Never fall through to a direct proxy, which would return
            // unmangled data with a 200 and hide that the script failed.
            Err(proxy::ProxyError::Script {
                status: failure.status,
                message: failure.message,
            })
        }
    }
}
