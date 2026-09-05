// SPDX-License-Identifier: Unlicense

//! The `bmc` script module. Everything here reaches the one configured BMC and
//! nothing here lets a script choose which one, or what credential goes with it.

use std::collections::HashMap;

use axum::body::Bytes;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::{HeaderMap, HeaderValue, Method};
use rune::Module;
use url::Url;

use crate::http::{
    content_type, copy_end_to_end, is_hop_by_hop, is_json, is_redacted, json_content_type,
    rewrite_headers, rewrite_response,
};
use crate::rune_host::{Ids, request_ctx};
use crate::script_util::log_response;

/// Shared by `ScriptRequest` and `BmcResponse`, which parse bodies identically
/// and differ only in the noun their error message uses.
fn body_json(body: &[u8], what: &str) -> Result<rune::Value, String> {
    serde_json::from_slice(body).map_err(|error| format!("{what} body is not valid JSON: {error}"))
}

fn body_text(body: &[u8], what: &str) -> Result<String, String> {
    std::str::from_utf8(body)
        .map(str::to_string)
        .map_err(|error| format!("{what} body is not valid UTF-8: {error}"))
}

/// A response header a script may read. Credentials are hidden the same way
/// they are on the way in, though they still reach the caller on the wire.
fn readable_header(headers: &HeaderMap, name: &str) -> Option<String> {
    if is_redacted(name) {
        return None;
    }
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// A script supplies a path, never an authority. Otherwise a credential could
/// be aimed at a host the operator never configured.
fn require_absolute(path: &str) -> Result<(), String> {
    // `//host/path` is a path by the letter of it, and reqwest does keep the
    // configured authority, but it reads like an escape so it is refused.
    if path.starts_with('/') && !path.starts_with("//") {
        return Ok(());
    }
    Err(format!(
        "bmc::* requires an absolute path beginning with a single '/', got {path:?}"
    ))
}

/// Whether a script may set this header on a subrequest. Auth is Rust's to
/// decide, so a script can add to a request but never re-aim or re-credential it.
fn script_may_set(name: &str) -> bool {
    !is_redacted(name)
        && !is_hop_by_hop(name)
        && !name.eq_ignore_ascii_case("host")
        && !name.eq_ignore_ascii_case("content-length")
}

pub(crate) fn to_script_value(json: serde_json::Value) -> Result<rune::Value, String> {
    serde_json::from_value(json).map_err(|error| format!("building a script value: {error}"))
}

fn last_segment(id: &str) -> Option<String> {
    id.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
}

/// A member link as a path this proxy can fetch. Rewriting may already have
/// turned a relative `@odata.id` absolute, and only the path part is ours.
fn member_path(id: &str) -> Result<String, String> {
    if let Ok(url) = Url::parse(id) {
        return Ok(url.path().to_string());
    }
    if id.starts_with('/') {
        return Ok(id.to_string());
    }
    Err(format!(
        "member link {id:?} is neither an absolute URL nor a path"
    ))
}

/// The trailing segment of each `Members[].@odata.id`, which is the id itself.
fn member_ids(collection: &serde_json::Value) -> Vec<String> {
    let Some(members) = collection["Members"].as_array() else {
        return Vec::new();
    };
    members
        .iter()
        .filter_map(|member| member["@odata.id"].as_str().and_then(last_segment))
        .collect()
}

/// The value a handler receives, a plain `Send` type because `rune::Value` is
/// not and cannot cross `Vm::send_execute`. Carries no target and no credential.
#[derive(rune::Any)]
#[rune(item = ::bmc)]
pub struct ScriptRequest {
    #[rune(get)]
    pub(crate) method: String,
    #[rune(get)]
    pub(crate) path: String,
    #[rune(get)]
    pub(crate) query: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: Bytes,
}

impl ScriptRequest {
    fn json(&self) -> Result<rune::Value, String> {
        body_json(&self.body, "request")
    }

    fn text(&self) -> Result<String, String> {
        body_text(&self.body, "request")
    }

    fn header(&self, name: &str) -> Option<String> {
        self.headers.get(&name.to_ascii_lowercase()).cloned()
    }

    fn content_type(&self) -> Option<String> {
        self.header("content-type")
    }

    /// What the caller declared, not how we hold the body. A handler branches on
    /// this to decide which half of the exchange it wants to own.
    fn is_json(&self) -> bool {
        json_content_type(self.content_type().as_deref())
    }

    /// One query parameter, decoded. Redfish leans on `$expand`, `$select` and
    /// friends, and picking one out of the raw string by hand invites mistakes.
    fn query_param(&self, name: &str) -> Option<String> {
        let url = Url::parse(&format!("https://proxy/?{}", self.query)).ok()?;
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    }

    fn header_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.headers.keys().cloned().collect();
        names.sort();
        names
    }
}

/// A subrequest a script is assembling. It carries no target and no credential,
/// because `send_request` supplies both, which is what keeps a script steerless.
#[derive(rune::Any)]
#[rune(item = ::bmc)]
pub struct BmcRequest {
    method: String,
    path: String,
    // `Bytes` rather than `Vec<u8>`, since `bmc::inbound` seeds this from the
    // inbound body and a multi-GB firmware push must not be copied to do it.
    body: Option<Bytes>,
    content_type: Option<String>,
    headers: Vec<(String, String)>,
}

impl BmcRequest {
    // Owned for the same reason `json_encode` is, that Rune cannot marshal a
    // `&Value` into `Module::associated_function`.
    #[allow(clippy::needless_pass_by_value)]
    fn json(mut self, value: rune::Value) -> Result<Self, String> {
        self.body = Some(Bytes::from(
            serde_json::to_vec(&value)
                .map_err(|error| format!("body is not serialisable as JSON: {error}"))?,
        ));
        self.content_type.get_or_insert("application/json".into());
        Ok(self)
    }

    fn text(mut self, body: &str) -> Self {
        self.body = Some(Bytes::copy_from_slice(body.as_bytes()));
        self.content_type
            .get_or_insert("text/plain; charset=utf-8".into());
        self
    }

    /// The only way to send bytes that are not text, since Rune has no byte
    /// string a handler could otherwise hand over. Firmware images arrive here.
    fn base64(mut self, body: &str) -> Result<Self, String> {
        self.body =
            Some(Bytes::from(BASE64.decode(body.as_bytes()).map_err(
                |error| format!("body is not valid base64: {error}"),
            )?));
        self.content_type
            .get_or_insert("application/octet-stream".into());
        Ok(self)
    }

    fn content_type(mut self, value: &str) -> Self {
        self.content_type = Some(value.to_string());
        self
    }

    /// Retargets a request seeded from the inbound one, so a handler can relay a
    /// body it did not build to a path it chose.
    fn path(mut self, value: &str) -> Result<Self, String> {
        require_absolute(value)?;
        self.path = value.to_string();
        Ok(self)
    }

    fn header(mut self, name: &str, value: &str) -> Result<Self, String> {
        if !script_may_set(name) {
            return Err(format!(
                "a script may not set {name:?}, since auth and framing are the proxy's"
            ));
        }
        self.headers.push((name.to_string(), value.to_string()));
        Ok(self)
    }
}

/// A BMC response, as the BMC sent it. Nothing is rewritten on the way in, so a
/// handler that echoes a link must call `.rewrite()` before returning it.
#[derive(rune::Any)]
#[rune(item = ::bmc)]
pub struct BmcResponse {
    status: u16,
    headers: HeaderMap,
    body: Bytes,
}

impl BmcResponse {
    const fn status(&self) -> u16 {
        self.status
    }

    fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    fn json(&self) -> Result<rune::Value, String> {
        body_json(&self.body, "response")
    }

    fn text(&self) -> Result<String, String> {
        body_text(&self.body, "response")
    }

    fn header(&self, name: &str) -> Option<String> {
        readable_header(&self.headers, name)
    }

    fn content_type(&self) -> Option<String> {
        content_type(&self.headers).map(str::to_string)
    }

    fn is_json(&self) -> bool {
        is_json(&self.headers)
    }
}

/// What `bmc::forward` produced. Either the whole body, when it was JSON and
/// worth rewriting, or the live response for anything that has to stream.
pub(crate) enum ForwardedBody {
    Buffered(Bytes),
    Streaming(Box<reqwest::Response>),
}

/// The inbound request relayed upstream verbatim. A handler returns this to
/// pass a response through, which is what the proxy used to do in Rust.
#[derive(rune::Any)]
#[rune(item = ::bmc)]
pub struct Forwarded {
    pub(crate) status: u16,
    pub(crate) headers: HeaderMap,
    pub(crate) body: ForwardedBody,
}

impl Forwarded {
    const fn status(&self) -> u16 {
        self.status
    }

    fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    fn streaming(&self) -> bool {
        matches!(self.body, ForwardedBody::Streaming(_))
    }

    fn header(&self, name: &str) -> Option<String> {
        readable_header(&self.headers, name)
    }

    fn content_type(&self) -> Option<String> {
        content_type(&self.headers).map(str::to_string)
    }

    /// What the BMC declared, not how the body is held. The two agree today, and
    /// reading the header keeps the predicate about the peer rather than about us.
    fn is_json(&self) -> bool {
        is_json(&self.headers)
    }

    fn json(&self) -> Result<rune::Value, String> {
        match &self.body {
            ForwardedBody::Buffered(bytes) => body_json(bytes, "forwarded response"),
            ForwardedBody::Streaming(_) => {
                Err("a streaming response has no body to parse; call .buffer() first".into())
            }
        }
    }

    fn text(&self) -> Result<String, String> {
        match &self.body {
            ForwardedBody::Buffered(bytes) => body_text(bytes, "forwarded response"),
            ForwardedBody::Streaming(_) => {
                Err("a streaming response has no body to read; call .buffer() first".into())
            }
        }
    }

    /// Pulls a streaming body into memory so `.text()` and `.json()` work. Only
    /// a handler knows a body is finite, so this is never automatic.
    async fn buffer(mut self) -> Result<Self, String> {
        // On `text/event-stream` this waits on a body that never ends, and
        // nothing preempts it, since a script has no deadline.
        if let ForwardedBody::Streaming(response) = self.body {
            let bytes = response
                .bytes()
                .await
                .map_err(|error| format!("buffering the forwarded body failed: {error}"))?;
            self.body = ForwardedBody::Buffered(bytes);
        }
        Ok(self)
    }

    /// The canonical outbound record. Returns self, so a handler logs and
    /// returns in one expression.
    fn log(self, level: &str, with_body: bool) -> Result<Self, String> {
        let ctx = request_ctx("log")?;
        let body = match (&self.body, with_body) {
            // Never read a streaming body to log it, or SSE gets buffered.
            (ForwardedBody::Buffered(bytes), true) => Some(bytes.clone()),
            _ => None,
        };
        log_response(
            level,
            self.status,
            ctx.target,
            &self.headers,
            body.as_deref(),
        )?;
        Ok(self)
    }

    /// Swaps the BMC's authority for the proxy's. Nothing does this
    /// automatically, so a handler that skips it serves the BMC address.
    fn rewrite(mut self) -> Result<Self, String> {
        let ctx = request_ctx("rewrite")?;
        match &self.body {
            ForwardedBody::Buffered(bytes) => {
                if let Some(rewritten) =
                    rewrite_response(ctx.target, &ctx.base, &mut self.headers, bytes)?
                {
                    self.body = ForwardedBody::Buffered(Bytes::from(rewritten));
                }
            }
            // Nothing to rewrite in a body we never hold, but the headers that
            // carry a `Location` are still ours to fix.
            ForwardedBody::Streaming(_) => {
                rewrite_headers(ctx.target, &ctx.base, &mut self.headers);
            }
        }
        Ok(self)
    }
}

/// The Redfish-shaped body a caller gets when the BMC could not be reached.
fn gateway_failure(status: u16, message: &str) -> Forwarded {
    let body = serde_json::json!({
        "error": { "code": "Base.1.0.GeneralError", "message": message }
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Forwarded {
        status,
        headers,
        body: ForwardedBody::Buffered(Bytes::from(body.to_string())),
    }
}

/// Classifies a reply the way the whole proxy does. JSON is buffered so it can
/// be read and rewritten, and everything else streams, since SSE never ends.
async fn into_forwarded(response: reqwest::Response) -> Result<Forwarded, String> {
    let status = response.status().as_u16();
    let mut headers = HeaderMap::new();
    copy_end_to_end(response.headers(), &mut headers);

    let body = if is_json(&headers) {
        ForwardedBody::Buffered(
            response
                .bytes()
                .await
                .map_err(|error| format!("reading the forwarded body failed: {error}"))?,
        )
    } else {
        ForwardedBody::Streaming(Box::new(response))
    };

    Ok(Forwarded {
        status,
        headers,
        body,
    })
}

/// Relays the inbound request upstream, unchanged.
async fn forward() -> Result<Forwarded, String> {
    let ctx = request_ctx("bmc::forward")?;
    let uri = &ctx.parts.uri;
    let path = uri.path();
    let url = match uri.query() {
        Some(query) => format!("https://{}{path}?{query}", ctx.target),
        None => format!("https://{}{path}", ctx.target),
    };

    let mut headers = HeaderMap::new();
    copy_end_to_end(&ctx.parts.headers, &mut headers);

    let response = match ctx
        .state
        .client
        .request(ctx.parts.method.clone(), url)
        .headers(headers)
        .body(reqwest::Body::from(ctx.body.clone()))
        .send()
        .await
    {
        Ok(response) => response,
        // A transport failure is a response, not a script error. Flattening it
        // through `?` would lose the difference between 504 and 502.
        Err(error) => {
            tracing::warn!(target = %ctx.target, %error, "forwarding failed");
            let status = if error.is_timeout() { 504 } else { 502 };
            return Ok(gateway_failure(
                status,
                &format!("forwarding {path}: {error}"),
            ));
        }
    };

    into_forwarded(response).await
}

/// The one place a script's request reaches the network. Everything a script
/// can influence is applied here, and everything it cannot is applied after.
async fn dispatch(request: BmcRequest) -> Result<reqwest::Response, String> {
    let ctx = request_ctx("bmc::*")?;
    require_absolute(&request.path)?;
    let method: Method = request
        .method
        .parse()
        .map_err(|_| format!("{:?} is not an HTTP method", request.method))?;

    let path = request.path;
    let url = format!("https://{}{path}", ctx.target);

    // The script's own headers go on first, then the relayed credentials
    // overwrite them, so a handler cannot forge or replace what Rust sends.
    let mut headers = HeaderMap::new();
    for (name, value) in &request.headers {
        if !script_may_set(name) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            headers.append(name, value);
        }
    }
    for (name, value) in &ctx.relay_headers {
        headers.insert(name.clone(), value.clone());
    }

    // `insert`, since a request seeded from the inbound one already carries a
    // `Content-Type` and reqwest's builder appends rather than replaces.
    let body = request.body;
    if body.is_some() {
        let content_type = request
            .content_type
            .as_deref()
            .unwrap_or("application/json");
        if let Ok(value) = http::HeaderValue::from_str(content_type) {
            headers.insert(http::header::CONTENT_TYPE, value);
        }
    }

    let mut outbound = ctx.state.client.request(method, url).headers(headers);
    if let Some(body) = body {
        outbound = outbound.body(body);
    }

    outbound
        .send()
        .await
        .map_err(|error| format!("subrequest to {path} failed: {error}"))
}

/// A script-built request whose reply is read whole. The ergonomic path, since
/// a handler that built a request usually means to look at what came back.
async fn send_request(request: BmcRequest) -> Result<BmcResponse, String> {
    let response = dispatch(request).await?;

    let status = response.status();
    let mut headers = HeaderMap::new();
    copy_end_to_end(response.headers(), &mut headers);

    let body = response
        .bytes()
        .await
        .map_err(|error| format!("reading subrequest body failed: {error}"))?;

    Ok(BmcResponse {
        status: status.as_u16(),
        headers,
        body,
    })
}

/// A script-built request classified like a forwarded one, so a non-JSON reply
/// streams instead of being held. This is the returnable half of `.send()`.
async fn send_forwarded(request: BmcRequest) -> Result<Forwarded, String> {
    into_forwarded(dispatch(request).await?).await
}

/// The inbound request as something a script can modify, which is what makes
/// "relay this, but with a patched body" expressible.
fn inbound() -> Result<BmcRequest, String> {
    let ctx = request_ctx("bmc::inbound")?;
    let uri = &ctx.parts.uri;
    let path = match uri.query() {
        Some(query) => format!("{}?{query}", uri.path()),
        None => uri.path().to_string(),
    };

    // Filtered at seed time, so the type never holds a credential even briefly.
    // `dispatch` puts the real ones back, exactly as for any other request.
    let headers = ctx
        .parts
        .headers
        .iter()
        .filter(|(name, _)| script_may_set(name.as_str()))
        .filter_map(|(name, value)| {
            Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
        })
        .collect();

    Ok(BmcRequest {
        method: ctx.parts.method.as_str().to_string(),
        path,
        body: (!ctx.body.is_empty()).then(|| ctx.body.clone()),
        content_type: content_type(&ctx.parts.headers).map(str::to_string),
        headers,
    })
}

/// One BMC subrequest on behalf of a script. Takes its own permit, since a
/// whole-request one would deadlock a fan-out against itself.
async fn subrequest(
    method: Method,
    path: String,
    body: Option<Bytes>,
) -> Result<BmcResponse, String> {
    send_request(BmcRequest {
        method: method.to_string(),
        path,
        body,
        content_type: Some("application/json".to_string()),
        headers: Vec::new(),
    })
    .await
}

/// One internal GET whose body is parsed rather than handed to the script.
async fn get_json(path: &str) -> Result<serde_json::Value, String> {
    let response = subrequest(Method::GET, path.to_string(), None).await?;
    if !(200..300).contains(&response.status) {
        return Err(format!("GET {path} returned {}", response.status));
    }
    serde_json::from_slice(&response.body)
        .map_err(|error| format!("GET {path} body is not valid JSON: {error}"))
}

/// GETs a collection with `Members` inlined, asking the BMC to expand first and
/// fetching each member itself when the BMC ignored `$expand`.
async fn expand_collection(path: String) -> Result<rune::Value, String> {
    require_absolute(&path)?;
    let separator = if path.contains('?') { '&' } else { '?' };
    let mut collection = get_json(&format!("{path}{separator}$expand=.($levels=1)")).await?;

    let members = collection["Members"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // A shallow member carries nothing but `@odata.*` keys, so if every member
    // has more than that the BMC honoured the expand and there is no work.
    let expanded_already = members.iter().all(|member| {
        member
            .as_object()
            .is_some_and(|fields| fields.keys().any(|key| !key.starts_with("@odata.")))
    });
    if expanded_already {
        return to_script_value(collection);
    }

    let mut expanded = Vec::with_capacity(members.len());
    for member in members {
        let id = member["@odata.id"]
            .as_str()
            .ok_or_else(|| format!("{path}: a Members entry has no @odata.id"))?;
        expanded.push(get_json(&member_path(id)?).await?);
    }
    collection["Members"] = serde_json::Value::Array(expanded);
    to_script_value(collection)
}

/// Resolves the system and manager the way libredfish does, so a script ported
/// from there gets the same answers on the same hardware.
async fn resolve_ids() -> Result<Ids, String> {
    let ctx = request_ctx("bmc::system_id and bmc::manager_id")?;
    if let Ok(cached) = ctx.ids.lock()
        && let Some(ids) = cached.clone()
    {
        return Ok(ids);
    }

    let systems = member_ids(&get_json("/redfish/v1/Systems").await?);
    let preferred = systems
        .iter()
        .find(|id| *id == "System_0")
        .or_else(|| systems.first())
        .ok_or("no systems found under /redfish/v1/Systems")?
        .clone();

    // An auxiliary board can enumerate first, so the system carrying a `Bios`
    // wins. A failed fetch just means "not this one", since preferred stands.
    let mut found = None;
    let rest = systems.iter().filter(|id| **id != preferred);
    for id in std::iter::once(&preferred).chain(rest) {
        if let Ok(system) = get_json(&format!("/redfish/v1/Systems/{id}")).await
            && system.get("Bios").is_some()
        {
            found = Some((id.clone(), system));
            break;
        }
    }

    let managed_by = found.as_ref().and_then(|(_, system)| {
        let first = system["Links"]["ManagedBy"].as_array()?.first()?;
        first["@odata.id"].as_str().and_then(last_segment)
    });

    // Only walk the managers collection when the system named no manager,
    // which is one request fewer than resolving it up front as a fallback.
    let manager = match managed_by {
        Some(manager) => manager,
        None => member_ids(&get_json("/redfish/v1/Managers").await?)
            .into_iter()
            .next()
            .ok_or("no managers found under /redfish/v1/Managers")?,
    };

    let ids = Ids {
        system: found.map_or(preferred, |(id, _)| id),
        manager,
    };
    if let Ok(mut cache) = ctx.ids.lock() {
        *cache = Some(ids.clone());
    }
    Ok(ids)
}

/// `expand_collection` with the fallback a script otherwise writes itself,
/// since a BMC that serves no such collection 404s rather than returning empty.
async fn expand_or_empty(path: String, name: String) -> Result<rune::Value, String> {
    match expand_collection(path.clone()).await {
        Ok(collection) => Ok(collection),
        Err(_) => to_script_value(crate::script_util::empty_collection_json(&path, &name)),
    }
}

/// Pacing, for polling a Task or a Job. This is an await, so a caller hanging
/// up still cancels the handler, unlike the busy loop a script would write.
async fn sleep(millis: i64) -> Result<(), String> {
    let millis = u64::try_from(millis).map_err(|_| "bmc::sleep needs a positive delay")?;
    tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
    Ok(())
}

pub(crate) fn bmc_module() -> Result<Module, rune::ContextError> {
    let mut module = Module::with_crate("bmc")?;

    module.ty::<ScriptRequest>()?;
    module.associated_function("json", ScriptRequest::json)?;
    module.associated_function("text", ScriptRequest::text)?;
    module.associated_function("header", ScriptRequest::header)?;
    module.associated_function("header_names", ScriptRequest::header_names)?;
    module.associated_function("query_param", ScriptRequest::query_param)?;
    module.associated_function("content_type", ScriptRequest::content_type)?;
    module.associated_function("is_json", ScriptRequest::is_json)?;

    // The general form, for what the five verb helpers cannot express, being a
    // non-JSON body, an extra header, or a method such as HEAD.
    module.ty::<BmcRequest>()?;
    module.associated_function("json", BmcRequest::json)?;
    module.associated_function("text", BmcRequest::text)?;
    module.associated_function("base64", BmcRequest::base64)?;
    module.associated_function("content_type", BmcRequest::content_type)?;
    module.associated_function("path", BmcRequest::path)?;
    module.associated_function("header", BmcRequest::header)?;
    module.associated_function("send", send_request)?;
    module
        .function("request", |method: &str, path: &str| {
            require_absolute(path).map(|()| BmcRequest {
                method: method.to_ascii_uppercase(),
                path: path.to_string(),
                body: None,
                content_type: None,
                headers: Vec::new(),
            })
        })
        .build()?;

    module.ty::<Forwarded>()?;
    module.associated_function("status", Forwarded::status)?;
    module.associated_function("ok", Forwarded::ok)?;
    module.associated_function("streaming", Forwarded::streaming)?;
    module.associated_function("header", Forwarded::header)?;
    module.associated_function("content_type", Forwarded::content_type)?;
    module.associated_function("is_json", Forwarded::is_json)?;
    module.associated_function("json", Forwarded::json)?;
    module.associated_function("text", Forwarded::text)?;
    module.associated_function("buffer", Forwarded::buffer)?;
    module.associated_function("rewrite", Forwarded::rewrite)?;
    module.associated_function("log", Forwarded::log)?;
    module.function("forward", forward).build()?;
    // The other half of `forward`, for a request the script built rather than
    // the one that came in. Same classification, so a non-JSON reply streams.
    module.function("forward_with", send_forwarded).build()?;
    module.function("inbound", inbound).build()?;

    module.ty::<BmcResponse>()?;
    module.associated_function("status", BmcResponse::status)?;
    module.associated_function("ok", BmcResponse::ok)?;
    module.associated_function("json", BmcResponse::json)?;
    module.associated_function("text", BmcResponse::text)?;
    module.associated_function("header", BmcResponse::header)?;
    module.associated_function("content_type", BmcResponse::content_type)?;
    module.associated_function("is_json", BmcResponse::is_json)?;

    // Every path is borrowed, not taken. Rune moves an owned argument, so a
    // `String` here would make a script's second use of the same path fail.
    module
        .function("get", |path: &str| {
            subrequest(Method::GET, path.to_string(), None)
        })
        .build()?;
    module
        .function("expand_collection", |path: &str| {
            expand_collection(path.to_string())
        })
        .build()?;
    module
        .function("expand_or_empty", |path: &str, name: &str| {
            expand_or_empty(path.to_string(), name.to_string())
        })
        .build()?;
    module.function("sleep", sleep).build()?;
    module
        .function("system_id", || async {
            resolve_ids().await.map(|ids| ids.system)
        })
        .build()?;
    module
        .function("manager_id", || async {
            resolve_ids().await.map(|ids| ids.manager)
        })
        .build()?;
    // The target a script is pinned to, which it can read but never choose.
    module
        .function("address", || {
            request_ctx("bmc::address").map(|ctx| ctx.target.to_string())
        })
        .build()?;
    // The other side of `address`, being what the target is rewritten to, which
    // a script synthesising a link needs.
    module
        .function("external_base", || {
            request_ctx("bmc::external_base")
                .map(|ctx| ctx.base.as_str().trim_end_matches('/').to_string())
        })
        .build()?;
    // Rewriting has already made links absolute by the time a script reads one,
    // so following an `@odata.id` needs the path back out of it.
    module.function("path_of", member_path).build()?;
    module
        .function("delete", |path: &str| {
            subrequest(Method::DELETE, path.to_string(), None)
        })
        .build()?;
    for (name, method) in [
        ("post", Method::POST),
        ("patch", Method::PATCH),
        ("put", Method::PUT),
    ] {
        module
            .function(name, move |path: &str, body: rune::Value| {
                let method = method.clone();
                let path = path.to_string();
                async move {
                    let encoded = serde_json::to_vec(&body).map_err(|error| {
                        format!("request body is not serialisable as JSON: {error}")
                    })?;
                    subrequest(method, path, Some(Bytes::from(encoded))).await
                }
            })
            .build()?;
    }

    Ok(module)
}
