// SPDX-License-Identifier: Unlicense

//! The `util` and `log` script modules, being everything a handler can call
//! that does not touch the BMC.

use std::net::SocketAddrV4;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::HeaderMap;
use rune::Module;

use crate::http::{redact_headers, render_body, rewrite_text, rewrite_value};
use crate::rune_host::request_ctx;
use crate::script_bmc::to_script_value;

/// Emits at a level named at runtime. `tracing` resolves a level at compile
/// time, so a dynamic one is a match rather than a parameter.
macro_rules! emit {
    ($level:expr, $($arg:tt)*) => {
        match $level {
            "trace" => { tracing::trace!($($arg)*); Ok(()) }
            "debug" => { tracing::debug!($($arg)*); Ok(()) }
            "info" => { tracing::info!($($arg)*); Ok(()) }
            "warn" => { tracing::warn!($($arg)*); Ok(()) }
            "error" => { tracing::error!($($arg)*); Ok(()) }
            other => Err(format!(
                "{other:?} is not a level; use trace, debug, info, warn or error"
            )),
        }
    };
}

/// Structured output. Field *names* are compile time in `tracing` too, so the
/// object is rendered into one `fields` value rather than into separate keys.
#[allow(clippy::needless_pass_by_value)]
fn event(level: &str, message: &str, fields: rune::Value) -> Result<(), String> {
    let rendered = serde_json::to_string(&fields)
        .map_err(|error| format!("log::event fields are not serialisable: {error}"))?;
    emit!(level, source = "script", fields = %rendered, "{message}")
}

/// The inbound request, with credentials redacted and the body clipped. A
/// script decides whether to call this, never how to redact.
fn log_request(level: &str, with_body: bool) -> Result<(), String> {
    let ctx = request_ctx("log::request")?;
    let body = with_body.then(|| render_body(&ctx.body)).flatten();
    emit!(
        level,
        method = %ctx.parts.method,
        path = ctx.parts.uri.path(),
        target = %ctx.target,
        headers = ?redact_headers(&ctx.parts.headers),
        body = ?body,
        "request"
    )
}

/// The outbound record, shared by both response shapes.
pub(crate) fn log_response(
    level: &str,
    status: u16,
    target: SocketAddrV4,
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Result<(), String> {
    let body = body.and_then(render_body);
    emit!(
        level,
        status = status,
        target = %target,
        headers = ?redact_headers(headers),
        body = ?body,
        "response"
    )
}

pub(crate) fn log_module() -> Result<Module, rune::ContextError> {
    let mut module = Module::with_crate("log")?;

    for name in ["trace", "debug", "info", "warn", "error"] {
        module
            .function(name, move |message: &str| {
                let _ = emit!(name, source = "script", "{message}");
            })
            .build()?;
    }

    module
        .function("at", |level: &str, message: &str| {
            emit!(level, source = "script", "{message}")
        })
        .build()?;
    module.function("event", event).build()?;
    module.function("request", log_request).build()?;

    Ok(module)
}

fn hex(digest: ring::digest::Digest) -> String {
    use std::fmt::Write as _;
    digest.as_ref().iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn b64_decode(data: &str) -> Result<String, String> {
    let bytes = BASE64
        .decode(data.as_bytes())
        .map_err(|error| format!("b64_decode: {error}"))?;
    String::from_utf8(bytes).map_err(|error| format!("b64_decode: not valid UTF-8: {error}"))
}

// Owned deliberately. Rune has no marshalling for `&Value`, so a borrow here
// fails to satisfy `Module::function` however unused the ownership looks.
#[allow(clippy::needless_pass_by_value)]
fn json_encode(value: rune::Value) -> Result<String, String> {
    serde_json::to_string(&value).map_err(|error| format!("json_encode: {error}"))
}

fn json_decode(text: &str) -> Result<rune::Value, String> {
    serde_json::from_str(text).map_err(|error| format!("json_decode: {error}"))
}

fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The one place a script reaches the filesystem, so the containment check is
/// written once and both readers inherit it.
fn read_script_json(what: &str, name: &str) -> Result<serde_json::Value, String> {
    let ctx = request_ctx(what)?;
    let dir = &ctx.state.config.rune.script_dir;

    let root = dir
        .canonicalize()
        .map_err(|error| format!("resolving rune.script_dir {}: {error}", dir.display()))?;

    // Canonicalising the joined path is what makes `..`, an absolute name and a
    // symlink pointing out of the directory all fail, rather than just `..`.
    let path = root
        .join(name)
        .canonicalize()
        .map_err(|error| format!("resolving {name:?} under {}: {error}", root.display()))?;

    if !path.starts_with(&root) {
        return Err(format!(
            "{name:?} resolves to {}, outside rune.script_dir {}",
            path.display(),
            root.display()
        ));
    }
    if !path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        return Err(format!("{name:?} is not a .json file"));
    }

    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("reading {}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("{name:?} is not valid JSON: {error}"))
}

/// Reads a JSON document from the script directory, which is how a script gets
/// a lookup table without the operator growing a config key for it.
fn read_json_file(name: &str) -> Result<rune::Value, String> {
    to_script_value(read_script_json("util::read_json_file", name)?)
}

/// Reads an environment variable the operator allowed. Unset `rune.env_allow`
/// denies every name, so this is closed until a deployment opens it.
fn read_env(name: &str) -> Result<Option<String>, String> {
    let ctx = request_ctx("util::read_env")?;
    let Some(allowed) = &ctx.state.env_allow else {
        return Err(format!(
            "util::read_env({name:?}) is denied because rune.env_allow is unset"
        ));
    };
    if !allowed.is_match(name) {
        return Err(format!(
            "util::read_env({name:?}) is denied by rune.env_allow"
        ));
    }
    Ok(std::env::var(name).ok())
}

/// Swaps the BMC's authority for the proxy's inside any JSON value, for a
/// handler assembling a body rather than forwarding one.
#[allow(clippy::needless_pass_by_value)]
fn rewrite_links(value: rune::Value) -> Result<rune::Value, String> {
    let ctx = request_ctx("util::rewrite_links")?;
    let mut json: serde_json::Value =
        serde_json::to_value(&value).map_err(|error| format!("rewrite_links: {error}"))?;
    rewrite_value(ctx.target, &ctx.base, &mut json);
    to_script_value(json)
}

/// The same swap on a plain string, which is the only way to fix a buffered
/// body that is textual but not JSON, such as the XML `$metadata` document.
fn rewrite_links_text(text: &str) -> Result<String, String> {
    let ctx = request_ctx("util::rewrite_links_text")?;
    Ok(rewrite_text(ctx.target, &ctx.base, text))
}

/// Walks a slash separated path such as `Links/ManagedBy/0/@odata.id`, where a
/// numeric segment indexes an array. Slash, since Redfish keys contain dots.
fn walk<'a>(mut node: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    for segment in path.split('/') {
        node = match node {
            serde_json::Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            other => other.get(segment)?,
        };
    }
    Some(node)
}

/// A deep read that answers `None` rather than failing the request, which is
/// what indexing does when a key is absent.
#[allow(clippy::needless_pass_by_value)]
fn at(value: rune::Value, path: &str) -> Result<Option<rune::Value>, String> {
    let json: serde_json::Value =
        serde_json::to_value(&value).map_err(|error| format!("util::at: {error}"))?;
    walk(&json, path)
        .cloned()
        .map_or(Ok(None), |found| to_script_value(found).map(Some))
}

/// A deep write that creates the objects along the way, since Rune's index-set
/// does not. Returns the value, because Rune cannot marshal a `&mut`.
#[allow(clippy::needless_pass_by_value)]
fn set(value: rune::Value, path: &str, new: rune::Value) -> Result<rune::Value, String> {
    let mut json: serde_json::Value =
        serde_json::to_value(&value).map_err(|error| format!("util::set: {error}"))?;
    let new: serde_json::Value =
        serde_json::to_value(&new).map_err(|error| format!("util::set: {error}"))?;

    // `split` always yields at least one segment, so the empty path has to be
    // refused here or it silently writes a key named "".
    if path.is_empty() {
        return Err("util::set needs a path".to_string());
    }
    let segments: Vec<&str> = path.split('/').collect();
    let Some((last, parents)) = segments.split_last() else {
        return Err("util::set needs a path".to_string());
    };

    let mut node = &mut json;
    for segment in parents {
        if let Ok(index) = segment.parse::<usize>()
            && node.is_array()
        {
            node = node
                .get_mut(index)
                .ok_or_else(|| format!("util::set: {path} indexes past the end of an array"))?;
            continue;
        }
        if !node.is_object() {
            *node = serde_json::Value::Object(serde_json::Map::new());
        }
        node = node
            .as_object_mut()
            .and_then(|map| {
                map.entry((*segment).to_string())
                    .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                map.get_mut(*segment)
            })
            .ok_or_else(|| format!("util::set: {path} is not reachable"))?;
    }

    if let Ok(index) = last.parse::<usize>()
        && let Some(slot) = node.get_mut(index)
    {
        *slot = new;
    } else {
        if !node.is_object() {
            *node = serde_json::Value::Object(serde_json::Map::new());
        }
        node.as_object_mut()
            .ok_or_else(|| format!("util::set: {path} is not reachable"))?
            .insert((*last).to_string(), new);
    }
    to_script_value(json)
}

/// Rune's `Vec` has no `contains`, so every script that needs one writes a loop.
#[allow(clippy::needless_pass_by_value)]
fn contains(list: rune::Value, wanted: rune::Value) -> Result<bool, String> {
    let list: serde_json::Value =
        serde_json::to_value(&list).map_err(|error| format!("util::contains: {error}"))?;
    let wanted: serde_json::Value =
        serde_json::to_value(&wanted).map_err(|error| format!("util::contains: {error}"))?;
    Ok(list.as_array().is_some_and(|items| items.contains(&wanted)))
}

/// RFC 7386 merge-patch, which is the semantics a Redfish PATCH body carries. A
/// `null` in the patch deletes the key rather than setting it to null.
fn merge_json(target: &mut serde_json::Value, patch: serde_json::Value) {
    let serde_json::Value::Object(patch) = patch else {
        *target = patch;
        return;
    };
    if !target.is_object() {
        *target = serde_json::Value::Object(serde_json::Map::new());
    }
    let map = target.as_object_mut().expect("just made it an object");
    for (key, value) in patch {
        if value.is_null() {
            map.remove(&key);
        } else {
            merge_json(map.entry(key).or_insert(serde_json::Value::Null), value);
        }
    }
}

/// RFC 7386 merge-patch. Named for the RFC so it cannot be confused with
/// `json_patch`, which is the other one and behaves very differently.
#[allow(clippy::needless_pass_by_value)]
fn json_merge_patch(target: rune::Value, patch: rune::Value) -> Result<rune::Value, String> {
    let mut target: serde_json::Value = serde_json::to_value(&target)
        .map_err(|error| format!("util::json_merge_patch: {error}"))?;
    let patch: serde_json::Value =
        serde_json::to_value(&patch).map_err(|error| format!("util::json_merge_patch: {error}"))?;
    merge_json(&mut target, patch);
    to_script_value(target)
}

/// How many operations one patch may carry. Fixed rather than configurable,
/// because a patch longer than this is generated by a bug, not by an operator.
const MAX_PATCH_OPS: usize = 1024;

/// Largest subtree a copy will duplicate, counted in nodes. Copying the root
/// doubles the document each time, so an op cap alone bounds nothing.
const MAX_COPY_NODES: usize = 64 * 1024;

/// Splits an RFC 6901 pointer into its unescaped tokens. The empty pointer
/// addresses the whole document, so it yields no tokens at all.
fn pointer_tokens(pointer: &str) -> Result<Vec<String>, String> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let Some(rest) = pointer.strip_prefix('/') else {
        return Err(format!(
            "{pointer:?} is not a pointer, which starts with a slash"
        ));
    };

    // `~1` before `~0`, or a literal `~01` would come back out as a slash.
    Ok(rest
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect())
}

/// An array token, which RFC 6901 writes as digits with no leading zero. `-`
/// names one past the end, which only an `add` is allowed to use.
fn array_index(token: &str, len: usize, allow_end: bool) -> Result<usize, String> {
    if token == "-" {
        if allow_end {
            return Ok(len);
        }
        return Err("\"-\" names one past the end, which only add may use".to_string());
    }
    let digits = !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_digit());
    if !digits || (token.len() > 1 && token.starts_with('0')) {
        return Err(format!("{token:?} is not an array index"));
    }
    token
        .parse()
        .map_err(|_| format!("{token:?} is not an array index"))
}

/// Walks tokens to the value they address. Absent rather than created, since
/// every operation but `add` requires the location to be there already.
fn resolve<'a>(root: &'a serde_json::Value, tokens: &[String]) -> Option<&'a serde_json::Value> {
    let mut node = root;
    for token in tokens {
        node = match node {
            serde_json::Value::Array(items) => {
                items.get(array_index(token, items.len(), false).ok()?)?
            }
            serde_json::Value::Object(map) => map.get(token.as_str())?,
            _ => return None,
        };
    }
    Some(node)
}

fn resolve_mut<'a>(
    root: &'a mut serde_json::Value,
    tokens: &[String],
) -> Option<&'a mut serde_json::Value> {
    let mut node = root;
    for token in tokens {
        node = match node {
            serde_json::Value::Array(items) => {
                let index = array_index(token, items.len(), false).ok()?;
                items.get_mut(index)?
            }
            serde_json::Value::Object(map) => map.get_mut(token.as_str())?,
            _ => return None,
        };
    }
    Some(node)
}

/// The one people get wrong. Against an object key this replaces, against an
/// array index it inserts and shifts, and `-` appends.
fn patch_add(
    root: &mut serde_json::Value,
    tokens: &[String],
    value: serde_json::Value,
) -> Result<(), String> {
    let Some((last, parents)) = tokens.split_last() else {
        *root = value;
        return Ok(());
    };
    let parent = resolve_mut(root, parents).ok_or("the parent does not exist")?;
    match parent {
        serde_json::Value::Array(items) => {
            let index = array_index(last, items.len(), true)?;
            if index > items.len() {
                return Err(format!(
                    "{index} is past the end of an array of {}",
                    items.len()
                ));
            }
            items.insert(index, value);
        }
        serde_json::Value::Object(map) => {
            map.insert(last.clone(), value);
        }
        _ => return Err("the parent is neither an object nor an array".to_string()),
    }
    Ok(())
}

/// Removing what is not there fails, unlike a merge-patch null. The removed
/// value comes back so `move` can put it down again.
fn patch_remove(
    root: &mut serde_json::Value,
    tokens: &[String],
) -> Result<serde_json::Value, String> {
    let Some((last, parents)) = tokens.split_last() else {
        return Err("the whole document cannot be removed".to_string());
    };
    let parent = resolve_mut(root, parents).ok_or("the parent does not exist")?;
    match parent {
        serde_json::Value::Array(items) => {
            let index = array_index(last, items.len(), false)?;
            if index >= items.len() {
                return Err(format!(
                    "{index} is past the end of an array of {}",
                    items.len()
                ));
            }
            Ok(items.remove(index))
        }
        serde_json::Value::Object(map) => map
            .remove(last.as_str())
            .ok_or_else(|| format!("{last:?} is not there to remove")),
        _ => Err("the parent is neither an object nor an array".to_string()),
    }
}

/// Nodes in a subtree, which is what a copy is charged for. Counted rather than
/// encoded, since the cost that matters is what the clone allocates.
fn nodes(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(items) => 1 + items.iter().map(nodes).sum::<usize>(),
        serde_json::Value::Object(map) => 1 + map.values().map(nodes).sum::<usize>(),
        _ => 1,
    }
}

fn patch_move(root: &mut serde_json::Value, from: &[String], to: &[String]) -> Result<(), String> {
    // Moving a location inside itself would need the value to contain itself.
    if to.len() > from.len() && to[..from.len()] == *from {
        return Err("a location cannot move into its own descendant".to_string());
    }
    let value = patch_remove(root, from)?;
    patch_add(root, to, value)
}

/// The required string field of an operation, already parsed into tokens.
fn pointer_field(
    op: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Vec<String>, String> {
    match op.get(key) {
        Some(serde_json::Value::String(text)) => pointer_tokens(text),
        Some(_) => Err(format!("{key} is not a string")),
        None => Err(format!("{key} is missing")),
    }
}

/// RFC 6902 wants the key present and null is a legal value, so this asks
/// whether the key is there rather than whether it is null.
fn value_field(
    op: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<serde_json::Value, String> {
    op.remove("value")
        .ok_or_else(|| "value is missing".to_string())
}

fn apply_one(target: &mut serde_json::Value, op: serde_json::Value) -> Result<(), String> {
    let serde_json::Value::Object(mut op) = op else {
        return Err("the operation is not an object".to_string());
    };
    let name = match op.get("op") {
        Some(serde_json::Value::String(name)) => name.clone(),
        Some(_) => return Err("op is not a string".to_string()),
        None => return Err("op is missing".to_string()),
    };
    let path = pointer_field(&op, "path")?;

    match name.as_str() {
        "add" => {
            let value = value_field(&mut op)?;
            patch_add(target, &path, value)
        }
        "remove" => patch_remove(target, &path).map(|_| ()),
        "replace" => {
            let value = value_field(&mut op)?;
            let slot = resolve_mut(target, &path).ok_or("the location does not exist")?;
            *slot = value;
            Ok(())
        }
        "move" => {
            let from = pointer_field(&op, "from")?;
            patch_move(target, &from, &path)
        }
        "copy" => {
            let from = pointer_field(&op, "from")?;
            let source = resolve(target, &from).ok_or("the source does not exist")?;
            let size = nodes(source);
            if size > MAX_COPY_NODES {
                return Err(format!(
                    "the source is {size} nodes, over the {MAX_COPY_NODES} node limit"
                ));
            }
            let value = source.clone();
            patch_add(target, &path, value)
        }
        "test" => {
            let value = value_field(&mut op)?;
            let found = resolve(target, &path).ok_or("the location does not exist")?;
            // The located value stays out of the message, which reaches a log
            // and a 502 body that this proxy otherwise redacts.
            if *found == value {
                Ok(())
            } else {
                Err("the location does not hold the tested value".to_string())
            }
        }
        other => Err(format!("{other:?} is not an operation")),
    }
}

fn apply_patch(target: &mut serde_json::Value, ops: serde_json::Value) -> Result<(), String> {
    let serde_json::Value::Array(ops) = ops else {
        return Err("the patch is not an array of operations".to_string());
    };
    if ops.len() > MAX_PATCH_OPS {
        return Err(format!(
            "the patch has {} operations, over the {MAX_PATCH_OPS} limit",
            ops.len()
        ));
    }
    for (index, op) in ops.into_iter().enumerate() {
        apply_one(target, op).map_err(|error| format!("op {index} {error}"))?;
    }
    Ok(())
}

/// RFC 6902 JSON Patch, which is the other patch and nothing like the merge
/// one. Paths are RFC 6901 pointers, not the paths `at` and `set` walk.
#[allow(clippy::needless_pass_by_value)]
fn json_patch(target: rune::Value, ops: rune::Value) -> Result<rune::Value, String> {
    let mut patched: serde_json::Value =
        serde_json::to_value(&target).map_err(|error| format!("util::json_patch: {error}"))?;
    let ops: serde_json::Value =
        serde_json::to_value(&ops).map_err(|error| format!("util::json_patch: {error}"))?;

    // All or nothing. The work lands on this copy and the caller only ever sees
    // it once every operation has applied, so a failure changes nothing.
    apply_patch(&mut patched, ops).map_err(|error| format!("util::json_patch {error}"))?;
    to_script_value(patched)
}

/// The same patch read from a file beside the script, so a deployment can carry
/// an override that the script itself does not have to spell out.
#[allow(clippy::needless_pass_by_value)]
fn json_patch_file(target: rune::Value, name: &str) -> Result<rune::Value, String> {
    let mut patched: serde_json::Value =
        serde_json::to_value(&target).map_err(|error| format!("util::json_patch_file: {error}"))?;
    let ops = read_script_json("util::json_patch_file", name)?;

    apply_patch(&mut patched, ops).map_err(|error| format!("util::json_patch_file {error}"))?;
    to_script_value(patched)
}

/// The shape a Redfish client expects where a BMC serves nothing at all. Shared
/// with `bmc::expand_or_empty`, so the shape is written once.
pub(crate) fn empty_collection_json(id: &str, name: &str) -> serde_json::Value {
    serde_json::json!({
        "@odata.id": id,
        "Name": name,
        "Members": [],
        "Members@odata.count": 0,
    })
}

fn empty_collection(id: &str, name: &str) -> Result<rune::Value, String> {
    to_script_value(empty_collection_json(id, name))
}

/// Whether a Redfish resource reports itself enabled, read off `Status.State`.
#[allow(clippy::needless_pass_by_value)]
fn is_enabled(value: rune::Value) -> Result<bool, String> {
    let json: serde_json::Value =
        serde_json::to_value(&value).map_err(|error| format!("util::is_enabled: {error}"))?;
    Ok(walk(&json, "Status/State")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|state| state.to_ascii_lowercase().contains("enabled")))
}

/// One segment of a slash separated path, counted from the end when negative.
/// Four shipped scripts hand-rolled this, which is what earned it a place.
fn segment(path: &str, index: i64) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    let at = if index < 0 {
        parts
            .len()
            .checked_sub(usize::try_from(index.unsigned_abs()).ok()?)?
    } else {
        usize::try_from(index).ok()?
    };
    parts.get(at).map(|part| (*part).to_string())
}

/// Helpers with no BMC in them. Kept out of `bmc` because none of them can
/// reach the target, which is the distinction that matters when reading a script.
pub(crate) fn util_module() -> Result<Module, rune::ContextError> {
    let mut module = Module::with_crate("util")?;

    module
        .function("sha256", |data: String| {
            hex(ring::digest::digest(&ring::digest::SHA256, data.as_bytes()))
        })
        .build()?;
    module
        .function("sha512", |data: String| {
            hex(ring::digest::digest(&ring::digest::SHA512, data.as_bytes()))
        })
        .build()?;
    module
        .function("b64_encode", |data: String| BASE64.encode(data.as_bytes()))
        .build()?;
    module.function("b64_decode", b64_decode).build()?;
    module.function("json_encode", json_encode).build()?;
    module.function("json_decode", json_decode).build()?;
    module.function("unix_time", unix_time).build()?;
    module.function("read_json_file", read_json_file).build()?;
    module.function("read_env", read_env).build()?;
    module.function("rewrite_links", rewrite_links).build()?;
    module
        .function("rewrite_links_text", rewrite_links_text)
        .build()?;
    module.function("at", at).build()?;
    module.function("set", set).build()?;
    module.function("contains", contains).build()?;
    module
        .function("json_merge_patch", json_merge_patch)
        .build()?;
    module.function("json_patch", json_patch).build()?;
    module
        .function("json_patch_file", json_patch_file)
        .build()?;
    module
        .function("empty_collection", empty_collection)
        .build()?;
    module.function("is_enabled", is_enabled).build()?;
    module.function("segment", segment).build()?;

    Ok(module)
}
