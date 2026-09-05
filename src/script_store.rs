// SPDX-License-Identifier: Unlicense

//! The `store` script module, being the only place a script can keep anything
//! between requests. Everything else a handler touches is gone when it returns.

//! In memory and process-lifetime only, so a restart empties it the way a BMC
//! forgets across a power cycle. Nothing here reaches the disk.

use std::collections::HashMap;
use std::sync::Mutex;

use rune::Module;

use crate::rune_host::request_ctx;
use crate::script_bmc::to_script_value;

/// How many keys the store will hold. Fixed rather than configurable, because
/// a script that wants a thousand and first key has a bug, not a deployment.
const MAX_KEYS: usize = 1024;

/// Longest key accepted, so a generated one cannot become the payload.
const MAX_KEY_LEN: usize = 256;

/// Largest value accepted, measured as encoded JSON. A script that wants to
/// park a firmware image here should be writing it to the BMC instead.
const MAX_VALUE_BYTES: usize = 64 * 1024;

/// The shared map. One per process, since one proxy fronts one BMC and there is
/// nothing to key a second namespace on.
#[derive(Default)]
pub struct Store {
    entries: Mutex<HashMap<String, serde_json::Value>>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of keys held, for the startup and reload log lines.
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |entries| entries.len())
    }
}

/// A poisoned lock means a previous holder panicked mid-write, so the map may be
/// half-updated. A store that silently stops storing is worse than a failure.
fn poisoned(what: &str) -> String {
    format!("store::{what}: the store lock is poisoned")
}

fn check_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("store: the key is empty".to_string());
    }
    if key.len() > MAX_KEY_LEN {
        return Err(format!(
            "store: key is {} bytes, over the {MAX_KEY_LEN} byte limit",
            key.len()
        ));
    }
    Ok(())
}

fn get(key: &str) -> Result<Option<rune::Value>, String> {
    check_key(key)?;
    let ctx = request_ctx("store::get")?;
    let entries = ctx
        .state
        .store
        .entries
        .lock()
        .map_err(|_| poisoned("get"))?;
    match entries.get(key) {
        Some(value) => to_script_value(value.clone()).map(Some),
        None => Ok(None),
    }
}

/// `get` with the answer a script would otherwise write a `match` for. The
/// default comes back untouched, so a stored copy of it reads like a miss.
#[allow(clippy::needless_pass_by_value)]
fn get_or(key: &str, fallback: rune::Value) -> Result<rune::Value, String> {
    match get(key)? {
        Some(value) => Ok(value),
        None => Ok(fallback),
    }
}

// Owned deliberately. Rune has no marshalling for `&Value`, so a borrow here
// fails to satisfy `Module::function` however unused the ownership looks.
#[allow(clippy::needless_pass_by_value)]
fn set(key: &str, value: rune::Value) -> Result<(), String> {
    check_key(key)?;

    let json = serde_json::to_value(&value).map_err(|error| {
        format!("store::set {key:?}: value is not serialisable as JSON: {error}")
    })?;

    // Encoded length, not the in-memory size of the tree, since that is the
    // number the limit is written in terms of and the only one worth quoting.
    let encoded = serde_json::to_vec(&json)
        .map_err(|error| format!("store::set {key:?}: {error}"))?
        .len();
    if encoded > MAX_VALUE_BYTES {
        return Err(format!(
            "store::set {key:?}: value is {encoded} bytes, over the {MAX_VALUE_BYTES} byte limit"
        ));
    }

    let ctx = request_ctx("store::set")?;
    let mut entries = ctx
        .state
        .store
        .entries
        .lock()
        .map_err(|_| poisoned("set"))?;

    // Overwriting an existing key is always allowed. Only growing past the
    // limit is refused, so a store at capacity still serves what it holds.
    if entries.len() >= MAX_KEYS && !entries.contains_key(key) {
        return Err(format!(
            "store::set {key:?}: the store already holds {MAX_KEYS} keys"
        ));
    }

    entries.insert(key.to_string(), json);
    Ok(())
}

/// Removes everything under a prefix, so a reset can clear per-member keys it
/// has no way to enumerate. Answers with how many went.
fn remove_prefix(prefix: &str) -> Result<i64, String> {
    check_key(prefix)?;
    let ctx = request_ctx("store::remove_prefix")?;
    let mut entries = ctx
        .state
        .store
        .entries
        .lock()
        .map_err(|_| poisoned("remove_prefix"))?;
    let before = entries.len();
    entries.retain(|key, _| !key.starts_with(prefix));
    i64::try_from(before - entries.len()).map_err(|_| "store::remove_prefix overflowed".to_string())
}

/// Whether the key was there, so a caller can tell a delete from a no-op.
fn remove(key: &str) -> Result<bool, String> {
    check_key(key)?;
    let ctx = request_ctx("store::remove")?;
    let mut entries = ctx
        .state
        .store
        .entries
        .lock()
        .map_err(|_| poisoned("remove"))?;
    Ok(entries.remove(key).is_some())
}

fn contains(key: &str) -> Result<bool, String> {
    check_key(key)?;
    let ctx = request_ctx("store::contains")?;
    let entries = ctx
        .state
        .store
        .entries
        .lock()
        .map_err(|_| poisoned("contains"))?;
    Ok(entries.contains_key(key))
}

/// State a script keeps for itself. Kept out of `util`, where everything is a
/// pure function of its arguments, so a `store` call stands out when reading.
pub(crate) fn store_module() -> Result<Module, rune::ContextError> {
    let mut module = Module::with_crate("store")?;
    module.function("get", get).build()?;
    module.function("get_or", get_or).build()?;
    module.function("set", set).build()?;
    module.function("remove", remove).build()?;
    module.function("remove_prefix", remove_prefix).build()?;
    module.function("contains", contains).build()?;
    Ok(module)
}
