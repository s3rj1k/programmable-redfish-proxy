# programmable-redfish-proxy

An HTTPS proxy for a Redfish BMC where every request is handled by a
[Rune](https://github.com/rune-rs/rune) script.

Routes and scripts are set in `config.toml`. The shipped ones make a plain
Redfish emulator look like a Supermicro BMC.

Build and install with `make build && sudo make install`.

Public domain under the [Unlicense](LICENSE).

## Script API

A handler is ordinary Rune, so start with the
[Rune book](https://rune-rs.github.io/book/getting_started.html). The table below
is only what this proxy adds.

```rune
pub async fn handle(req) {
    log::request("info", true)?;
    bmc::forward().await?.rewrite()?.log("info", true)
}
```

Nothing is automatic. A handler that skips `.rewrite()` serves the BMC's own
address, and one that skips logging serves the request silently. No script can
choose the target or set auth, which Rust owns either way.

Types are module scoped, so `bmc::Forwarded`, `resp::ScriptResponse` and so on.

| item | kind | what it does |
| --- | --- | --- |
| `bmc::address()` | fn | The target's `host:port`. Readable, never choosable. |
| `bmc::delete(path)` | fn | DELETE the path. Reply buffered. |
| `bmc::expand_collection(path)` | fn | GET a collection with `Members` inlined, asking `$expand` first and walking members itself when the BMC ignored it. |
| `bmc::expand_or_empty(path, name)` | fn | As `expand_collection`, answering an empty collection on **any** failure, a 404 and an unreachable BMC alike. A dead target reads as an empty collection, not an error. |
| `bmc::external_base()` | fn | What links are rewritten to, being the proxy's own base. |
| `bmc::forward()` | fn | Relay the inbound request, less the hop-by-hop headers, `Host` and `Accept-Encoding`. JSON is buffered, everything else streams. A transport failure comes back as a 502 or 504 rather than an error. |
| `bmc::forward_with(req)` | fn | Send a script-built request, classified the way `forward` classifies one. |
| `bmc::get(path)` | fn | GET the path. Reply buffered. |
| `bmc::inbound()` | fn | The inbound request as a `BmcRequest` to modify and relay. |
| `bmc::manager_id()` | fn | The manager id, probed once per request. |
| `bmc::patch(path, body)` | fn | PATCH with a JSON body. |
| `bmc::path_of(link)` | fn | The path out of an `@odata.id`, whether it is an absolute URL or already a path. |
| `bmc::post(path, body)` | fn | POST with a JSON body. |
| `bmc::put(path, body)` | fn | PUT with a JSON body. |
| `bmc::request(method, path)` | fn | Start a request for what the verb helpers cannot express, being a non-JSON body, an extra header, or a method such as HEAD. |
| `bmc::sleep(millis)` | fn | Await a delay, for polling a Task or a Job. |
| `bmc::system_id()` | fn | The system id, probed once per request. |
| `log::at(level, message)` | fn | A message at a level named at runtime. |
| `log::debug(message)` | fn | A message at debug. |
| `log::error(message)` | fn | A message at error. |
| `log::event(level, message, fields)` | fn | A structured record, the object rendered into one `fields` value. |
| `log::info(message)` | fn | A message at info. |
| `log::request(level, with_body)` | fn | The inbound request record, credentials redacted and the body clipped. |
| `log::trace(message)` | fn | A message at trace. |
| `log::warn(message)` | fn | A message at warn. |
| `resp::json(status, value)` | fn | A JSON response. |
| `resp::status(status)` | fn | A response with no body. |
| `resp::text(status, body)` | fn | A `text/plain` response. |
| `store::contains(key)` | fn | Whether the key is set. |
| `store::get(key)` | fn | The value, or `None`. |
| `store::get_or(key, fallback)` | fn | The value, or the fallback returned untouched. |
| `store::remove(key)` | fn | Drop the key, answering whether it was there. |
| `store::remove_prefix(prefix)` | fn | Drop every key under a prefix, answering how many went. |
| `store::set(key, value)` | fn | Keep a value between requests. In memory and process lifetime only, so a restart empties it. At most 1024 keys, a 256 byte key and a 64KiB encoded value. |
| `util::at(value, path)` | fn | A deep read on a slash separated path, answering `None` rather than failing the request. |
| `util::b64_decode(data)` | fn | Decode base64 into a string. |
| `util::b64_encode(data)` | fn | Encode a string as base64. |
| `util::contains(list, wanted)` | fn | Whether a list holds a value, which Rune's `Vec` cannot answer. |
| `util::empty_collection(id, name)` | fn | The shape a Redfish client expects where nothing is served. |
| `util::is_enabled(value)` | fn | Whether a resource reports itself enabled, read off `Status.State`. |
| `util::json_decode(text)` | fn | Parse JSON text into a value. |
| `util::json_encode(value)` | fn | Render a value as JSON text. |
| `util::json_merge_patch(target, patch)` | fn | RFC 7386 merge-patch, where a `null` in the patch deletes the key. |
| `util::json_patch(target, ops)` | fn | RFC 6902 JSON Patch, an array of ops over RFC 6901 pointers. Not the same operation as the merge one. At most 1024 ops. |
| `util::json_patch_file(target, name)` | fn | As `json_patch`, with the ops read from a file beside the script. |
| `util::read_env(name)` | fn | An environment variable, but only if `rune.env_allow` matches the name. |
| `util::read_json_file(name)` | fn | A `.json` file under `script_dir`, nested directories included and nothing outside it. |
| `util::rewrite_links(value)` | fn | Swap the BMC's authority for the proxy's inside a JSON value. |
| `util::rewrite_links_text(text)` | fn | The same swap on a plain string, for a body no JSON rewrite reaches. |
| `util::segment(path, index)` | fn | One slash separated segment, counted from the end when the index is negative. |
| `util::set(value, path, new)` | fn | A deep write that creates the objects along the way. Answers the value, since Rune cannot marshal a reference. |
| `util::sha256(data)` | fn | Lowercase hex SHA-256. |
| `util::sha512(data)` | fn | Lowercase hex SHA-512. |
| `util::unix_time()` | fn | Seconds since the epoch. |
| `BmcRequest.base64(body)` | method | Set a body from base64, the only way to send bytes that are not text. |
| `BmcRequest.content_type(value)` | method | Override the content type the body would otherwise set. |
| `BmcRequest.header(name, value)` | method | Add a header. Auth, hop-by-hop, `host` and `content-length` are refused. |
| `BmcRequest.json(value)` | method | Set a JSON body. |
| `BmcRequest.path(value)` | method | Retarget the request. Still refuses anything but an absolute path. |
| `BmcRequest.send()` | method | Send it. Reply buffered whatever its type. |
| `BmcRequest.text(body)` | method | Set a `text/plain` body. |
| `BmcResponse.content_type()` | method | The declared content type. |
| `BmcResponse.header(name)` | method | One header. Credentials are hidden. |
| `BmcResponse.is_json()` | method | Whether the reply declared JSON. |
| `BmcResponse.json()` | method | Parse the body. |
| `BmcResponse.ok()` | method | Whether the status is 2xx. |
| `BmcResponse.status()` | method | The status code. |
| `BmcResponse.text()` | method | The body as text. |
| `Forwarded.buffer()` | method | Pull a streaming body into memory so it can be read. On `text/event-stream` this waits on a body that never ends. |
| `Forwarded.content_type()` | method | The declared content type. |
| `Forwarded.header(name)` | method | One header. Credentials are hidden. |
| `Forwarded.is_json()` | method | Whether the reply declared JSON, which is what it said and not how the body is held. |
| `Forwarded.json()` | method | Parse a buffered body. |
| `Forwarded.log(level, with_body)` | method | Emit the response record and answer itself, so a handler logs and returns in one expression. |
| `Forwarded.ok()` | method | Whether the status is 2xx. |
| `Forwarded.rewrite()` | method | Swap the BMC's authority for the proxy's, in the headers and in a JSON body. `Location` and `Content-Location` hold nothing but a link back, so every absolute URL in those is swapped whatever authority it names. |
| `Forwarded.status()` | method | The status code. |
| `Forwarded.streaming()` | method | Whether the body is streaming rather than held. |
| `Forwarded.text()` | method | A buffered body as text. |
| `ScriptRequest.content_type()` | method | The declared content type. |
| `ScriptRequest.header(name)` | method | One inbound header. Credentials are removed before a script sees them. |
| `ScriptRequest.header_names()` | method | Every readable header name, sorted. |
| `ScriptRequest.is_json()` | method | Whether the caller declared JSON. |
| `ScriptRequest.json()` | method | Parse the inbound body. |
| `ScriptRequest.method` | field | The inbound method. |
| `ScriptRequest.path` | field | The inbound path, without the query. |
| `ScriptRequest.query` | field | The raw query string. |
| `ScriptRequest.query_param(name)` | method | One query parameter, percent-decoded. |
| `ScriptRequest.text()` | method | The inbound body as text. |
| `ScriptResponse.log(level, with_body)` | method | Emit the response record and answer itself. |
| `ScriptResponse.rewrite()` | method | Swap the BMC's authority for the proxy's, on the same terms as `Forwarded.rewrite`. |
| `ScriptResponse.with_header(name, value)` | method | Add a header. Auth and hop-by-hop names are dropped. |
