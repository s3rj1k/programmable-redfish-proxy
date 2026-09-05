// SPDX-License-Identifier: Unlicense

//! HTTP policy with no Rune in it. Which headers are a credential, how a record
//! is rendered for the log, and how a BMC-absolute URL becomes a proxy one.

use std::net::SocketAddrV4;

use http::{HeaderMap, HeaderName, HeaderValue};
use url::Url;

/// Hop-by-hop headers, stripped in both directions.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub(crate) fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Copies end-to-end headers, dropping hop-by-hop ones. `Authorization` and
/// `X-Auth-Token` are kept, because relaying them is the entire point.
pub(crate) fn copy_end_to_end(source: &HeaderMap, dest: &mut HeaderMap) {
    for (name, value) in source {
        if is_hop_by_hop(name.as_str()) || name == http::header::HOST {
            continue;
        }
        // Nothing here decompresses, so a BMC that honoured this would hand
        // back a body the rewriter cannot read and must then refuse.
        if name == http::header::ACCEPT_ENCODING {
            continue;
        }
        dest.append(name.clone(), value.clone());
    }
}

/// Headers whose values are never logged, in any form.
const REDACTED: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-auth-token",
    "cookie",
    "set-cookie",
];

pub(crate) fn is_redacted(header_name: &str) -> bool {
    REDACTED
        .iter()
        .any(|candidate| header_name.eq_ignore_ascii_case(candidate))
}

/// Header names a script must never be able to set, so it cannot forge or
/// exfiltrate credentials through its returned response.
pub(crate) const fn script_forbidden_headers() -> [HeaderName; 3] {
    [
        http::header::AUTHORIZATION,
        http::header::PROXY_AUTHORIZATION,
        HeaderName::from_static("x-auth-token"),
    ]
}

const REDACTION: &str = "<redacted>";

/// How much of a body reaches the log before it is clipped. Fixed, because no
/// deployment has a reason to want a different number here.
const MAX_BODY_LOG: usize = 16 * 1024;

/// The declared content type, shared by the rewriter and the log renderer.
pub(crate) fn content_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
}

/// Whether a declared type is JSON. `+json` is a suffix test rather than a
/// substring one, so `application/atom+xml` and `text/xml` stay outside it.
pub(crate) fn json_content_type(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    // Parameters are not part of the type, so `;charset=utf-8` comes off first.
    let essence = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence == "application/json" || essence.ends_with("+json")
}

pub(crate) fn is_json(headers: &HeaderMap) -> bool {
    json_content_type(content_type(headers))
}

/// Truncates a body for logging and marks that it happened, so a clipped body
/// is never mistaken for a complete one.
fn truncate_body(body: &str) -> String {
    let cap = MAX_BODY_LOG;
    if body.len() <= cap {
        return body.to_string();
    }
    let mut end = cap;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… <truncated {} bytes>", &body[..end], body.len() - end)
}

/// Renders an already-buffered body, clipped to `MAX_BODY_LOG`. Binary falls
/// out through the UTF-8 check rather than a content-type list.
pub(crate) fn render_body(body: &[u8]) -> Option<String> {
    std::str::from_utf8(body).ok().map(truncate_body)
}

/// Renders headers for logging, replacing credential values with a marker.
/// The header name is kept so operators can still see that auth was present.
pub(crate) fn redact_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            if is_redacted(&name) {
                return (name, REDACTION.to_string());
            }
            let rendered = value.to_str().map_or_else(
                |_| "<non-utf8>".to_string(),
                std::string::ToString::to_string,
            );
            (name, rendered)
        })
        .collect()
}

/// Headers whose whole value is a URL pointing back at the BMC, so any absolute
/// URL in them can be rewritten.
const BMC_RELATIVE_HEADERS: &[&str] = &["location", "content-location"];

/// Headers whose URLs may legitimately be external, so only the target's own
/// authority is swapped. Redfish cites `redfish.dmtf.org` schemas this way.
const FOREIGN_URL_HEADERS: &[&str] = &["link"];

/// Whether an authority names the target, at any port. A BMC redirecting to
/// another port on itself is still the BMC.
fn is_target(authority: &str, target: SocketAddrV4) -> bool {
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    };

    // No bracketed-authority handling, and none needed. A bracketed IPv6 host
    // never equals an IPv4 address either way, so a foreign one is left alone.
    host.eq_ignore_ascii_case(&target.ip().to_string())
}

/// Walks back from a `://` over the scheme, returning where the URL starts.
/// Equal to `sep` when nothing scheme-shaped precedes it.
fn scheme_start(text: &str, sep: usize) -> usize {
    let mut start = sep;
    for (index, ch) in text[..sep].char_indices().rev() {
        if ch.is_ascii_alphanumeric() || ch == '+' || ch == '-' || ch == '.' {
            start = index;
        } else {
            break;
        }
    }
    // A scheme must begin with a letter.
    match text[start..sep].chars().next() {
        Some(first) if first.is_ascii_alphabetic() => start,
        _ => sep,
    }
}

/// Replaces the `scheme://authority` of each URL that `wanted` accepts. Parsed,
/// since a substring match strands the port on a non-default one.
fn swap_authorities(base: &Url, text: &str, wanted: impl Fn(&str) -> bool) -> String {
    let base = base.as_str().trim_end_matches('/');
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;

    while let Some(found) = text[cursor..].find("://") {
        let sep = cursor + found;
        let scheme_start = scheme_start(text, sep);
        // Not a scheme, so leave the `://` where it is.
        if scheme_start == sep {
            out.push_str(&text[cursor..sep + 3]);
            cursor = sep + 3;
            continue;
        }

        let authority_start = sep + 3;
        let authority_end = authority_start
            + text[authority_start..]
                .find(|c: char| "/?#\"'<>, \t".contains(c))
                .unwrap_or(text.len() - authority_start);

        out.push_str(&text[cursor..scheme_start]);
        if wanted(&text[authority_start..authority_end]) {
            out.push_str(base);
        } else {
            out.push_str(&text[scheme_start..authority_end]);
        }
        cursor = authority_end;
    }

    out.push_str(&text[cursor..]);
    out
}

fn is_bmc_relative(name: &str) -> bool {
    BMC_RELATIVE_HEADERS
        .iter()
        .any(|h| name.eq_ignore_ascii_case(h))
}

fn is_url_header(name: &str) -> bool {
    is_bmc_relative(name)
        || FOREIGN_URL_HEADERS
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h))
}

/// Rewrites URL-bearing headers in place. Always applied, as it costs no
/// parsing.
pub(crate) fn rewrite_headers(target: SocketAddrV4, base: &Url, headers: &mut HeaderMap) {
    let names: Vec<_> = headers
        .keys()
        .filter(|name| is_url_header(name.as_str()))
        .cloned()
        .collect();

    for name in names {
        let rewritten: Vec<HeaderValue> = headers
            .get_all(&name)
            .iter()
            .map(|value| {
                let Ok(text) = value.to_str() else {
                    return value.clone();
                };
                // A BMC-relative header holds nothing but a link back to the
                // BMC, so every authority in it is swapped whatever it names.
                let swapped = if is_bmc_relative(name.as_str()) {
                    swap_authorities(base, text, |_| true)
                } else {
                    swap_authorities(base, text, |a| is_target(a, target))
                };
                // Keeping the original beats dropping it, since `remove` below
                // takes every value and only these are put back.
                HeaderValue::from_str(&swapped).unwrap_or_else(|_| value.clone())
            })
            .collect();
        if !rewritten.is_empty() {
            headers.remove(&name);
            for value in rewritten {
                headers.append(&name, value);
            }
        }
    }
}

/// Swaps the target's own authority in a plain string. Only the target's, since
/// an `Oem` blob may hold a vendor URL that has nothing to do with this BMC.
pub(crate) fn rewrite_text(target: SocketAddrV4, base: &Url, text: &str) -> String {
    if !text.contains("://") {
        return text.to_string();
    }
    swap_authorities(base, text, |a| is_target(a, target))
}

/// Walks every string rather than a list of known URL-bearing keys, since
/// `Oem.*` is unbounded in shape and any such list would be incomplete.
pub(crate) fn rewrite_value(target: SocketAddrV4, base: &Url, value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            if s.contains("://") {
                *s = rewrite_text(target, base, s);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                rewrite_value(target, base, item);
            }
        }
        serde_json::Value::Object(map) => {
            for (_key, item) in map.iter_mut() {
                rewrite_value(target, base, item);
            }
        }
        _ => {}
    }
}

/// Rewrites absolute URLs inside a JSON body. Bounded by type only, since
/// rewriting is a correctness requirement and a skipped body leaks the BMC.
fn rewrite_json(
    target: SocketAddrV4,
    base: &Url,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    if !json_content_type(content_type) {
        return Ok(None);
    }
    // A HEAD reply and a 204 both declare a type and carry nothing, and an
    // empty body has no address in it to leak.
    if body.is_empty() {
        return Ok(None);
    }
    // Refused rather than skipped. Serving a body the rewriter could not read
    // is the one outcome that leaks the BMC address to the caller.
    let mut value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| format!("a body declared JSON could not be parsed: {error}"))?;
    rewrite_value(target, base, &mut value);
    serde_json::to_vec(&value)
        .map(Some)
        .map_err(|error| format!("re-encoding a rewritten body failed: {error}"))
}

/// Rewrites a response's headers and JSON body together, which is the only
/// order they are ever wanted in. Returns `None` when the body is untouched.
pub(crate) fn rewrite_response(
    target: SocketAddrV4,
    base: &Url,
    headers: &mut HeaderMap,
    body: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    rewrite_headers(target, base, headers);
    let content_type = content_type(headers).map(str::to_string);
    rewrite_json(target, base, content_type.as_deref(), body)
}
