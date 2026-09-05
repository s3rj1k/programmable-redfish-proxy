// SPDX-License-Identifier: Unlicense

//! Black-box end-to-end tests. The proxy runs as a subprocess and is reached
//! only over HTTPS, through its config file, and by reading its logs.

//! Tests are grouped by subject and sorted by name inside each group. A new
//! test goes in its section, in order, not at the end of the file.

use std::fmt::Write as _;
use std::time::Duration;
use support::{
    PROXY_BASE, base_config, check, client, config_with, config_without_tls, script, spawn_bmc,
    start_proxy, start_proxy_env, tls,
};

// Shared by every scripted section below.

fn rune_config(tls: &support::Tls, bmc: std::net::SocketAddr, name: &str, body: &str) -> String {
    script(tls, name, body);
    format!(
        r#"{base}
        [[route]]
        path   = "/redfish/v1/Chassis/*"
        script = "{name}"
        "#,
        base = base_config(tls, bmc),
    )
}

// Forwarding.

fn assert_upload(seen: &support::Seen) {
    assert_eq!(seen.body_len, 64 * 1024);
    assert_eq!(seen.header("content-length"), Some("65536"));
    assert!(
        !seen.has_header("transfer-encoding"),
        "the upload was chunked"
    );
}

#[tokio::test]
async fn a_caller_cannot_steer_the_proxy_at_another_host() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    // The target is fixed at startup, so the headers that used to select one
    // are inert. This is what replaced the allowlist as the perimeter.
    let response = client()
        .get(format!("https://{}/redfish/v1", proxy.addr))
        .header("forwarded", "host=198.51.100.1")
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);
    assert_eq!(seen.count(), 1);
    assert_eq!(seen.last().path, "/redfish/v1");

    // A `/bmc/<ip>/` prefix is an ordinary path now, not a target selector.
    let prefixed = client()
        .get(format!(
            "https://{}/bmc/198.51.100.1/redfish/v1",
            proxy.addr
        ))
        .send()
        .await
        .expect("request");
    assert_eq!(prefixed.status(), 404);
    assert_eq!(seen.last().path, "/bmc/198.51.100.1/redfish/v1");
}

#[tokio::test]
async fn a_forwarded_request_keeps_its_query_string() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    // Redfish leans on `$expand` and `$select`, so dropping the query would
    // quietly change what a caller asked for.
    let handler = r#"
        pub async fn handle(req) {
            if req.query_param("mode") == Some("inbound") {
                let out = bmc::inbound()?;
                return resp::json(200, bmc::forward_with(out).await?.json()?).rewrite()?;
            }
            resp::json(200, bmc::forward().await?.json()?).rewrite()
        }
    "#;
    let proxy = start_proxy(
        &tls,
        &route_config(&tls, bmc, "query.rn", handler, "/redfish/v1/Echo", ""),
    );

    for mode in ["forward", "inbound"] {
        let response = client()
            .get(format!(
                "https://{}/redfish/v1/Echo?mode={mode}&$select=Id",
                proxy.addr
            ))
            .send()
            .await
            .expect("request");
        assert_eq!(response.status(), 200, "{mode}");
    }

    let queries: Vec<String> = seen
        .all()
        .into_iter()
        .filter(|call| call.path == "/redfish/v1/Echo")
        .map(|call| call.query.clone())
        .collect();
    assert_eq!(queries.len(), 2, "both modes should have reached the BMC");
    for query in &queries {
        assert!(query.contains("$select=Id"), "query was dropped: {query:?}");
    }
}

#[tokio::test]
async fn a_slow_upload_is_bounded_by_the_target_timeout() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // Nothing scales a timeout by body size, so target.timeout is the whole
    // budget and a slow BMC fails fast rather than hanging.
    let proxy = start_proxy(&tls, &config_with(&tls, bmc, "timeout = \"1s\""));

    let began = std::time::Instant::now();
    let response = client()
        .post(format!("https://{}/redfish/v1/Slow", proxy.addr))
        .body(vec![b'x'; 4096])
        .send()
        .await
        .expect("request");
    let took = began.elapsed();

    assert_eq!(response.status(), 504, "the upload timeout never fired");
    assert!(
        took < Duration::from_secs(8),
        "the upload ran well past target.timeout, took {took:?}"
    );
}

#[tokio::test]
async fn credentials_are_relayed_verbatim_and_hop_by_hop_headers_are_not() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let response = client()
        .get(format!("https://{}/redfish/v1", proxy.addr))
        .basic_auth("root", Some("calvin"))
        .header("x-auth-token", "session-token-abc")
        .header("te", "trailers")
        .header("proxy-authenticate", "Basic realm=nope")
        .header("upgrade", "websocket")
        .header("keep-alive", "timeout=5")
        .header("odata-version", "4.0")
        .send()
        .await
        .expect("request reaches the proxy");
    assert_eq!(response.status(), 200);

    let seen = seen.last();

    // The entire point of this proxy, that a credential arrives unchanged. Both
    // forms of it, since a Redfish session token is a credential as much as Basic.
    assert_eq!(seen.header("authorization"), Some("Basic cm9vdDpjYWx2aW4="));
    assert_eq!(seen.header("x-auth-token"), Some("session-token-abc"));

    // An ordinary end-to-end header is untouched, and hop-by-hop ones are gone.
    assert_eq!(seen.header("odata-version"), Some("4.0"));
    // Only names the client actually sent. Asserting on one it never sent
    // passes whether the proxy strips it or not.
    for dropped in ["te", "proxy-authenticate", "upgrade", "keep-alive"] {
        assert!(!seen.has_header(dropped), "{dropped} was forwarded");
    }
}

#[tokio::test]
async fn event_streams_are_passed_through_without_buffering() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let response = client()
        .get(format!(
            "https://{}/redfish/v1/EventService/SSE",
            proxy.addr
        ))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    // The fake emits one event then holds the connection open for 30s. If the
    // proxy buffered, nothing would arrive until that elapsed.
    let mut stream = response.bytes_stream();
    let first = tokio::time::timeout(
        Duration::from_secs(5),
        futures_util::StreamExt::next(&mut stream),
    )
    .await
    .expect("SSE was buffered rather than streamed")
    .expect("a chunk arrives")
    .expect("chunk reads");
    assert_eq!(&first[..], b"data: first\n\n");

    // An endless body must never reach the log either.
    assert!(!proxy.logs().contains("data: first"), "SSE body was logged");
}

#[tokio::test]
async fn every_inbound_verb_reaches_the_bmc() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    // Forwarding is verb-agnostic, so the ones a Redfish client uses less often
    // are the ones most likely to have quietly stopped working.
    let url = format!("https://{}/redfish/v1/Echo", proxy.addr);
    for method in [
        reqwest::Method::DELETE,
        reqwest::Method::HEAD,
        reqwest::Method::OPTIONS,
    ] {
        let response = client()
            .request(method.clone(), &url)
            .send()
            .await
            .unwrap_or_else(|error| panic!("{method} request: {error}"));
        assert_eq!(response.status(), 200, "{method}");
    }

    let seen_verbs: Vec<String> = seen
        .all()
        .into_iter()
        .filter(|call| call.path == "/redfish/v1/Echo")
        .map(|call| call.method)
        .collect();
    assert_eq!(seen_verbs, ["DELETE", "HEAD", "OPTIONS"]);
}

#[tokio::test]
async fn every_upload_reaches_the_bmc_with_a_length_and_never_chunked() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let url = format!("https://{}/redfish/v1/UpdateService/upload", proxy.addr);

    // The case that matters. The caller declares no length, and BMC firmware
    // rejects chunked, so buffering is what lets one be declared upstream.
    let stream =
        futures_util::stream::iter((0..64).map(|_| Ok::<_, std::io::Error>(vec![b'x'; 1024])));
    let undeclared = client()
        .post(&url)
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .expect("request");
    assert_eq!(undeclared.status(), 202);
    assert_upload(&seen.last());

    // A declared length is the same path, since every body is buffered.
    let declared = client()
        .post(&url)
        .header("content-type", "application/octet-stream")
        .body(vec![b'x'; 64 * 1024])
        .send()
        .await
        .expect("request");
    assert_eq!(declared.status(), 202);
    assert_upload(&seen.last());
}

#[tokio::test]
async fn redirects_are_returned_to_the_caller_not_followed() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let response = client()
        .get(format!("https://{}/redfish/v1/Redirect", proxy.addr))
        .send()
        .await
        .expect("request");

    // A streamed body cannot be replayed, and chasing a Location would leave
    // the configured target behind.
    assert_eq!(response.status(), 307);
    let location = response.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(PROXY_BASE), "{location}");
    assert!(!location.contains(&bmc.to_string()), "{location}");
    assert!(
        !seen.all().iter().any(|s| s.path == "/redfish/v1/Elsewhere"),
        "the proxy followed the redirect"
    );
}

// Link rewriting.

#[tokio::test]
async fn a_body_the_rewriter_cannot_read_is_refused_rather_than_served() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let response = client()
        .get(format!("https://{}/redfish/v1/Opaque", proxy.addr))
        .header("accept-encoding", "gzip")
        .send()
        .await
        .expect("request");

    // Nothing here decompresses, so relaying this would invite a body the
    // rewriter cannot read and would then have to refuse.
    assert!(
        !seen.last().has_header("accept-encoding"),
        "accept-encoding reached the BMC"
    );

    // Serving it un-rewritten is the one outcome that leaks the BMC address,
    // so a body declared JSON that will not parse fails the request instead.
    assert_eq!(response.status(), 502);
    let body = response.text().await.expect("body");
    assert!(
        !body.contains(&bmc.to_string()),
        "the BMC address leaked: {body}"
    );
}

#[tokio::test]
async fn a_handler_that_skips_rewrite_serves_the_bmc_address() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // Nothing rewrites automatically any more, so this is the shape of the
    // mistake. Pinned deliberately, since it is the cost of manual rewriting.
    let handler = "pub async fn handle(req) { bmc::forward().await? }";
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "raw.rn", handler));

    let body = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .text()
        .await
        .expect("body");

    assert!(
        body.contains(&bmc.to_string()),
        "a handler that skips rewrite is expected to leak, but did not: {body}"
    );
    assert!(!body.contains(PROXY_BASE), "{body}");
}

#[tokio::test]
async fn a_header_value_that_cannot_be_rewritten_is_kept() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let response = client()
        .get(format!("https://{}/redfish/v1/TwoLinks", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    // Rewriting removes every value and puts the survivors back, so a sibling
    // that cannot be read must survive rather than vanish with the rest.
    let links: Vec<_> = response.headers().get_all("link").iter().collect();
    assert_eq!(links.len(), 2, "a sibling Link value was dropped");
    assert!(
        links
            .iter()
            .any(|v| v.to_str().is_ok_and(|t| t.contains(PROXY_BASE))),
        "the readable value was not rewritten"
    );
}

#[tokio::test]
async fn a_large_json_body_is_still_rewritten() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let body = client()
        .get(format!("https://{}/redfish/v1/Huge", proxy.addr))
        .send()
        .await
        .expect("request")
        .text()
        .await
        .expect("body");

    // No size cap exists, so there is no body large enough to leak the BMC by
    // being skipped. Rewriting is a correctness requirement, not a best effort.
    assert!(body.contains(PROXY_BASE), "a large body was not rewritten");
    assert!(!body.contains(&bmc.to_string()), "{}", &body[..200]);
}

#[tokio::test]
async fn a_non_json_response_has_headers_rewritten_and_its_body_left_alone() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // Rewriting is bounded by kind. A text body is not parsed, so the URL in it
    // survives while the `Location` the handler set is still fixed.
    let handler = r#"
        pub async fn handle(req) {
            resp::text(200, `plain text mentioning https://${bmc::address()?}/redfish/v1/Raw`)
                .with_header("location", `https://${bmc::address()?}/redfish/v1/Made`)
                .rewrite()
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "textrw.rn", handler));

    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    let location = response.headers()["location"]
        .to_str()
        .expect("utf8")
        .to_string();
    assert_eq!(location, format!("{PROXY_BASE}/redfish/v1/Made"));

    let body = response.text().await.expect("body");
    assert!(
        body.contains(&bmc.to_string()),
        "a text body is not parsed, so it is left alone: {body}"
    );
}

#[tokio::test]
async fn a_vendor_json_suffix_type_is_buffered_and_rewritten() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    // `+json` is JSON by its suffix, so it has to be buffered and rewritten
    // rather than streamed past the rewriter as an unrecognised type.
    let response = client()
        .get(format!("https://{}/redfish/v1/VendorJson", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);
    let body = response.text().await.expect("body");

    assert!(body.contains(PROXY_BASE), "not rewritten: {body}");
    assert!(!body.contains(&bmc.to_string()), "leaked the BMC: {body}");
}

#[tokio::test]
async fn absolute_links_are_rewritten_in_both_headers_and_body() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let response = client()
        .post(format!(
            "https://{}/redfish/v1/SessionService/Sessions",
            proxy.addr
        ))
        .json(&serde_json::json!({"UserName": "root"}))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 201);

    let location = response.headers()["location"].to_str().unwrap().to_string();
    let body = response.text().await.expect("body");

    // One un-rewritten URL removes the proxy from the path, so assert the BMC
    // address is absent rather than that ours appears.
    assert!(!location.contains(&bmc.to_string()), "{location}");
    assert!(location.starts_with(PROXY_BASE), "{location}");
    assert!(!body.contains(&bmc.to_string()), "{body}");
    assert!(body.contains(PROXY_BASE), "{body}");
}

#[tokio::test]
async fn content_location_is_rewritten_like_location() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    // Both headers are BMC-relative, so any absolute URL in either is swapped.
    // Only `Location` was covered, and the pair share one code path.
    let response = client()
        .get(format!("https://{}/redfish/v1/Staged", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    let location = response.headers()["content-location"]
        .to_str()
        .expect("utf8")
        .to_string();
    assert_eq!(location, format!("{PROXY_BASE}/redfish/v1/Staged/Settings"));
    assert!(!location.contains(&bmc.to_string()), "{location}");
}

#[tokio::test]
async fn every_url_shape_a_bmc_emits_is_rewritten() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let response = client()
        .get(format!("https://{}/redfish/v1/Awkward", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 201);

    let location = response.headers()["location"].to_str().unwrap().to_string();
    let links: Vec<String> = response
        .headers()
        .get_all("link")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    let body = response.text().await.expect("body");

    // A BMC naming itself by hostname cannot be matched against the configured
    // IP, so Location is rewritten whatever authority it carries.
    assert_eq!(location, format!("{PROXY_BASE}/redfish/v1/ByName"));

    // Link may cite an external schema, which must survive.
    assert!(
        links.iter().any(|l| l.contains("redfish.dmtf.org")),
        "{links:?}"
    );
    assert!(links.iter().any(|l| l.contains(PROXY_BASE)), "{links:?}");

    // A non-default port on the target once stranded itself on the result.
    assert!(
        body.contains(&format!("{PROXY_BASE}/redfish/v1/Odd")),
        "{body}"
    );
    assert!(!body.contains(":8443:"), "a port was stranded: {body}");

    // An uppercase scheme is still the target.
    assert!(
        body.contains(&format!("{PROXY_BASE}/redfish/v1/Up")),
        "{body}"
    );

    // Bodies stay conservative, so a vendor link is untouched.
    assert!(body.contains("https://vendor.example/kb/1"), "{body}");

    // A bracketed IPv6 authority never equals the IPv4 target, so it survives
    // even though the rewriter has no bracket handling of its own.
    assert!(
        body.contains("https://[2001:db8::1]:443/redfish/v1/Six"),
        "a bracketed IPv6 URL was mangled: {body}"
    );

    // A separator with nothing scheme-shaped before it is not a URL, so the
    // scanner has to walk past it rather than rewrite from there.
    assert!(body.contains("see ://nothing here"), "{body}");
    assert!(!body.contains(&bmc.to_string()), "{body}");
}

#[tokio::test]
async fn h2_is_never_negotiated_even_when_a_client_offers_it() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    // Many BMCs speak HTTP/1.1 only, so the proxy serves one protocol on both
    // sides. A client that offers h2 must be answered with http/1.1.
    let picked = support::negotiated_protocol(&tls, proxy.addr).await;
    assert_eq!(picked.as_deref(), Some("http/1.1"));
}

#[tokio::test]
async fn relative_links_are_left_alone() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let body = client()
        .get(format!("https://{}/redfish/v1", proxy.addr))
        .send()
        .await
        .expect("request")
        .text()
        .await
        .expect("body");
    assert!(
        body.contains(r#""Relative":"/redfish/v1/Chassis""#),
        "{body}"
    );
}

// Routing, meaning which script runs.

const THERMAL: &str = r#"
pub async fn handle(req) {
    let chassis = bmc::get("/redfish/v1/Chassis/1").await?;

    // Pass a BMC failure through rather than inventing a 200 over it.
    if !chassis.ok() {
        return resp::json(chassis.status(), chassis.json()?);
    }

    let thermal = bmc::get("/redfish/v1/Chassis/1/Thermal").await?;
    let out = chassis.json()?;
    let thermal_body = thermal.json()?;

    // Built in one go, because Rune's index-set creates no intermediate object
    // and a nested assign would fail whenever the BMC sent no `Oem` key.
    let oem = #{};
    if thermal.ok() {
        oem["Fans"] = thermal_body["Fans"];
    }
    oem["ProxiedBy"] = "programmable-redfish-proxy";
    out["Oem"] = oem;

    resp::json(200, out).with_header("x-proxied-by", "programmable-redfish-proxy").rewrite()
}
"#;

#[tokio::test]
async fn a_method_filter_decides_whether_a_script_runs() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    script(
        &tls,
        "get.rn",
        "pub async fn handle(req) { resp::text(200, \"scripted\") }",
    );
    let config = format!(
        r#"{base}
        [[route]]
        method = ["GET"]
        path   = "/redfish/v1/Chassis/*"
        script = "get.rn"
        "#,
        base = base_config(&tls, bmc),
    );
    let proxy = start_proxy(&tls, &config);

    let scripted = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .text()
        .await
        .expect("body");
    assert_eq!(scripted, "scripted");
    assert_eq!(seen.count(), 0, "the script made no subrequest");

    // A method outside the filter is refused. Relaying it to the BMC instead
    // would make `method = ["GET"]` read as read-only and do the opposite.
    let refused = client()
        .post(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .body("{}")
        .send()
        .await
        .expect("request");
    assert_eq!(refused.status(), 405);
    let body = refused.text().await.expect("body");
    assert!(!body.contains("scripted"), "the script ran for POST");
    assert_eq!(seen.count(), 0, "POST must not reach the BMC");
}

#[tokio::test]
async fn a_registered_route_is_handled_by_its_script() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "thermal.rn", THERMAL));

    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .basic_auth("root", Some("calvin"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["x-proxied-by"],
        "programmable-redfish-proxy"
    );

    let body: serde_json::Value = response.json().await.expect("json");
    assert_eq!(body["Id"], "1");
    assert_eq!(body["Oem"]["ProxiedBy"], "programmable-redfish-proxy");
    assert_eq!(body["Oem"]["Fans"][0]["Name"], "Fan1");

    // Both subrequests relayed the credential and neither escaped the target.
    let all = seen.all();
    assert_eq!(all.len(), 2, "expected two subrequests");
    for request in &all {
        assert_eq!(
            request.header("authorization"),
            Some("Basic cm9vdDpjYWx2aW4=")
        );
        // The script controls the body, so an inherited length would be a lie.
        assert!(!request.has_header("if-match"));
    }

    // Links the script echoed through are rewritten, twice over, idempotently.
    let rendered = body.to_string();
    assert!(!rendered.contains(&bmc.to_string()), "{rendered}");
    assert!(rendered.contains(PROXY_BASE), "{rendered}");
    assert!(
        !rendered.contains(":8443:"),
        "double rewrite stranded a port"
    );
}

#[tokio::test]
async fn a_script_in_a_subdirectory_is_named_by_its_relative_path() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;

    // Keying by the path under script_dir rather than by file name is what lets
    // two scripts share a name in different directories.
    let dir = script(
        &tls,
        "same.rn",
        r#"pub async fn handle(req) { resp::json(200, #{"who": "top"}) }"#,
    );
    std::fs::create_dir_all(dir.join("nested")).expect("nested dir");
    std::fs::write(
        dir.join("nested/same.rn"),
        r#"pub async fn handle(req) { resp::json(200, #{"who": "nested"}) }"#,
    )
    .expect("write nested script");

    let mut config = format!("{}\n", base_config(&tls, bmc));
    for (path, name) in [
        ("/redfish/v1/Systems/Top", "same.rn"),
        ("/redfish/v1/Systems/Nested", "nested/same.rn"),
    ] {
        let _ = write!(
            config,
            "\n        [[route]]\n        path   = \"{path}\"\n        script = \"{name}\"\n"
        );
    }
    let proxy = start_proxy(&tls, &config);

    for (path, expected) in [("Top", "top"), ("Nested", "nested")] {
        let body: serde_json::Value = client()
            .get(format!("https://{}/redfish/v1/Systems/{path}", proxy.addr))
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("json");
        assert_eq!(body["who"], expected, "/redfish/v1/Systems/{path}");
    }
}

#[tokio::test]
async fn a_wildcard_route_does_not_swallow_a_deeper_path() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;

    // `*` matches one segment and `**` crosses them. Without that, these two
    // tie on literal prefix and declaration order silently picks the winner.
    let shallow = r#"pub async fn handle(req) { resp::json(200, #{"who": "shallow"}) }"#;
    let deep = r#"pub async fn handle(req) { resp::json(200, #{"who": "deep"}) }"#;
    script(&tls, "shallow.rn", shallow);
    script(&tls, "deep.rn", deep);

    let mut config = format!("{}\n", base_config(&tls, bmc));
    for (path, name) in [
        ("/redfish/v1/Systems/*", "shallow.rn"),
        ("/redfish/v1/Systems/*/SecureBoot", "deep.rn"),
    ] {
        let _ = write!(
            config,
            "\n        [[route]]\n        path   = \"{path}\"\n        script = \"{name}\"\n"
        );
    }
    let proxy = start_proxy(&tls, &config);

    let who = |path: &'static str| {
        let url = format!("https://{}{path}", proxy.addr);
        async move {
            client()
                .get(url)
                .send()
                .await
                .expect("request")
                .json::<serde_json::Value>()
                .await
                .expect("json")["who"]
                .as_str()
                .expect("who")
                .to_string()
        }
    };

    assert_eq!(who("/redfish/v1/Systems/Sys-1").await, "shallow");
    // The shallow route is declared first, so order alone would give it this.
    assert_eq!(who("/redfish/v1/Systems/Sys-1/SecureBoot").await, "deep");
}

#[tokio::test]
async fn an_empty_method_list_matches_every_method() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(
        &tls,
        &rune_config(
            &tls,
            bmc,
            "any.rn",
            "pub async fn handle(req) { resp::text(200, req.method) }",
        ),
    );

    for method in ["GET", "DELETE"] {
        let got = client()
            .request(
                method.parse().unwrap(),
                format!("https://{}/redfish/v1/Chassis/1", proxy.addr),
            )
            .send()
            .await
            .expect("request")
            .text()
            .await
            .expect("body");
        assert_eq!(got, method);
    }
    assert_eq!(seen.count(), 0);
}

#[tokio::test]
async fn the_most_specific_route_wins_regardless_of_order() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    script(
        &tls,
        "broad.rn",
        "pub async fn handle(req) { resp::text(200, \"broad\") }",
    );
    script(
        &tls,
        "exact.rn",
        "pub async fn handle(req) { resp::text(200, \"exact\") }",
    );

    // The broad rule is declared first and must still lose.
    let config = format!(
        r#"{base}
        [[route]]
        path   = "/redfish/**"
        script = "broad.rn"

        [[route]]
        path   = "/redfish/v1/Chassis/Thermal"
        script = "exact.rn"
        "#,
        base = base_config(&tls, bmc),
    );
    let proxy = start_proxy(&tls, &config);

    let got = client()
        .get(format!("https://{}/redfish/v1/Chassis/Thermal", proxy.addr))
        .send()
        .await
        .expect("request")
        .text()
        .await
        .expect("body");
    assert_eq!(got, "exact");
}

#[tokio::test]
async fn two_scripts_may_share_an_entry_point_name() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    script(
        &tls,
        "one.rn",
        "pub async fn handle(req) { resp::text(200, \"one\") }",
    );
    script(
        &tls,
        "two.rn",
        "pub async fn handle(req) { resp::text(200, \"two\") }",
    );

    // Rune inserts every source at the root, so a shared unit would collide.
    let config = format!(
        r#"{base}
        [[route]]
        path   = "/redfish/v1/Chassis/One"
        script = "one.rn"

        [[route]]
        path   = "/redfish/v1/Chassis/Two"
        script = "two.rn"
        "#,
        base = base_config(&tls, bmc),
    );
    let proxy = start_proxy(&tls, &config);

    for (path, want) in [("One", "one"), ("Two", "two")] {
        let got = client()
            .get(format!("https://{}/redfish/v1/Chassis/{path}", proxy.addr))
            .send()
            .await
            .expect("request")
            .text()
            .await
            .expect("body");
        assert_eq!(got, want, "{path} ran the wrong script");
    }
}

#[tokio::test]
async fn unregistered_paths_never_touch_the_script_engine() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "thermal.rn", THERMAL));

    let response = client()
        .get(format!("https://{}/redfish/v1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);
    assert_eq!(seen.count(), 1, "a pass-through made more than one call");
    assert!(!response.text().await.unwrap().contains("ProxiedBy"));
}

// Script execution, meaning what a handler sees and returns.

#[tokio::test]
async fn a_bare_result_in_a_response_is_reported_not_silently_dropped() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // Rune serialises an Option transparently but has no representation for a
    // Result, so one left in a body is a mistake worth a clear failure.
    let handler = r#"
        pub async fn handle(req) {
            resp::json(200, #{"leftover": Ok(3).map(|n| n + 1)})
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "leftover.rn", handler));

    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 500);
    let body: serde_json::Value = response.json().await.expect("json");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not serialisable"),
        "{body}"
    );
}

#[tokio::test]
async fn a_failing_script_returns_502_rather_than_unmangled_data() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(
        &tls,
        &rune_config(
            &tls,
            bmc,
            "boom.rn",
            "pub async fn handle(req) { Err(\"deliberate\") }",
        ),
    );

    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");

    // Falling back to a direct proxy would return unmangled data with a 200.
    assert_eq!(response.status(), 502);
    assert!(!response.text().await.unwrap().contains("\"Id\":\"1\""));
}

#[tokio::test]
async fn a_handler_can_return_each_response_shape() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            if req.query == "shape=text" {
                return resp::text(201, "plain body").with_header("x-shape", "text");
            }
            if req.query == "shape=status" {
                return resp::status(204);
            }
            resp::json(200, #{"shape": "json"})
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "shapes.rn", handler));
    let base = format!("https://{}/redfish/v1/Chassis/1", proxy.addr);

    let text = client()
        .get(format!("{base}?shape=text"))
        .send()
        .await
        .expect("request");
    assert_eq!(text.status(), 201);
    assert_eq!(text.headers()["x-shape"], "text");
    assert_eq!(text.headers()["content-type"], "text/plain; charset=utf-8");
    assert_eq!(text.text().await.expect("body"), "plain body");

    let empty = client()
        .get(format!("{base}?shape=status"))
        .send()
        .await
        .expect("request");
    assert_eq!(empty.status(), 204);
    assert!(empty.text().await.expect("body").is_empty());

    let json = client().get(&base).send().await.expect("request");
    assert_eq!(json.status(), 200);
    assert_eq!(json.headers()["content-type"], "application/json");
    let body: serde_json::Value = json.json().await.expect("json");
    assert_eq!(body["shape"], "json");
}

#[tokio::test]
async fn a_handler_sees_every_part_of_the_request() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            resp::json(200, #{
                "method": req.method,
                "path": req.path,
                "query": req.query,
                "text": req.text()?,
                "name": req.json()?["Name"],
                "headers": req.header_names(),
                "note": req.header("x-note"),
                "address": bmc::address()?,
                "external_base": bmc::external_base()?,
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "parts.rn", handler));

    let body: serde_json::Value = client()
        .put(format!(
            "https://{}/redfish/v1/Chassis/1?select=Name&expand=.",
            proxy.addr
        ))
        .basic_auth("root", Some("calvin"))
        .header("x-note", "kept")
        .json(&serde_json::json!({"Name": "bay-3"}))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    assert_eq!(body["method"], "PUT");
    assert_eq!(body["path"], "/redfish/v1/Chassis/1");
    assert_eq!(body["query"], "select=Name&expand=.");
    assert_eq!(body["text"], r#"{"Name":"bay-3"}"#);
    assert_eq!(body["name"], "bay-3");
    assert_eq!(body["note"], "kept");

    // The two sides of rewriting, both readable and neither steerable.
    assert_eq!(body["address"], bmc.to_string());
    assert_eq!(body["external_base"], PROXY_BASE);

    // Sorted, and the credential is filtered out before the script sees it.
    let names: Vec<&str> = body["headers"]
        .as_array()
        .expect("header_names is a list")
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert!(names.contains(&"x-note"), "{names:?}");
    assert!(names.contains(&"content-type"), "{names:?}");
    assert!(
        !names.contains(&"authorization"),
        "the credential was listed to the script: {names:?}"
    );
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "header_names should be sorted");
}

#[tokio::test]
async fn a_handler_that_returns_the_wrong_shape_is_reported() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // Rune has no type to stop this, so the host has to say what happened. The
    // message is the only guidance a script author gets.
    let handler = r"
        pub async fn handle(req) {
            42
        }
    ";
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "wrong.rn", handler));

    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 502);

    let body: serde_json::Value = response.json().await.expect("json");
    let message = body["error"]["message"].as_str().expect("a message");
    assert!(message.contains("resp::"), "unhelpful message: {message}");
}

#[tokio::test]
async fn a_panicking_script_fails_its_request_and_leaves_the_proxy_serving() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            if req.query == "boom" {
                panic!("deliberate");
            }
            resp::text(200, "fine")
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "panic.rn", handler));
    let url = format!("https://{}/redfish/v1/Chassis/1", proxy.addr);

    let boom = client()
        .get(format!("{url}?boom"))
        .send()
        .await
        .expect("request");
    assert_eq!(boom.status(), 502);

    // A panic is contained to its own request. If it took the worker or the
    // process with it, this second request would never be answered.
    let after = client().get(&url).send().await.expect("request");
    assert_eq!(after.status(), 200);
    assert_eq!(after.text().await.expect("body"), "fine");
}

#[tokio::test]
async fn a_script_cannot_forge_a_credential_on_its_own_response() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // A separate guard from the one on a subrequest. This one is on the way
    // back, where a forged header would reach the caller.
    let handler = r#"
        pub async fn handle(req) {
            resp::json(200, #{"ok": true})
                .with_header("x-auth-token", "forged-token")
                .with_header("authorization", "Basic forged")
                .with_header("connection", "close")
                .with_header("x-fine", "kept")
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "forgeresp.rn", handler));

    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    let headers = response.headers().clone();
    for forbidden in ["x-auth-token", "authorization", "connection"] {
        assert!(
            !headers.contains_key(forbidden),
            "{forbidden} reached the caller"
        );
    }
    // An ordinary header the script set is still served, so the filter is not
    // simply dropping everything.
    assert_eq!(headers["x-fine"], "kept");

    let logs = proxy.wait_for_log("forbidden header");
    assert!(logs.contains("x-auth-token"), "{logs}");
}

#[tokio::test]
async fn a_script_never_sees_a_credential() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            let auth = req.header("authorization");
            let seen = if auth is Option && auth.is_some() { "leaked" } else { "hidden" };
            resp::json(200, #{"auth": seen, "odata": req.header("odata-version")})
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "peek.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .basic_auth("root", Some("calvin"))
        .header("odata-version", "4.0")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // A script that could read the credential could echo it into a response.
    assert_eq!(body["auth"], "hidden");
    assert_eq!(body["odata"], "4.0", "non-credential headers stay visible");
}

#[tokio::test]
async fn a_scripts_bmc_call_is_bounded_by_the_target_timeout() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    script(
        &tls,
        "slow.rn",
        "pub async fn handle(req) { let r = bmc::get(\"/redfish/v1/Slow\").await?; resp::text(200, \"never\") }",
    );
    let config = format!(
        r#"{base}
        [[route]]
        path   = "/redfish/v1/Chassis/*"
        script = "slow.rn"
        "#,
        base = config_with(&tls, bmc, "timeout = \"1s\""),
    );
    let proxy = start_proxy(&tls, &config);

    // A handler has no deadline of its own, so what stops this is the upstream
    // client timeout on the subrequest, surfacing as a failed handler.
    let response = tokio::time::timeout(
        Duration::from_secs(20),
        client()
            .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
            .send(),
    )
    .await
    .expect("the proxy hung")
    .expect("request");
    assert_eq!(response.status(), 502);
}

#[tokio::test]
async fn an_out_of_range_status_from_a_script_becomes_500() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(
        &tls,
        &rune_config(
            &tls,
            bmc,
            "odd.rn",
            "pub async fn handle(req) { resp::status(9999) }",
        ),
    );

    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 500);
}

// The script HTTP surface, `bmc::*`.

#[tokio::test]
async fn a_built_request_cannot_forge_auth_or_leave_the_target() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            let refused = [];
            for name in ["authorization", "x-auth-token", "proxy-authorization",
                         "cookie", "host", "content-length", "transfer-encoding"] {
                let attempt = bmc::request("GET", "/redfish/v1/Echo")?.header(name, "forged");
                refused.push(match attempt { Ok(_) => "allowed", Err(_) => "refused" });
            }

            // The path check is the builder's too, not just the helpers'.
            let elsewhere = match bmc::request("GET", "https://198.51.100.9/x") {
                Ok(_) => "allowed",
                Err(_) => "refused",
            };

            // A request that does go out still carries the real credential.
            let sent = bmc::request("GET", "/redfish/v1/Echo")?
                .header("x-note", "fine")?
                .send()
                .await?;

            resp::json(200, #{
                "refused": refused,
                "elsewhere": elsewhere,
                "sent": sent.status(),
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "forge.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .basic_auth("root", Some("calvin"))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // Auth, framing and routing headers are all the proxy's to set.
    assert_eq!(body["refused"], serde_json::json!(vec!["refused"; 7]));
    assert_eq!(body["elsewhere"], "refused");
    assert_eq!(body["sent"], 200);

    let sent = seen
        .all()
        .into_iter()
        .find(|c| c.path == "/redfish/v1/Echo")
        .expect("the subrequest was never made");
    // The caller's real credential, relayed by Rust, and not the forged one.
    assert_eq!(sent.header("authorization"), Some("Basic cm9vdDpjYWx2aW4="));
    assert_eq!(sent.header("x-note"), Some("fine"));
    assert_eq!(sent.header("host"), Some(bmc.to_string().as_str()));
}

#[tokio::test]
async fn a_forwarded_request_cannot_leave_the_target_or_forge_auth() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    // `forward_with` is a second way to reach the network. Its path is refused
    // when the request is built, and its credential is applied in `dispatch`.
    let handler = r#"
        pub async fn handle(req) {
            let refused = [];
            for path in ["https://198.51.100.9/x", "//198.51.100.9/x", "redfish/v1"] {
                refused.push(match bmc::request("GET", path) {
                    Ok(_) => "allowed",
                    Err(_) => "refused",
                });
            }

            let forged = match bmc::request("GET", "/redfish/v1/Echo")?
                .header("authorization", "forged")
            {
                Ok(_) => "allowed",
                Err(_) => "refused",
            };

            let built = bmc::request("GET", "/redfish/v1/Echo")?.header("x-note", "fine")?;
            let out = bmc::forward_with(built).await?;

            resp::json(200, #{
                "refused": refused,
                "forged": forged,
                "status": out.status(),
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "fwdguard.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .basic_auth("root", Some("calvin"))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    assert_eq!(body["refused"], serde_json::json!(vec!["refused"; 3]));
    assert_eq!(body["forged"], "refused");
    assert_eq!(body["status"], 200);

    let sent = seen
        .all()
        .into_iter()
        .find(|c| c.path == "/redfish/v1/Echo")
        .expect("the forwarded request was never made");
    // The caller's real credential, applied by Rust after the script's headers.
    assert_eq!(sent.header("authorization"), Some("Basic cm9vdDpjYWx2aW4="));
    assert_eq!(sent.header("x-note"), Some("fine"));
    assert_eq!(sent.header("host"), Some(bmc.to_string().as_str()));
}

#[tokio::test]
async fn a_handler_can_buffer_a_streaming_reply_and_read_it() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // XML is not JSON, so it arrives streaming. A handler that knows the body is
    // finite can pull it in, which nothing does on its behalf.
    let handler = r#"
        pub async fn handle(req) {
            let f = bmc::forward().await?;
            let before = f.streaming();
            let ok = f.ok();
            let f = f.buffer().await?;
            resp::json(200, #{
                "ok": ok,
                "before": before,
                "after": f.streaming(),
                "is_json": f.is_json(),
                "content_type": f.content_type(),
                "text": f.text()?,
            })
        }
    "#;
    let proxy = start_proxy(
        &tls,
        &route_config(&tls, bmc, "buffer.rn", handler, "/redfish/v1/$metadata", ""),
    );

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/$metadata", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    assert_eq!(body["ok"], true);
    assert_eq!(body["before"], true);
    assert_eq!(body["after"], false, "buffer did not convert the body");
    assert_eq!(body["is_json"], false);
    assert_eq!(body["content_type"], "application/xml");
    assert!(
        body["text"].as_str().expect("text").contains("edmx:Edmx"),
        "the body was not readable after buffering"
    );
}

#[tokio::test]
async fn a_handler_can_forward_a_request_it_modified() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    // The inbound request, patched and relayed. A body the script never built is
    // carried over rather than reconstructed.
    let handler = r#"
        pub async fn handle(req) {
            let doc = req.json()?;
            doc["Added"] = "by-the-script";
            let out = bmc::inbound()?.path("/redfish/v1/Echo")?.json(doc)?;
            let reply = bmc::forward_with(out).await?;
            resp::json(200, reply.json()?)
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "modify.rn", handler));

    let body: serde_json::Value = client()
        .post(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .header("content-type", "application/json")
        .header("odata-version", "4.0")
        .body(r#"{"Original":true}"#)
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // The fixture echoes what reached it, so this is the wire and not the intent.
    assert_eq!(body["SawMethod"], "POST");
    assert_eq!(body["SawBody"]["Original"], true);
    assert_eq!(body["SawBody"]["Added"], "by-the-script");

    let sent = seen
        .all()
        .into_iter()
        .find(|c| c.path == "/redfish/v1/Echo")
        .expect("the modified request was never made");
    // Seeded from the inbound request, so its headers came across with it.
    assert_eq!(sent.header("odata-version"), Some("4.0"));
}

#[tokio::test]
async fn a_handler_can_stream_a_reply_to_a_request_it_built() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // The combination `.send()` cannot reach, being a request the script built
    // whose reply is handed on without ever being held.
    let handler = r#"
        pub async fn handle(req) {
            let out = bmc::request("GET", "/redfish/v1/EventService/SSE")?;
            let f = bmc::forward_with(out).await?;
            if !f.streaming() {
                return resp::text(500, "the reply was buffered");
            }
            f.rewrite()
        }
    "#;
    let proxy = start_proxy(
        &tls,
        &route_config(&tls, bmc, "stream.rn", handler, "/redfish/v1/Stream", ""),
    );

    let started = std::time::Instant::now();
    let response = client()
        .get(format!("https://{}/redfish/v1/Stream", proxy.addr))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    // The fixture holds the stream for 30 seconds, so returning at all is what
    // proves nothing waited for the whole body.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the reply was buffered rather than streamed"
    );
}

#[tokio::test]
async fn a_handler_can_tell_a_streaming_body_from_a_buffered_one() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // Only JSON is buffered, so `.json()` is a mistake on anything else. A
    // handler asks first rather than finding out through an error.
    let handler = r#"
        pub async fn handle(req) {
            let doc = bmc::forward().await?;
            resp::json(200, #{"streaming": doc.streaming(), "id": doc.json()?["Id"]})
        }
    "#;
    let proxy = start_proxy(
        &tls,
        &route_config(&tls, bmc, "buf.rn", handler, "/redfish/v1/Chassis/1", ""),
    );
    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(body["streaming"], false);
    assert_eq!(body["id"], "1");

    // The SSE path is the other side of it, and must not be parseable.
    let sse = r#"
        pub async fn handle(req) {
            let event = bmc::forward().await?;
            resp::json(200, #{
                "streaming": event.streaming(),
                "no_body": event.json().is_err(),
                "no_text": event.text().is_err(),
            })
        }
    "#;
    let proxy = start_proxy(
        &tls,
        &route_config(&tls, bmc, "sse.rn", sse, "/redfish/v1/EventService/SSE", ""),
    );
    let body: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/EventService/SSE",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(body["streaming"], true);
    assert_eq!(body["no_body"], true, "a streaming body must not parse");
    assert_eq!(body["no_text"], true, "nor should it read as text");
}

#[tokio::test]
async fn a_script_cannot_leave_the_resolved_target() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            match bmc::get("https://198.51.100.1/redfish/v1").await {
                Ok(r)  => resp::text(200, "escaped"),
                Err(e) => resp::text(200, "refused"),
            }
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "escape.rn", handler));

    let body = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .text()
        .await
        .expect("body");

    assert_eq!(body, "refused", "a script left the configured target");
    assert_eq!(seen.count(), 0);
}

#[tokio::test]
async fn a_script_cannot_reach_another_host_with_any_verb() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    // Every verb takes the same path check, so a hole in one is a hole in all.
    let handler = r#"
        pub async fn handle(req) {
            let tried = [];
            for attempt in [
                bmc::get("https://198.51.100.9/redfish/v1").await,
                bmc::delete("//198.51.100.9/redfish/v1").await,
                bmc::post("https://198.51.100.9/x", #{}).await,
                bmc::put("redfish/v1/Echo", #{}).await,
                bmc::patch("https://198.51.100.9/x", #{}).await,
            ] {
                tried.push(match attempt { Ok(_) => "allowed", Err(_) => "refused" });
            }
            resp::json(200, #{"tried": tried})
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "escape.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // Every shape is refused, `//host/path` included. That one begins with '/'
    // and would have kept the target anyway, but guessing is not a guarantee.
    assert_eq!(
        body["tried"],
        serde_json::json!(["refused", "refused", "refused", "refused", "refused"])
    );
    assert!(
        !seen.all().iter().any(|c| c.path.contains("198.51.100.9")),
        "a subrequest carried a foreign host into the target"
    );
}

#[tokio::test]
async fn a_script_chooses_the_accept_on_its_own_subrequest() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    // `accept` is content negotiation, not a credential, so relaying the
    // caller's would overwrite what the script asked for and break `get_json`.
    let handler = r#"
        pub async fn handle(req) {
            let out = bmc::request("GET", "/redfish/v1/Echo")?
                .header("accept", "application/json")?;
            resp::json(200, out.send().await?.status())
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "acc.rn", handler));

    client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .header("accept", "text/html")
        .send()
        .await
        .expect("request");

    let sent = seen
        .all()
        .into_iter()
        .find(|c| c.path == "/redfish/v1/Echo")
        .expect("the subrequest was never made");
    assert_eq!(sent.header("accept"), Some("application/json"));
}

#[tokio::test]
async fn an_expanded_collection_costs_one_request_when_the_bmc_obliges() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            let jobs = bmc::expand_collection(
                "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs").await?;
            resp::json(200, jobs)
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "jobs.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // This collection honours `$expand`, so the members arrive already filled.
    assert_eq!(body["Members"][0]["JobState"], "Scheduled");
    assert_eq!(
        seen.count(),
        1,
        "an honoured $expand should not be followed by per-member fetches"
    );
}

#[tokio::test]
async fn an_inbound_request_carries_one_content_type() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    // `bmc::inbound` seeds the header map from the request and also sets
    // `content_type`, and reqwest's builder appends rather than replaces.
    let handler = r#"
        pub async fn handle(req) {
            let out = bmc::inbound()?.path("/redfish/v1/Echo")?;
            resp::json(200, bmc::forward_with(out).await?.json()?)
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "ct.rn", handler));

    let response = client()
        .patch(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .header("content-type", "application/json")
        .body(r#"{"a":1}"#)
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    let sent = seen
        .all()
        .into_iter()
        .find(|c| c.path == "/redfish/v1/Echo")
        .expect("the subrequest was never made");
    assert_eq!(
        sent.header_count("content-type"),
        1,
        "RFC 9110 forbids a repeated Content-Type, and BMC firmware rejects it"
    );
}

#[tokio::test]
async fn content_type_and_is_json_agree_in_both_directions() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // The predicates read what was declared, on the request the caller sent and
    // on the reply the BMC gave, which is what a handler branches on.
    let handler = r#"
        pub async fn handle(req) {
            let reply = bmc::get("/redfish/v1/Chassis/1").await?;
            resp::json(200, #{
                "req_type": req.content_type(),
                "req_json": req.is_json(),
                "resp_type": reply.content_type(),
                "resp_json": reply.is_json(),
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "types.rn", handler));
    let url = format!("https://{}/redfish/v1/Chassis/1", proxy.addr);

    let json: serde_json::Value = client()
        .post(&url)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(json["req_json"], true);
    assert_eq!(json["resp_json"], true);
    assert_eq!(json["resp_type"], "application/json");

    // Non-JSON up against a JSON reply, which is the mixed case the helpers
    // exist to let a handler notice.
    let mixed: serde_json::Value = client()
        .post(&url)
        .header("content-type", "application/octet-stream")
        .body(vec![0u8, 1, 2])
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(mixed["req_type"], "application/octet-stream");
    assert_eq!(mixed["req_json"], false);
    assert_eq!(
        mixed["resp_json"], true,
        "the reply is JSON whatever went up"
    );
}

#[tokio::test]
async fn every_http_verb_is_callable_from_a_script() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            let created = bmc::post("/redfish/v1/Echo", #{"Verb": "post"}).await?;
            let replaced = bmc::put("/redfish/v1/Echo", #{"Verb": "put"}).await?;
            let merged = bmc::patch("/redfish/v1/Echo", #{"Verb": "patch"}).await?;
            let removed = bmc::delete("/redfish/v1/Echo").await?;
            resp::json(200, #{
                "post": created.json()?["SawMethod"],
                "put": replaced.json()?["SawMethod"],
                "patch": merged.json()?["SawMethod"],
                "delete": removed.json()?["SawMethod"],
                "post_body": created.json()?["SawBody"]["Verb"],
                "put_body": replaced.json()?["SawBody"]["Verb"],
                "patch_body": merged.json()?["SawBody"]["Verb"],
                "status": created.status(),
                "ok": created.ok(),
                "content_type": created.header("content-type"),
                "raw_text_is_json": removed.text()?.starts_with("{"),
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "verbs.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // The BMC saw each verb as itself, not all of them as GET.
    assert_eq!(body["post"], "POST");
    assert_eq!(body["put"], "PUT");
    assert_eq!(body["patch"], "PATCH");
    assert_eq!(body["delete"], "DELETE");

    // And each body arrived intact, so the value crossed into JSON correctly.
    assert_eq!(body["post_body"], "post");
    assert_eq!(body["put_body"], "put");
    assert_eq!(body["patch_body"], "patch");

    assert_eq!(body["status"], 200);
    assert_eq!(body["ok"], true);
    assert_eq!(body["content_type"], "application/json");
    assert_eq!(body["raw_text_is_json"], true);

    let calls: Vec<_> = seen
        .all()
        .into_iter()
        .filter(|r| r.path == "/redfish/v1/Echo")
        .collect();
    let verbs: Vec<&str> = calls.iter().map(|r| r.method.as_str()).collect();
    assert_eq!(verbs, ["POST", "PUT", "PATCH", "DELETE"]);

    for call in &calls {
        assert_eq!(
            call.header("authorization"),
            None,
            "no credential was sent, but one appeared"
        );
        if call.method == "DELETE" {
            // No body, so no content type should be invented for it.
            assert_eq!(call.body_len, 0);
            assert_eq!(call.header("content-type"), None);
        } else {
            assert_eq!(call.header("content-type"), Some("application/json"));
            assert!(call.body_len > 0, "{call:?} carried no body");
        }
    }
}

#[tokio::test]
async fn the_builder_sends_json_with_a_header_the_verbs_cannot_carry() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            // The only way to send a JSON body and a header together, since
            // bmc::post carries no headers.
            let tagged = bmc::request("POST", "/redfish/v1/Echo")?
                .json(#{"Name": "bay-3"})?
                .header("odata-version", "4.0")?
                .send()
                .await?;

            // An explicit type wins whichever side of the body it is set on.
            let after = bmc::request("PATCH", "/redfish/v1/Echo")?
                .json(#{"Name": "bay-4"})?
                .content_type("application/merge-patch+json")
                .send()
                .await?;
            let before = bmc::request("PUT", "/redfish/v1/Echo")?
                .content_type("application/merge-patch+json")
                .json(#{"Name": "bay-5"})?
                .send()
                .await?;

            resp::json(200, #{
                "tagged": tagged.json()?["SawBody"]["Name"],
                "after": after.json()?["SawBody"]["Name"],
                "before": before.json()?["SawBody"]["Name"],
                "status": tagged.status(),
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "jsonbuild.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .basic_auth("root", Some("calvin"))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // Every body round-tripped as JSON rather than as a quoted string.
    assert_eq!(body["tagged"], "bay-3");
    assert_eq!(body["after"], "bay-4");
    assert_eq!(body["before"], "bay-5");
    assert_eq!(body["status"], 200);

    let call = |method: &str| {
        seen.all()
            .into_iter()
            .find(|c| c.method == method && c.path == "/redfish/v1/Echo")
            .unwrap_or_else(|| panic!("no {method} reached the BMC"))
    };

    // `.json` defaults the type, and the header rides along with it.
    let tagged = call("POST");
    assert_eq!(tagged.header("content-type"), Some("application/json"));
    assert_eq!(tagged.header("odata-version"), Some("4.0"));
    assert_eq!(
        tagged.header("authorization"),
        Some("Basic cm9vdDpjYWx2aW4="),
        "the relayed credential went missing on a built request"
    );

    // Set after the body, and set before it, both keep the explicit type. The
    // second is what `get_or_insert` buys, since a plain assign would lose it.
    for method in ["PATCH", "PUT"] {
        assert_eq!(
            call(method).header("content-type"),
            Some("application/merge-patch+json"),
            "{method} lost the content type the script asked for"
        );
    }
}

#[tokio::test]
async fn the_request_builder_reaches_past_the_verb_helpers() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    // A firmware push is the case the five verb helpers cannot express, since
    // they JSON-encode every body and force `application/json`.
    let handler = r#"
        pub async fn handle(req) {
            let image = bmc::request("POST", "/redfish/v1/Echo")?
                .base64(util::b64_encode("MZ\u{0000}binary"))?
                .header("odata-version", "4.0")?
                .send()
                .await?;

            let probed = bmc::request("HEAD", "/redfish/v1/Chassis/1")?.send().await?;

            let typed = bmc::request("PUT", "/redfish/v1/Echo")?
                .text("Name=bay-3")
                .content_type("application/x-www-form-urlencoded")
                .send()
                .await?;

            resp::json(200, #{
                "image_status": image.status(),
                "head_status": probed.status(),
                "head_body_empty": probed.text()?.is_empty(),
                "typed_status": typed.status(),
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "builder.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(body["image_status"], 200);
    assert_eq!(body["head_status"], 200);
    assert_eq!(body["head_body_empty"], true);
    assert_eq!(body["typed_status"], 200);

    let calls = seen.all();
    let posted = calls.iter().find(|c| c.method == "POST").expect("post");
    // Raw bytes, not a JSON string, and the script chose the type.
    assert_eq!(
        posted.header("content-type"),
        Some("application/octet-stream")
    );
    assert_eq!(posted.body_len, 9);
    assert_eq!(posted.header("odata-version"), Some("4.0"));

    assert!(calls.iter().any(|c| c.method == "HEAD"), "{calls:?}");

    let put = calls.iter().find(|c| c.method == "PUT").expect("put");
    assert_eq!(
        put.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(put.body_len, 10);
}

#[tokio::test]
async fn the_system_and_manager_are_resolved_by_probing_for_bios() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            let first = bmc::system_id().await?;
            // Asked twice on purpose, to prove the walk is not repeated.
            let again = bmc::system_id().await?;
            resp::json(200, #{
                "system": first,
                "again": again,
                "manager": bmc::manager_id().await?,
                "address": bmc::address()?,
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "ids.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // HGX_Baseboard_0 enumerates first and has no Bios, so it must lose.
    assert_eq!(body["system"], "Sys-1");
    assert_eq!(body["again"], "Sys-1");
    // BMC-Other is the first manager, but Links.ManagedBy names the real one.
    assert_eq!(body["manager"], "iDRAC.Embedded.1");
    assert_eq!(body["address"], bmc.to_string());

    let walks = seen
        .all()
        .iter()
        .filter(|r| r.path == "/redfish/v1/Systems")
        .count();
    assert_eq!(walks, 1, "the service root was walked once per call");
    assert!(
        !seen.all().iter().any(|r| r.path == "/redfish/v1/Managers"),
        "the managers collection was fetched despite Links.ManagedBy"
    );
}

// The script helpers, `util::*`.

#[tokio::test]
async fn a_bounded_store_refuses_a_key_too_many() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            let stored = 0;
            let refused = "none";
            for i in 0..1100 {
                match store::set(`key-${i}`, i) {
                    Ok(_) => { stored += 1; }
                    Err(error) => { refused = error; break; }
                }
            }
            // A key already held stays writable once the store is full, so a
            // store at capacity still serves what it has.
            let overwrite = match store::set("key-0", "again") {
                Ok(_) => "ok",
                Err(error) => error,
            };
            resp::json(200, #{
                "stored": stored,
                "refused": refused,
                "overwrite": overwrite,
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "bounded.rn", handler));
    let body = store_get(&proxy, "").await;

    assert_eq!(body["stored"], 1024);
    assert!(
        body["refused"].as_str().unwrap().contains("1024 keys"),
        "the store grew past its limit: {}",
        body["refused"]
    );
    assert_eq!(body["overwrite"], "ok");
}

#[tokio::test]
async fn a_deep_read_answers_none_rather_than_failing() {
    let body = run_script(
        "at.rn",
        r#"
        pub async fn handle(req) {
            let doc = #{"Links": #{"ManagedBy": [#{"@odata.id": "/redfish/v1/Managers/BMC"}]}};
            resp::json(200, #{
                "through_array": util::at(doc, "Links/ManagedBy/0/@odata.id")?,
                "missing_key": util::at(doc, "Links/Nope")?.is_none(),
                "missing_deep": util::at(doc, "a/b/c/d")?.is_none(),
                "past_the_end": util::at(doc, "Links/ManagedBy/7")?.is_none(),
                "whole_node": util::at(doc, "Links")?.is_some(),
            })
        }
    "#,
    )
    .await;

    assert_eq!(body["through_array"], "/redfish/v1/Managers/BMC");
    // Indexing would fail the request here. The point of `at` is that it does not.
    for absent in ["missing_key", "missing_deep", "past_the_end"] {
        assert_eq!(body[absent], true, "{absent}");
    }
    assert_eq!(body["whole_node"], true);
}

#[tokio::test]
async fn a_deep_write_creates_the_objects_along_the_way() {
    let body = run_script(
        "set.rn",
        r#"
        pub async fn handle(req) {
            let out = #{"Id": "1"};

            // Indexing this would fail with `Missing field Oem`, which is the
            // whole reason util::set exists.
            let out = util::set(out, "Oem/Vendor/Fans", 3)?;
            let out = util::set(out, "Id", "2")?;
            let deep = util::set(#{"a": [#{"b": 1}]}, "a/0/b", 9)?;

            resp::json(200, #{
                "created": util::at(out, "Oem/Vendor/Fans")?,
                "kept": out["Id"],
                "into_array": util::at(deep, "a/0/b")?,
                // The ways a deep write cannot land, each an error rather than
                // a silent no-op that leaves the caller guessing.
                "empty": match util::set(out, "", 1) { Ok(_) => "ok", Err(_) => "refused" },
                "past": match util::set(#{"a": []}, "a/7/b", 1) { Ok(_) => "ok", Err(_) => "refused" },
                // Writing through a scalar replaces it rather than failing,
                // which is the autovivify this helper exists for.
                "through": util::at(util::set(#{"a": 1}, "a/b", 2)?, "a/b")?,
                "bad_link": match bmc::path_of("not a url or path") { Ok(_) => "ok", Err(_) => "refused" },
                // Overwriting a slot that exists, rather than creating one.
                "slot": util::at(util::set(#{"a": [1, 2]}, "a/1", 9)?, "a/1")?,
                // Merging an object over a scalar replaces it wholesale.
                "over_scalar": util::at(util::json_merge_patch(#{"a": 1}, #{"a": #{"b": 2}})?, "a/b")?,
            })
        }
    "#,
    )
    .await;

    assert_eq!(body["created"], 3);
    assert_eq!(body["kept"], "2");
    assert_eq!(body["into_array"], 9);
    for key in ["empty", "past", "bad_link"] {
        assert_eq!(body[key], "refused", "{key} should not have succeeded");
    }
    assert_eq!(body["through"], 2);
    assert_eq!(body["slot"], 9);
    assert_eq!(body["over_scalar"], 2);
}

#[tokio::test]
async fn a_handler_can_rewrite_links_in_a_body_it_assembled() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // A body the handler built itself, holding a BMC-absolute URL it did not
    // get from a response, so nothing else would fix it.
    let handler = r#"
        pub async fn handle(req) {
            let built = #{"Link": `https://${bmc::address()?}/redfish/v1/Made/Up`};
            resp::json(200, util::rewrite_links(built)?)
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "links.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    assert_eq!(body["Link"], format!("{PROXY_BASE}/redfish/v1/Made/Up"));
    assert!(!body["Link"].as_str().unwrap().contains(&bmc.to_string()));
}

#[tokio::test]
async fn a_handler_can_rewrite_links_in_a_text_body() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // XML carries absolute URLs and no JSON rewrite will ever reach it, so this
    // is all that stands between `$metadata` and a leaked BMC address.
    let handler = r#"
        pub async fn handle(req) {
            let f = bmc::forward().await?.buffer().await?;
            let fixed = util::rewrite_links_text(f.text()?)?;
            resp::json(200, #{
                "is_json": f.is_json(),
                "parses": f.json().is_ok(),
                "xml": fixed,
            })
        }
    "#;
    let proxy = start_proxy(
        &tls,
        &route_config(&tls, bmc, "meta.rn", handler, "/redfish/v1/$metadata", ""),
    );

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/$metadata", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // XML stays on the non-JSON side of the widened predicate. A suffix rule
    // written as a substring rule would have put it on the wrong one.
    assert_eq!(body["is_json"], false);
    assert_eq!(body["parses"], false);

    let xml = body["xml"].as_str().expect("xml");
    assert!(xml.contains(PROXY_BASE), "not rewritten: {xml}");
    assert!(!xml.contains(&bmc.to_string()), "leaked the BMC: {xml}");
}

#[tokio::test]
async fn a_json_patch_applies_every_operation() {
    let body = run_script(
        "patch.rn",
        r#"
        pub async fn handle(req) {
            let doc = #{
                "Keep": 1,
                "Drop": 2,
                "Old": "here",
                "Copy": #{"deep": true},
                "List": ["a", "b", "c"],
            };
            let patched = util::json_patch(doc, [
                #{ "op": "test",    "path": "/Keep", "value": 1 },
                #{ "op": "remove",  "path": "/Drop" },
                #{ "op": "replace", "path": "/Keep", "value": 9 },
                #{ "op": "move",    "from": "/Old", "path": "/New" },
                #{ "op": "copy",    "from": "/Copy", "path": "/Copied" },
                #{ "op": "add",     "path": "/List/1", "value": "inserted" },
                #{ "op": "remove",  "path": "/List/0" },
            ])?;
            resp::json(200, patched)
        }
    "#,
    )
    .await;

    assert_eq!(body["Keep"], 9);
    assert!(body.get("Drop").is_none(), "remove did nothing: {body}");
    // A move leaves nothing behind, unlike a copy.
    assert_eq!(body["New"], "here");
    assert!(body.get("Old").is_none(), "move left the source: {body}");
    assert_eq!(body["Copied"]["deep"], true);
    assert_eq!(
        body["Copy"]["deep"], true,
        "copy removed the source: {body}"
    );
    assert_eq!(
        body["List"],
        serde_json::json!(["inserted", "b", "c"]),
        "{body}"
    );
}

#[tokio::test]
async fn a_json_patch_distinguishes_adding_to_an_object_from_an_array() {
    let body = run_script(
        "add.rn",
        r#"
        pub async fn handle(req) {
            let doc = #{"Obj": #{"a": 1}, "Arr": ["x", "z"]};
            let outcome = |ops| match util::json_patch(doc, ops) {
                Ok(value) => value,
                Err(error) => error,
            };
            resp::json(200, #{
                "over_key":  outcome([#{ "op": "add", "path": "/Obj/a", "value": 2 }]),
                "new_key":   outcome([#{ "op": "add", "path": "/Obj/b", "value": 2 }]),
                "inserted":  outcome([#{ "op": "add", "path": "/Arr/1", "value": "y" }]),
                "appended":  outcome([#{ "op": "add", "path": "/Arr/-", "value": "end" }]),
                "past_end":  outcome([#{ "op": "add", "path": "/Arr/9", "value": "no" }]),
                "dash_read": outcome([#{ "op": "remove", "path": "/Arr/-" }]),
                "null_kept": outcome([#{ "op": "add", "path": "/Obj/n", "value": () }]),
            })
        }
    "#,
    )
    .await;

    // Against an object key add replaces, which is the half people expect.
    assert_eq!(body["over_key"]["Obj"]["a"], 2);
    assert_eq!(body["new_key"]["Obj"]["b"], 2);
    // Against an array it inserts and shifts rather than overwriting.
    assert_eq!(body["inserted"]["Arr"], serde_json::json!(["x", "y", "z"]));
    assert_eq!(
        body["appended"]["Arr"],
        serde_json::json!(["x", "z", "end"])
    );
    assert!(
        body["past_end"].as_str().unwrap().contains("past the end"),
        "{body}"
    );
    // `-` is only a target for add, never a location to read.
    assert!(
        body["dash_read"].as_str().unwrap().contains("only add"),
        "{body}"
    );
    // A null value is a value, not an absent one, so the key is created.
    assert!(
        body["null_kept"]["Obj"].get("n").is_some(),
        "a null value was dropped: {body}"
    );
}

#[tokio::test]
async fn a_json_patch_is_all_or_nothing() {
    let body = run_script(
        "atomic.rn",
        r#"
        pub async fn handle(req) {
            let doc = #{"A": 1, "B": 2};
            let failed = match util::json_patch(doc, [
                #{ "op": "replace", "path": "/A", "value": 99 },
                #{ "op": "remove",  "path": "/B" },
                #{ "op": "remove",  "path": "/Nope" },
            ]) {
                Ok(value) => "unexpectedly ok",
                Err(error) => error,
            };
            resp::json(200, #{ "error": failed, "doc": doc })
        }
    "#,
    )
    .await;

    // The third operation fails, so the first two must not have landed either.
    assert!(
        body["error"].as_str().unwrap().contains("op 2"),
        "the failing operation was not named: {body}"
    );
    assert_eq!(body["doc"]["A"], 1, "a failed patch still wrote: {body}");
    assert_eq!(body["doc"]["B"], 2, "a failed patch still removed: {body}");
}

#[tokio::test]
async fn a_json_patch_reads_a_pointer_not_a_path() {
    let body = run_script(
        "pointer.rn",
        r#"
        pub async fn handle(req) {
            let doc = #{"a/b": "slash", "m~n": "tilde", "~1": "literal", "plain": #{"deep": 1}};
            let outcome = |ops| match util::json_patch(doc, ops) {
                Ok(value) => value,
                Err(error) => error,
            };
            resp::json(200, #{
                "slash":    outcome([#{ "op": "replace", "path": "/a~1b", "value": "hit" }]),
                "tilde":    outcome([#{ "op": "replace", "path": "/m~0n", "value": "hit" }]),
                "unescaped": outcome([#{ "op": "replace", "path": "/a/b", "value": "hit" }]),
                "no_slash": outcome([#{ "op": "replace", "path": "plain/deep", "value": 2 }]),
                "order":    outcome([#{ "op": "replace", "path": "/~01", "value": "hit" }]),
                "whole":    outcome([#{ "op": "replace", "path": "", "value": #{"root": true} }]),
            })
        }
    "#,
    )
    .await;

    // `~1` is a slash inside one key, not a step down into another.
    assert_eq!(body["slash"]["a/b"], "hit");
    assert_eq!(body["tilde"]["m~n"], "hit");
    // The same text unescaped walks two levels and finds nothing.
    assert!(
        body["unescaped"]
            .as_str()
            .unwrap()
            .contains("does not exist"),
        "{body}"
    );
    // A `util::at` style path is not a pointer, and is refused rather than guessed.
    assert!(
        body["no_slash"]
            .as_str()
            .unwrap()
            .contains("starts with a slash"),
        "{body}"
    );
    // `~01` is the key `~1`, which only holds when `~1` is decoded before `~0`.
    assert_eq!(
        body["order"]["~1"], "hit",
        "the unescape order is wrong: {body}"
    );
    // The empty pointer addresses the whole document.
    assert_eq!(body["whole"], serde_json::json!({"root": true}));
}

#[tokio::test]
async fn a_json_patch_refuses_an_operation_it_cannot_apply() {
    let body = run_script(
        "refuse.rn",
        r#"
        pub async fn handle(req) {
            let doc = #{"A": 1, "Arr": [1, 2], "L": []};
            let outcome = |ops| match util::json_patch(doc, ops) {
                Ok(value) => "unexpectedly ok",
                Err(error) => error,
            };

            // Appending the whole document to a list doubles it every time, so
            // twenty operations is what an op count alone would let through.
            let runaway = [];
            for i in 0..20 {
                runaway.push(#{ "op": "copy", "from": "", "path": "/L/-" });
            }
            resp::json(200, #{
                "missing_remove":  outcome([#{ "op": "remove", "path": "/Nope" }]),
                "missing_replace": outcome([#{ "op": "replace", "path": "/Nope", "value": 1 }]),
                "failed_test":     outcome([#{ "op": "test", "path": "/A", "value": 2 }]),
                "unknown_op":      outcome([#{ "op": "frobnicate", "path": "/A" }]),
                "no_value":        outcome([#{ "op": "add", "path": "/B" }]),
                "move_into_self":  outcome([#{ "op": "move", "from": "/Arr", "path": "/Arr/0" }]),
                "not_an_array":    outcome(#{ "op": "add", "path": "/B", "value": 1 }),
                "runaway_copy":    outcome(runaway),
            })
        }
    "#,
    )
    .await;

    let says = |key: &str, want: &str| {
        let got = body[key].as_str().unwrap_or("");
        assert!(got.contains(want), "{key} said {got:?}, wanted {want:?}");
    };
    says("missing_remove", "not there to remove");
    says("missing_replace", "does not exist");
    says("failed_test", "does not hold the tested value");
    // The located value stays out of the message, which reaches a log too.
    assert!(
        !body["failed_test"].as_str().unwrap().contains('1'),
        "the tested value leaked into the error: {body}"
    );
    says("unknown_op", "is not an operation");
    // A missing value differs from a null one, which is why it is refused.
    says("no_value", "value is missing");
    says("move_into_self", "own descendant");
    // An op cap bounds the count, never the size each copy multiplies out to.
    says("runaway_copy", "node limit");
    says("not_an_array", "not an array of operations");
}

#[tokio::test]
async fn a_merge_patch_deletes_a_key_set_to_null() {
    let body = run_script(
        "merge.rn",
        r#"
        pub async fn handle(req) {
            let doc = #{"Keep": 1, "Drop": 2, "Nested": #{"A": 1, "B": 2}};
            let merged = util::json_merge_patch(doc, #{
                "Drop": (),
                "Added": 3,
                "Nested": #{"B": (), "C": 4},
            })?;
            resp::json(200, merged)
        }
    "#,
    )
    .await;

    // RFC 7386, the part people get wrong. A null in the patch removes the key.
    assert_eq!(body["Keep"], 1);
    assert!(body.get("Drop").is_none(), "null did not delete: {body}");
    assert_eq!(body["Added"], 3);
    assert_eq!(
        body["Nested"]["A"], 1,
        "the merge was not recursive: {body}"
    );
    assert!(body["Nested"].get("B").is_none(), "{body}");
    assert_eq!(body["Nested"]["C"], 4);
}

#[tokio::test]
async fn a_missing_key_reads_as_none_and_a_default_stands_in() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            resp::json(200, #{
                "missing": store::get("absent")?.is_none(),
                "default": store::get_or("absent", "fallback")?,
                "contains": store::contains("absent")?,
                "empty_key": match store::get("") {
                    Ok(_) => "allowed",
                    Err(error) => error,
                },
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "missing.rn", handler));
    let body = store_get(&proxy, "").await;

    assert_eq!(body["missing"], true);
    // The default is handed back untouched, so a miss is indistinguishable from
    // a stored copy of it, which is what makes it usable as a constant.
    assert_eq!(body["default"], "fallback");
    assert_eq!(body["contains"], false);
    assert!(body["empty_key"].as_str().unwrap().contains("key is empty"));
}

#[tokio::test]
async fn a_path_segment_is_read_from_either_end() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // Counting from the end is how a script reads an id without knowing the
    // depth, and it is the branch the shipped scripts never take.
    let handler = r#"
        pub async fn handle(req) {
            resp::json(200, #{
                "front": util::segment(req.path, 3),
                "id": util::segment(req.path, -1),
                "parent": util::segment(req.path, -2),
                "past_end": util::segment(req.path, 99),
                "before_start": util::segment(req.path, -99),
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "seg.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    assert_eq!(body["front"], "Chassis");
    assert_eq!(body["id"], "1");
    assert_eq!(body["parent"], "Chassis");
    // Out of range answers None rather than failing the request.
    assert_eq!(body["past_end"], serde_json::Value::Null);
    assert_eq!(body["before_start"], serde_json::Value::Null);
}

#[tokio::test]
async fn a_query_parameter_is_read_without_splitting_by_hand() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            resp::json(200, #{
                "select": req.query_param("$select")?,
                "encoded": req.query_param("note")?,
                "absent": req.query_param("nope").is_none(),
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "query.rn", handler));

    let body: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Chassis/1?$select=Name&note=a%20b%2Bc",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    assert_eq!(body["select"], "Name");
    // url decodes percent escapes, which hand splitting would not.
    assert_eq!(body["encoded"], "a b+c");
    assert_eq!(body["absent"], true);
}

#[tokio::test]
async fn a_removed_key_is_gone_and_the_removal_is_reported() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            store::set("held", #{ "Privilege": "Administrator" })?;
            resp::json(200, #{
                "held_before": store::contains("held")?,
                "first": store::remove("held")?,
                "second": store::remove("held")?,
                "gone": store::get("held")?.is_none(),
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "removed.rn", handler));
    let body = store_get(&proxy, "").await;

    assert_eq!(body["held_before"], true);
    assert_eq!(body["first"], true);
    // Reported rather than silent, so a caller can tell a delete from a no-op.
    assert_eq!(body["second"], false);
    assert_eq!(body["gone"], true);
}

#[tokio::test]
async fn a_script_can_pace_itself_with_sleep() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            bmc::sleep(250).await?;
            resp::text(200, "paced")
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "sleep.rn", handler));

    let started = std::time::Instant::now();
    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");
    let took = started.elapsed();

    assert_eq!(response.status(), 200);
    // A floor, not a ceiling. A ceiling flakes on a loaded machine.
    assert!(
        took >= Duration::from_millis(200),
        "returned too fast: {took:?}"
    );
}

#[tokio::test]
async fn a_value_is_kept_across_requests_and_survives_a_reload() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            match req.query_param("set") {
                Some(value) => { store::set("lockdown", value)?; }
                None => {}
            }
            resp::json(200, #{
                "value": store::get_or("lockdown", "unset")?,
                "present": store::contains("lockdown")?,
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "kept.rn", handler));

    // Nothing has been written, so the default stands.
    let first = store_get(&proxy, "").await;
    assert_eq!(first["value"], "unset");
    assert_eq!(first["present"], false);

    let written = store_get(&proxy, "?set=Disabled").await;
    assert_eq!(written["value"], "Disabled");

    // A different request, the same process, so the write is still there.
    let second = store_get(&proxy, "").await;
    assert_eq!(second["value"], "Disabled");
    assert_eq!(second["present"], true);

    // A reload swaps compiled units and nothing else. State a script decided is
    // not a script, so editing one must not silently reset what the BMC reports.
    proxy.reload();
    let after_reload = store_get(&proxy, "").await;
    assert_eq!(after_reload["value"], "Disabled");
    assert_eq!(after_reload["present"], true);
}

// The script store, `store::*`.

/// One GET through the proxy, returning the JSON the handler produced. Every
/// test in this section drives the store through the same route.
async fn store_get(proxy: &support::Proxy, query: &str) -> serde_json::Value {
    client()
        .get(format!(
            "https://{}/redfish/v1/Chassis/1{query}",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json")
}

#[tokio::test]
async fn an_oversized_value_is_refused() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            let chunk = "xxxxxxxxxxxxxxxx";
            let big = "";
            for i in 0..8192 {
                big += chunk;
            }
            let refused = match store::set("big", big) {
                Ok(_) => "stored",
                Err(error) => error,
            };
            let accepted = match store::set("small", chunk) {
                Ok(_) => "stored",
                Err(error) => error,
            };
            resp::json(200, #{
                "refused": refused,
                "accepted": accepted,
                "big_held": store::contains("big")?,
                "small_held": store::contains("small")?,
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "oversized.rn", handler));
    let body = store_get(&proxy, "").await;

    assert!(
        body["refused"].as_str().unwrap().contains("byte limit"),
        "an oversized value was stored: {}",
        body["refused"]
    );
    assert_eq!(body["accepted"], "stored");
    // Refused means not held, not held and then trimmed.
    assert_eq!(body["big_held"], false);
    assert_eq!(body["small_held"], true);
}

#[tokio::test]
async fn json_is_read_only_from_inside_the_script_directory() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            let outcome = |name| match util::read_json_file(name) {
                Ok(value) => value,
                Err(error) => error,
            };
            resp::json(200, #{
                "nested": outcome("nested/table.json"),
                "escape": outcome("../escape.json"),
                "absolute": outcome("/etc/hostname"),
                "wrong_type": outcome("notes.txt"),
                "malformed": outcome("broken.json"),
                "missing": outcome("absent.json"),
            })
        }
    "#;
    let dir = script(&tls, "read.rn", handler);
    std::fs::create_dir_all(dir.join("nested")).expect("nested dir");
    std::fs::write(dir.join("nested/table.json"), r#"{"ok":true}"#).expect("nested table");
    std::fs::write(dir.join("notes.txt"), r#"{"ok":true}"#).expect("text file");
    std::fs::write(dir.join("broken.json"), "{not json").expect("broken file");
    std::fs::write(tls.dir().join("escape.json"), r#"{"secret":true}"#).expect("escape file");

    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "read.rn", handler));
    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // A nested directory is fine, everything that leaves the directory is not.
    assert_eq!(body["nested"]["ok"], true);
    assert!(
        body["escape"].as_str().unwrap().contains("outside"),
        "a relative escape was allowed: {}",
        body["escape"]
    );
    assert!(
        body["absolute"].as_str().unwrap().contains("outside"),
        "an absolute path was allowed: {}",
        body["absolute"]
    );
    assert!(body["wrong_type"].as_str().unwrap().contains("not a .json"));
    assert!(
        body["malformed"]
            .as_str()
            .unwrap()
            .contains("not valid JSON")
    );
    assert!(body["missing"].as_str().unwrap().contains("resolving"));
}

#[tokio::test]
async fn json_patch_is_read_only_from_inside_the_script_directory() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;

    let handler = r#"
        pub async fn handle(req) {
            let doc = #{"Vendor": "Generic"};
            let outcome = |name| match util::json_patch_file(doc, name) {
                Ok(value) => value,
                Err(error) => error,
            };
            resp::json(200, #{
                "nested": outcome("nested/patch.json"),
                "escape": outcome("../escape.json"),
                "absolute": outcome("/etc/hostname"),
                "wrong_type": outcome("notes.txt"),
                "malformed": outcome("broken.json"),
                "missing": outcome("absent.json"),
                "not_ops": outcome("object.json"),
            })
        }
    "#;
    let dir = script(&tls, "patchfile.rn", handler);
    std::fs::create_dir_all(dir.join("nested")).expect("nested dir");
    std::fs::write(
        dir.join("nested/patch.json"),
        r#"[{"op":"replace","path":"/Vendor","value":"Supermicro"}]"#,
    )
    .expect("nested patch");
    std::fs::write(dir.join("notes.txt"), "[]").expect("text file");
    std::fs::write(dir.join("broken.json"), "[not json").expect("broken file");
    std::fs::write(dir.join("object.json"), r#"{"op":"remove"}"#).expect("object file");
    std::fs::write(
        tls.dir().join("escape.json"),
        r#"[{"op":"replace","path":"/Vendor","value":"Escaped"}]"#,
    )
    .expect("escape file");

    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "patchfile.rn", handler));
    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // The patch applies from a subdirectory, and nothing outside is reachable.
    assert_eq!(body["nested"]["Vendor"], "Supermicro");
    for (key, want) in [
        ("escape", "outside"),
        ("absolute", "outside"),
        ("wrong_type", "not a .json"),
        ("malformed", "not valid JSON"),
        ("missing", "resolving"),
        ("not_ops", "not an array of operations"),
    ] {
        let got = body[key].as_str().unwrap_or("");
        assert!(got.contains(want), "{key} said {got:?}, wanted {want:?}");
    }
}

#[tokio::test]
async fn the_environment_is_closed_until_a_pattern_opens_it() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            let read = |name| match util::read_env(name) {
                Ok(value) => if value is Option && value.is_some() { value.unwrap() } else { "unset" },
                Err(_) => "denied",
            };
            resp::json(200, #{
                "allowed": read("BMC_SCRIPT_SITE"),
                "suffixed": read("BMC_SCRIPT_SITEX"),
                "prefixed": read("XBMC_SCRIPT_SITE"),
                "unrelated": read("HOME"),
            })
        }
    "#;
    let env = [
        ("BMC_SCRIPT_SITE", "dc-1"),
        ("BMC_SCRIPT_SITEX", "leaked"),
        ("XBMC_SCRIPT_SITE", "leaked"),
    ];

    // Closed by default, with no `rune.env_allow` in the config at all.
    let closed = start_proxy_env(&tls, &rune_config(&tls, bmc, "env.rn", handler), &env);
    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", closed.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(body["allowed"], "denied", "the default must read nothing");
    drop(closed);

    let config = rune_config(&tls, bmc, "env.rn", handler).replace(
        "[rune]\n        script_dir",
        "[rune]\n        env_allow = \"BMC_SCRIPT_SITE\"\n        script_dir",
    );
    let proxy = start_proxy_env(&tls, &config, &env);
    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    assert_eq!(body["allowed"], "dc-1");
    // Anchored at both ends, so neither a longer name nor a prefixed one match.
    assert_eq!(body["suffixed"], "denied");
    assert_eq!(body["prefixed"], "denied");
    assert_eq!(body["unrelated"], "denied");
}

#[tokio::test]
async fn the_pure_helpers_hash_encode_and_decode() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            resp::json(200, #{
                "sha256": util::sha256("abc"),
                "sha512_len": util::sha512("abc").len(),
                "b64": util::b64_encode("hello"),
                "round_trip": util::b64_decode(util::b64_encode("hello"))?,
                "bad_b64": match util::b64_decode("!!!!") { Ok(_) => "ok", Err(_) => "refused" },
                "bad_json": match util::json_decode("{nope}") { Ok(_) => "ok", Err(_) => "refused" },
                // A link that is already a path comes back unchanged, which is
                // the branch a rewritten `@odata.id` never takes.
                "relative_link": bmc::path_of("/redfish/v1/Systems/1")?,
                "no_urls": util::rewrite_links_text("nothing to swap here")?,
                "encoded": util::json_encode(#{"a": 1})?,
                "decoded": util::json_decode("{\"a\":[1,2]}")?["a"][1],
                "recent": util::unix_time() > 1700000000,
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "util.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // The published SHA-256 of "abc", so a wrong digest is a wrong answer and
    // not merely a differently shaped one.
    assert_eq!(
        body["sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(body["sha512_len"], 128);
    assert_eq!(body["b64"], "aGVsbG8=");
    assert_eq!(body["round_trip"], "hello");
    assert_eq!(body["bad_b64"], "refused");
    assert_eq!(body["bad_json"], "refused");
    assert_eq!(body["relative_link"], "/redfish/v1/Systems/1");
    assert_eq!(body["no_urls"], "nothing to swap here");
    assert_eq!(body["encoded"], r#"{"a":1}"#);
    assert_eq!(body["decoded"], 2);
    assert_eq!(body["recent"], true);
}

// The Rune language and standard library, from inside a handler.

/// Spawns a proxy for one script and returns the JSON it produced. Most of the
/// coverage below is pure computation that never touches the BMC.
async fn run_script(name: &str, handler: &str) -> serde_json::Value {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, name, handler));
    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    response.json().await.expect("json")
}

#[tokio::test]
async fn rune_collection_methods_are_available() {
    let body = run_script(
        "collections.rn",
        r#"
        pub async fn handle(req) {
            let v = [3, 1, 2];
            v.push(4);
            v.sort();
            let popped = v.pop()?;
            v.insert(0, 9);
            let removed = v.remove(0);
            v.extend([7]);

            let sorted_by = [3, 1, 2];
            sorted_by.sort_by(|a, b| b.cmp(a));

            let obj = #{"a": 1, "b": 2};
            let taken = obj.remove("b")?;

            let map = std::collections::HashMap::new();
            map.insert("k", 1);
            let set = std::collections::HashSet::new();
            set.insert(1);
            set.insert(1);
            let dq = std::collections::VecDeque::new();
            dq.push_back(1);
            dq.push_front(0);

            resp::json(200, #{
                "len": v.len(),
                "get": v.get(0)?,
                "popped": popped,
                "removed": removed,
                "is_empty": [].is_empty(),
                "sort": format!("{:?}", v),
                "sort_by": format!("{:?}", sorted_by),
                "obj_get": obj.get("a")?,
                "obj_contains": obj.contains_key("a"),
                "obj_removed": taken,
                "obj_missing": obj.get("b").is_none(),
                "hashmap": map.get("k")?,
                "hashset": set.len(),
                "vecdeque": dq.len(),
            })
        }
    "#,
    )
    .await;

    assert_eq!(body["len"], 4);
    assert_eq!(body["get"], 1);
    assert_eq!(body["popped"], 4);
    assert_eq!(body["removed"], 9);
    assert_eq!(body["is_empty"], true);
    assert_eq!(body["sort"], "[1, 2, 3, 7]");
    assert_eq!(body["sort_by"], "[3, 2, 1]");
    assert_eq!(body["obj_get"], 1);
    assert_eq!(body["obj_contains"], true);
    assert_eq!(body["obj_removed"], 2);
    assert_eq!(body["obj_missing"], true);
    assert_eq!(body["hashmap"], 1);
    // Inserted twice, so a set that does not deduplicate would read 2.
    assert_eq!(body["hashset"], 1);
    assert_eq!(body["vecdeque"], 2);
}

#[tokio::test]
async fn rune_generators_and_select_are_available() {
    let body = run_script(
        "asyncish.rn",
        r#"
        fn counter() {
            yield 1;
            yield 2;
            yield 3;
        }

        pub async fn handle(req) {
            let yielded = [];
            for n in counter() {
                yielded.push(n);
            }

            // Two real subrequests raced. Either may win, so assert only that
            // one did and that the arm ran.
            let winner = select {
                a = bmc::get("/redfish/v1/Chassis/1") => "first",
                b = bmc::get("/redfish/v1/Chassis/1/Thermal") => "second",
            };

            resp::json(200, #{
                "yielded": yielded,
                "raced": winner == "first" || winner == "second",
            })
        }
    "#,
    )
    .await;

    assert_eq!(body["yielded"], serde_json::json!([1, 2, 3]));
    assert_eq!(body["raced"], true);
}

#[tokio::test]
async fn rune_iterator_adapters_are_available() {
    let body = run_script(
        "iters.rn",
        r#"
        pub async fn handle(req) {
            let v = [1, 2, 3, 4];
            resp::json(200, #{
                "map": v.iter().map(|n| n * 2).collect::<Vec>(),
                "filter": v.iter().filter(|n| n % 2 == 0).collect::<Vec>(),
                "filter_map": v.iter().filter_map(|n| if n > 2 { Some(n) } else { None }).collect::<Vec>(),
                "flat_map": v.iter().flat_map(|n| [n, n]).collect::<Vec>().len(),
                "fold": v.iter().fold(0, |acc, n| acc + n),
                "reduce": v.iter().reduce(|a, b| a + b)?,
                "find": v.iter().find(|n| n > 2)?,
                "any": v.iter().any(|n| n == 3),
                "all": v.iter().all(|n| n > 0),
                "count": v.iter().count(),
                "sum": v.iter().sum::<i64>(),
                "product": v.iter().product::<i64>(),
                "chain": v.iter().chain([5].iter()).count(),
                "enumerate": v.iter().enumerate().map(|e| e.0).collect::<Vec>(),
                "rev": v.iter().rev().collect::<Vec>(),
                "skip": v.iter().skip(2).collect::<Vec>(),
                "take": v.iter().take(2).collect::<Vec>(),
                "range": (0..4).iter().sum::<i64>(),
            })
        }
    "#,
    )
    .await;

    assert_eq!(body["map"], serde_json::json!([2, 4, 6, 8]));
    assert_eq!(body["filter"], serde_json::json!([2, 4]));
    assert_eq!(body["filter_map"], serde_json::json!([3, 4]));
    assert_eq!(body["flat_map"], 8);
    assert_eq!(body["fold"], 10);
    assert_eq!(body["reduce"], 10);
    assert_eq!(body["find"], 3);
    assert_eq!(body["any"], true);
    assert_eq!(body["all"], true);
    assert_eq!(body["count"], 4);
    assert_eq!(body["sum"], 10);
    assert_eq!(body["product"], 24);
    assert_eq!(body["chain"], 5);
    assert_eq!(body["enumerate"], serde_json::json!([0, 1, 2, 3]));
    assert_eq!(body["rev"], serde_json::json!([4, 3, 2, 1]));
    assert_eq!(body["skip"], serde_json::json!([3, 4]));
    assert_eq!(body["take"], serde_json::json!([1, 2]));
    assert_eq!(body["range"], 6);
}

#[tokio::test]
async fn rune_language_constructs_are_available() {
    let body = run_script(
        "lang.rn",
        r#"
        const LIMIT = 3;

        struct Fan { name, rpm }

        impl Fan {
            fn label(self) { `${self.name}@${self.rpm}` }
        }

        enum State { On, Off }

        fn describe(state) {
            match state {
                State::On => "on",
                State::Off => "off",
            }
        }

        mod util2 {
            pub fn double(n) { n * 2 }

            pub mod inner {
                pub fn quad(n) { super::double(n) * 2 }
            }
        }

        use util2::double;

        fn early(n) {
            if n > 0 {
                return "positive";
            }
            "other"
        }

        fn fallible(ok) {
            if ok { Ok(7) } else { Err("no") }
        }

        pub async fn handle(req) {
            let counted = 0;
            for n in 0..LIMIT {
                counted += n;
            }

            let while_n = 0;
            while while_n < 4 {
                while_n += 1;
            }

            let looped = 0;
            loop {
                looped += 1;
                if looped == 2 {
                    continue;
                }
                if looped >= 5 {
                    break;
                }
            }

            let branch = if LIMIT > 2 { "big" } else { "small" };
            let pair = (1, "two");
            let add = |a, b| a + b;

            resp::json(200, #{
                "const": LIMIT,
                "for_sum": counted,
                "while_n": while_n,
                "looped": looped,
                "branch": branch,
                "struct_impl": Fan { name: "Fan1", rpm: 900 }.label(),
                "enum_match": describe(State::Off),
                "mod_use": double(21),
                "closure": add(1, 2),
                "tuple": pair.0 + pair.1.len(),
                "template": `n=${LIMIT}`,
                "is": (#{} is Object) && ("x" is String) && (1 is i64),
                "cast": (7 as f64) / 2.0,
                "not_and_or": !false && (true || false),
                "try": fallible(true)?,
                "err_shape": fallible(false).is_err(),
                "range_len": (0..LIMIT).iter().count(),
                "return": early(1),
                "move": (move || 5)(),
                "super": util2::inner::quad(3),
                "crate": crate::util2::double(4),
            })
        }
    "#,
    )
    .await;

    assert_eq!(body["const"], 3);
    assert_eq!(body["for_sum"], 3);
    assert_eq!(body["while_n"], 4);
    assert_eq!(body["looped"], 5);
    assert_eq!(body["branch"], "big");
    assert_eq!(body["struct_impl"], "Fan1@900");
    assert_eq!(body["enum_match"], "off");
    assert_eq!(body["mod_use"], 42);
    assert_eq!(body["closure"], 3);
    assert_eq!(body["tuple"], 4);
    assert_eq!(body["template"], "n=3");
    assert_eq!(
        body["is"], true,
        "the `is` operator did not match Rune's own types"
    );
    assert_eq!(body["cast"], 3.5);
    assert_eq!(body["not_and_or"], true);
    assert_eq!(body["try"], 7);
    assert_eq!(body["err_shape"], true);
    assert_eq!(body["range_len"], 3);
    assert_eq!(body["return"], "positive");
    assert_eq!(body["move"], 5);
    assert_eq!(body["super"], 12);
    assert_eq!(body["crate"], 8);
}

#[tokio::test]
async fn rune_macros_are_available_and_print_reaches_the_proxy_log() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            println!("script-said-hello");
            print!("no-newline ");
            dbg!("debugged");
            resp::json(200, #{
                "format": format!("{}-{}", "a", 1),
                "debug_format": format!("{:?}", [1, 2]),
                "file": file!().ends_with(".rn"),
                "line": line!() > 0,
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "macros.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    assert_eq!(body["format"], "a-1");
    assert_eq!(body["debug_format"], "[1, 2]");
    assert_eq!(body["file"], true);
    assert_eq!(body["line"], true);

    // `with_default_modules` passes stdio, so a script writes to the proxy's own
    // stdout. Ambient output we never granted, and an operator will see it.
    let logs = proxy.wait_for_log("script-said-hello");
    assert!(logs.contains("no-newline"), "print! went nowhere");
    assert!(logs.contains("debugged"), "dbg! went nowhere");
}

#[tokio::test]
async fn rune_numeric_families_and_introspection_are_available() {
    let body = run_script(
        "stdtail.rn",
        r#"
        pub async fn handle(req) {
            // The test module's macros abort the handler when they fail, so
            // reaching the response at all is the assertion.
            assert_eq!(1, 1);
            assert_ne!(1, 2);
            std::mem::drop([1]);

            let it = [1, 2, 3].iter();
            let first = it.next()?;

            resp::json(200, #{
                "epsilon": f64::EPSILON > 0.0,
                "infinity": f64::INFINITY.is_infinite(),
                "neg_infinity": f64::NEG_INFINITY < 0.0,
                "nan": f64::NAN.is_nan(),
                "min_positive": f64::MIN_POSITIVE > 0.0,
                "max_exp": f64::MAX_EXP > 0,
                "min_exp": f64::MIN_EXP < 0,
                "max_10_exp": f64::MAX_10_EXP > 0,
                "min_10_exp": f64::MIN_10_EXP < 0,
                "checked_sub": (6).checked_sub(2)?,
                "checked_mul": (6).checked_mul(2)?,
                "checked_div": (6).checked_div(2)?,
                "checked_rem": (7).checked_rem(2)?,
                "wrapping_sub": (6).wrapping_sub(2),
                "wrapping_mul": (6).wrapping_mul(2),
                "wrapping_div": (6).wrapping_div(2),
                "wrapping_rem": (7).wrapping_rem(2),
                "saturating_sub": (6).saturating_sub(2),
                "saturating_mul": (6).saturating_mul(2),
                "saturating_pow": (2).saturating_pow(3),
                "saturating_abs": (-2).saturating_abs(),
                "next": first,
                "next_back": [1, 2].iter().rev().next()?,
                "nth_back": [1, 2, 3].iter().nth_back(0)?,
                "size_hint": [1, 2].iter().size_hint().0,
                "stringify": stringify!(1 + 1),
                "is_readable": is_readable(1),
                "is_writable": is_writable(1),
                "snapshot": std::mem::snapshot(1).is_some(),
            })
        }
    "#,
    )
    .await;

    for flag in [
        "epsilon",
        "infinity",
        "neg_infinity",
        "nan",
        "min_positive",
        "max_exp",
        "min_exp",
        "max_10_exp",
        "min_10_exp",
        "is_readable",
        "is_writable",
    ] {
        assert_eq!(body[flag], true, "{flag}");
    }
    assert_eq!(body["checked_sub"], 4);
    assert_eq!(body["checked_mul"], 12);
    assert_eq!(body["checked_div"], 3);
    assert_eq!(body["checked_rem"], 1);
    assert_eq!(body["wrapping_sub"], 4);
    assert_eq!(body["wrapping_mul"], 12);
    assert_eq!(body["wrapping_div"], 3);
    assert_eq!(body["wrapping_rem"], 1);
    assert_eq!(body["saturating_sub"], 4);
    assert_eq!(body["saturating_mul"], 12);
    assert_eq!(body["saturating_pow"], 8);
    assert_eq!(body["saturating_abs"], 2);
    assert_eq!(body["next"], 1);
    assert_eq!(body["next_back"], 2);
    assert_eq!(body["nth_back"], 3);
    assert_eq!(body["size_hint"], 2);
    assert_eq!(body["stringify"], "1 + 1");
}

#[tokio::test]
async fn rune_numeric_methods_are_available() {
    let body = run_script(
        "numbers.rn",
        r#"
        pub async fn handle(req) {
            resp::json(200, #{
                "abs": (-5).abs(),
                "signum": (-5).signum(),
                "pow": (2).pow(10),
                "min": (3).min(9),
                "max": (3).max(9),
                "to_float": (3).to::<f64>() / 2.0,
                "to_string": (42).to_string(),
                "is_positive": (1).is_positive(),
                "is_negative": (-1).is_negative(),
                "checked_ok": (1).checked_add(1)?,
                "checked_overflow": i64::MAX.checked_add(1).is_none(),
                "wrapping": i64::MAX.wrapping_add(1) == i64::MIN,
                "saturating": i64::MAX.saturating_add(1) == i64::MAX,
                "f_abs": (-1.5).abs(),
                "f_ceil": 1.2.ceil(),
                "f_floor": 1.8.floor(),
                "f_round": 1.5.round(),
                "f_sqrt": 9.0.sqrt(),
                "f_powi": 2.0.powi(3),
                "f_nan": (0.0 / 0.0).is_nan(),
                "f_finite": 1.0.is_finite(),
                "f_to_int": 3.9.to::<i64>(),
            })
        }
    "#,
    )
    .await;

    assert_eq!(body["abs"], 5);
    assert_eq!(body["signum"], -1);
    assert_eq!(body["pow"], 1024);
    assert_eq!(body["min"], 3);
    assert_eq!(body["max"], 9);
    assert_eq!(body["to_float"], 1.5);
    assert_eq!(body["to_string"], "42");
    assert_eq!(body["is_positive"], true);
    assert_eq!(body["is_negative"], true);
    assert_eq!(body["checked_ok"], 2);
    // The three overflow policies differ, which is the point of having all of them.
    assert_eq!(body["checked_overflow"], true);
    assert_eq!(body["wrapping"], true);
    assert_eq!(body["saturating"], true);
    assert_eq!(body["f_abs"], 1.5);
    assert_eq!(body["f_ceil"], 2.0);
    assert_eq!(body["f_floor"], 1.0);
    assert_eq!(body["f_round"], 2.0);
    assert_eq!(body["f_sqrt"], 3.0);
    assert_eq!(body["f_powi"], 8.0);
    assert_eq!(body["f_nan"], true);
    assert_eq!(body["f_finite"], true);
    assert_eq!(body["f_to_int"], 3);
}

#[tokio::test]
async fn rune_option_and_result_methods_are_available() {
    let body = run_script(
        "optres.rn",
        r#"
        pub async fn handle(req) {
            let some = Some(2);
            let none = None;
            let ok = Ok(3);
            let err = Err("bad");

            resp::json(200, #{
                "is_some": some.is_some(),
                "is_none": none.is_none(),
                "unwrap": some.unwrap(),
                "unwrap_or": none.unwrap_or(9),
                "unwrap_or_else": none.unwrap_or_else(|| 8),
                "expect": some.expect("present"),
                "map": Some(2).map(|n| n * 3),
                "and_then": Some(2).and_then(|n| Some(n + 1)),
                "ok_or": Some(2).ok_or("missing").is_ok(),
                "ok_or_else": none.ok_or_else(|| "missing").is_err(),
                "take": Some(5).take(),
                "is_ok": ok.is_ok(),
                "is_err": err.is_err(),
                "r_unwrap": ok.unwrap(),
                "r_unwrap_or": Err("x").unwrap_or(4),
                "r_map": Ok(3).map(|n| n + 1).unwrap(),
                "r_and_then": Ok(3).and_then(|n| Ok(n * 2)).unwrap(),
                "r_ok": Ok(3).ok(),
            })
        }
    "#,
    )
    .await;

    assert_eq!(body["is_some"], true);
    assert_eq!(body["is_none"], true);
    assert_eq!(body["unwrap"], 2);
    assert_eq!(body["unwrap_or"], 9);
    assert_eq!(body["unwrap_or_else"], 8);
    assert_eq!(body["expect"], 2);
    assert_eq!(body["map"], 6);
    assert_eq!(body["and_then"], 3);
    assert_eq!(body["ok_or"], true);
    assert_eq!(body["ok_or_else"], true);
    assert_eq!(body["take"], 5);
    assert_eq!(body["is_ok"], true);
    assert_eq!(body["is_err"], true);
    assert_eq!(body["r_unwrap"], 3);
    assert_eq!(body["r_unwrap_or"], 4);
    assert_eq!(body["r_map"], 4);
    assert_eq!(body["r_and_then"], 6);
    assert_eq!(body["r_ok"], 3);
}

#[tokio::test]
async fn rune_remaining_std_surface_is_available() {
    let body = run_script(
        "stdrest.rn",
        r#"
        pub async fn handle(req) {
            let bytes = "ab".as_bytes();

            let built = String::new();
            built.push_str("ab");
            built.push('c');

            let sized = Vec::new();
            sized.push(1);
            let resized = [1];
            resized.resize(3, 0);

            let joined = "a";
            joined += "b";

            let grown = String::with_capacity(1);
            grown.reserve(16);
            grown.reserve_exact(32);
            grown.push_str("x");
            grown.shrink_to_fit();

            let raw = "ab".as_bytes();
            raw.extend_str("c");

            resp::json(200, #{
                "bytes_len": bytes.len(),
                "bytes_vec": bytes.as_vec().len(),
                "from_utf8": String::from_utf8("hi".as_bytes())?,
                "into_bytes": "hi".into_bytes().len(),
                "str_new": built,
                "str_capacity": String::with_capacity(8).capacity() >= 8,
                "vec_new": sized.len(),
                "vec_capacity": Vec::with_capacity(4).capacity() >= 4,
                "vec_resize": format!("{:?}", resized),
                "add_assign": joined,
                "type_name": std::any::type_name_of_val(1),
                "iter_once": std::iter::once(5).count(),
                "iter_empty": std::iter::empty().count(),
                "nth": [1, 2, 3].iter().nth(1)?,
                "peekable": [1, 2].iter().peekable().count(),
                "transpose": Some(Ok(1)).transpose()?,
                "powf": 2.0.powf(3.0),
                "is_infinite": (1.0 / 0.0).is_infinite(),
                "is_normal": 1.0.is_normal(),
                "is_subnormal": 1.0.is_subnormal(),
                "char_from": char::from_i64(65)?,
                "char_to_i64": 'A'.to_i64(),
                "char_alnum": 'a'.is_alphanumeric(),
                "char_control": '\n'.is_control(),
                "char_lower": 'a'.is_lowercase(),
                "parse_char": "x".parse::<char>()?,
                "reserve": grown,
                "extend_str": raw.len(),
                "bytes_last": raw.last()?,
                "into_vec": "hi".as_bytes().into_vec().len(),
                "clone": [1].clone().len(),
                "cmp_min": std::cmp::min(1, 2),
                "cmp_max": std::cmp::max(1, 2),
            })
        }
    "#,
    )
    .await;

    assert_eq!(body["bytes_len"], 2);
    assert_eq!(body["bytes_vec"], 2);
    assert_eq!(body["from_utf8"], "hi");
    assert_eq!(body["into_bytes"], 2);
    assert_eq!(body["str_new"], "abc");
    assert_eq!(body["str_capacity"], true);
    assert_eq!(body["vec_new"], 1);
    assert_eq!(body["vec_capacity"], true);
    assert_eq!(body["vec_resize"], "[1, 0, 0]");
    assert_eq!(body["add_assign"], "ab");
    assert_eq!(body["type_name"], "::std::i64");
    assert_eq!(body["iter_once"], 1);
    assert_eq!(body["iter_empty"], 0);
    assert_eq!(body["nth"], 2);
    assert_eq!(body["peekable"], 2);
    assert_eq!(body["transpose"], 1);
    assert_eq!(body["powf"], 8.0);
    assert_eq!(body["is_infinite"], true);
    assert_eq!(body["is_normal"], true);
    assert_eq!(body["is_subnormal"], false);
    assert_eq!(body["char_from"], "A");
    assert_eq!(body["char_to_i64"], 65);
    assert_eq!(body["char_alnum"], true);
    assert_eq!(body["char_control"], true);
    assert_eq!(body["char_lower"], true);
    assert_eq!(body["parse_char"], "x");
    assert_eq!(body["reserve"], "x");
    assert_eq!(body["extend_str"], 3);
    assert_eq!(body["bytes_last"], 99);
    assert_eq!(body["into_vec"], 2);
    assert_eq!(body["clone"], 1);
    assert_eq!(body["cmp_min"], 1);
    assert_eq!(body["cmp_max"], 2);
}

#[tokio::test]
async fn rune_string_and_char_methods_are_available() {
    let body = run_script(
        "strings.rn",
        r#"
        pub async fn handle(req) {
            let s = "  Redfish/v1  ";
            let t = s.trim();
            let parts = "a=b".split_once("=")?;
            let chars = "abc".chars().collect::<Vec>();

            resp::json(200, #{
                "len": t.len(),
                "trim": t,
                "trim_end": "x  ".trim_end(),
                "upper": t.to_uppercase(),
                "lower": t.to_lowercase(),
                "starts": t.starts_with("Red"),
                "ends": t.ends_with("v1"),
                "contains": t.contains("fish"),
                "replace": t.replace("/", "-"),
                "split": "a,b,c".split(",").collect::<Vec>().len(),
                "split_once": `${parts.0}|${parts.1}`,
                "char_at": t.char_at(0),
                "chars": chars.len(),
                "is_empty": "".is_empty(),
                "parse_int": "42".parse::<i64>()?,
                "parse_float": "1.5".parse::<f64>()?,
                "bytes": "ab".as_bytes().len(),
                "char_alpha": 'a'.is_alphabetic(),
                "char_num": '7'.is_numeric(),
                "char_upper": 'A'.is_uppercase(),
                "char_space": ' '.is_whitespace(),
                "char_digit": '7'.to_digit(10)?,
            })
        }
    "#,
    )
    .await;

    assert_eq!(body["len"], 10);
    assert_eq!(body["trim"], "Redfish/v1");
    assert_eq!(body["trim_end"], "x");
    assert_eq!(body["upper"], "REDFISH/V1");
    assert_eq!(body["lower"], "redfish/v1");
    assert_eq!(body["starts"], true);
    assert_eq!(body["ends"], true);
    assert_eq!(body["contains"], true);
    assert_eq!(body["replace"], "Redfish-v1");
    assert_eq!(body["split"], 3);
    assert_eq!(body["split_once"], "a|b");
    assert_eq!(body["char_at"], "R");
    assert_eq!(body["chars"], 3);
    assert_eq!(body["is_empty"], true);
    assert_eq!(body["parse_int"], 42);
    assert_eq!(body["parse_float"], 1.5);
    assert_eq!(body["bytes"], 2);
    for flag in ["char_alpha", "char_num", "char_upper", "char_space"] {
        assert_eq!(body[flag], true, "{flag}");
    }
    assert_eq!(body["char_digit"], 7);
}

// The libredfish Rune vendor, ported.

// Ported from libredfish `tests/rune/sushy.rn`. That emulator ignores
// `$expand`, 404s several collections and leaves fields blank.
const SUSHY: &str = r#"

pub async fn handle(req) {
    let path = req.path;

    // Collections sushy leaves shallow, expanded client side.
    if path == "/redfish/v1/AccountService/Accounts" {
        return resp::json(200, bmc::expand_or_empty(path, "Accounts").await?).rewrite()?;
    }
    if path == "/redfish/v1/ComponentIntegrity" {
        return resp::json(200, bmc::expand_or_empty(path, "Component Integrity").await?).rewrite()?;
    }

    // Vanilla sushy 404s FirmwareInventory, so answer with an empty one.
    if path == "/redfish/v1/UpdateService/FirmwareInventory" {
        return resp::json(200, bmc::expand_or_empty(path, "Firmware Inventory").await?).rewrite()?;
    }

    // Same, plus the standard filter and sort, keeping only enabled devices
    // that name a manufacturer.
    if path.ends_with("/PCIeDevices") {
        let collection = bmc::expand_or_empty(path, "PCIe Devices").await?;
        let kept = [];
        for device in collection["Members"] {
            if util::is_enabled(device)?
                && util::at(device, "Id")?.is_some()
                && util::at(device, "Manufacturer")?.is_some()
            {
                kept.push(device);
            }
        }
        kept.sort_by(|a, b| a["Manufacturer"].cmp(b["Manufacturer"]));
        collection["Members"] = kept;
        collection["Members@odata.count"] = kept.len();
        return resp::json(200, collection).rewrite()?;
    }

    // Vanilla sushy has no BootOptions endpoint at all, so answer the shape
    // directly rather than paying for a request that is going to 404.
    if path.ends_with("/BootOptions") {
        return resp::json(200, util::empty_collection(path, "Boot Options")?).rewrite()?;
    }

    // sushy has no NTP backend, so accept the write and never forward it.
    if path.ends_with("/NetworkProtocol") {
        return resp::json(204, #{});
    }

    // Storage members are shallow and each Drive is a bare ref, so expand then
    // inline every drive document, skipping USB as the standard client does.
    if path.ends_with("/Storage") {
        let storage = bmc::expand_or_empty(path, "Storage").await?;
        for entry in storage["Members"] {
            match entry.get("Drives") {
                Some(refs) => {
                    let drives = [];
                    for reference in refs {
                        let drive = bmc::path_of(reference["@odata.id"])?;
                        if drive.contains("USB") {
                            continue;
                        }
                        drives.push(bmc::get(drive).await?.json()?);
                    }
                    entry["Drives"] = drives;
                }
                None => {}
            }
        }
        return resp::json(200, storage).rewrite()?;
    }

    if path.ends_with("/EthernetInterfaces") {
        return resp::json(200, bmc::expand_collection(path).await?).rewrite()?;
    }

    // Site explorer reads UefiDevicePath, which sushy never sets. A table
    // beside the script supplies it, keyed by MAC.
    if path.contains("/EthernetInterfaces/") {
        let iface = bmc::get(path).await?.json()?;
        let mac = match iface.get("MACAddress") {
            Some(v) => v.to_lowercase(),
            None => "",
        };
        let table = util::read_json_file("nics.json")?;
        match table.get(mac) {
            Some(found) => { iface["UefiDevicePath"] = found; }
            None => {}
        }
        return resp::json(200, iface).rewrite()?;
    }

    // Unlike libredfish, which has no request URL and must resolve a system,
    // the proxy is handed one. Using a resolved id here would ignore the caller.
    if req.method == "PATCH" {
        let wanted = req.json()?;
        let staged = bmc::patch(path, wanted).await?;
        if staged.ok() {
            return resp::json(staged.status(), staged.json()?);
        }
        // What set_boot_order_dpu_first does, since sushy stores UefiHttp as
        // Pxe and rejects the former outright.
        let boot = wanted["Boot"];
        if boot["BootSourceOverrideTarget"] == "UefiHttp" {
            boot["BootSourceOverrideTarget"] = "Pxe";
            wanted["Boot"] = boot;
            let retried = bmc::patch(path, wanted).await?;
            return resp::json(retried.status(), retried.json()?)
                .with_header("x-boot-target-fallback", "Pxe");
        }
        return resp::json(staged.status(), staged.json()?);
    }

    let out = bmc::get(path).await?.json()?;
    let blank = match out.get("SerialNumber") {
        Some(sn) => sn.trim().is_empty(),
        None => true,
    };
    if blank {
        out["SerialNumber"] = out["UUID"].replace("-", "").to_uppercase();
    }

    // The two predicates that have no endpoint of their own. sushy has no BIOS
    // profile, and network boot is what "boot order" means for it.
    let target = match out.get("Boot") {
        Some(boot) => match boot.get("BootSourceOverrideTarget") {
            Some(t) => if t is String { t } else { "" },
            None => "",
        },
        None => "",
    };
    let oem = match out.get("Oem") {
        Some(existing) => existing,
        None => #{},
    };
    oem["Proxy"] = #{
        "BiosSetup": true,
        "BootOrderSetup": target == "UefiHttp" || target == "Pxe",
    };
    out["Oem"] = oem;

    resp::json(200, out).with_header("x-serial-source", "uuid").rewrite()
}
"#;

// Ported from libredfish `tests/rune/hw.rn`, the Dell iDRAC handler. Every
// override there is gated on the manager advertising `Oem.Dell`, as here.
const DELL: &str = r#"
pub async fn handle(req) {
    let manager = bmc::manager_id().await?;
    let mgr = bmc::get(`/redfish/v1/Managers/${manager}`).await?.json()?;

    let is_dell = match mgr.get("Oem") {
        Some(oem) => match oem.get("Dell") { Some(_) => true, None => false },
        None => false,
    };
    if !is_dell {
        return resp::json(501, #{"error": #{
            "code": "Base.1.0.ActionNotSupported",
            "message": `${bmc::address()} does not advertise Oem.Dell`,
        }});
    }

    let system = bmc::system_id().await?;
    let wanted = req.json()?["Attributes"];

    // Valid values are read from the registry rather than hardcoded, since
    // firmware revisions differ in what they will accept.
    let registry = bmc::get(`/redfish/v1/Systems/${system}/Bios/BiosRegistry`).await?.json()?;
    let allowed = #{};
    for attribute in registry["RegistryEntries"]["Attributes"] {
        let names = [];
        for value in attribute["Value"] {
            names.push(value["ValueName"]);
        }
        allowed[attribute["AttributeName"]] = names;
    }

    // Bound rather than destructured, since Rune warns a tuple pattern here
    // might panic.
    for entry in wanted {
        let name = entry.0;
        let value = entry.1;
        match allowed.get(name) {
            Some(names) => {
                if !util::contains(names, value)? {
                    return resp::json(400, #{"error": #{
                        "code": "Base.1.0.PropertyValueNotInList",
                        "message": `${value} is not a listed value for ${name}`,
                    }});
                }
            }
            None => {
                return resp::json(400, #{"error": #{
                    "code": "Base.1.0.PropertyUnknown",
                    "message": `${name} is not in the BIOS registry`,
                }});
            }
        }
    }

    // iDRAC refuses a settings PATCH while a job is queued, so clear them.
    let jobs = bmc::expand_collection(`/redfish/v1/Managers/${manager}/Oem/Dell/Jobs`).await?;
    let cleared = [];
    for job in jobs["Members"] {
        bmc::delete(bmc::path_of(job["@odata.id"])?).await?;
        cleared.push(job["Id"]);
    }

    let staged = bmc::patch(`/redfish/v1/Systems/${system}/Bios/Settings`,
                            #{"Attributes": wanted}).await?;
    resp::json(staged.status(), #{"ClearedJobs": cleared, "Staged": wanted})
}
"#;

/// The sushy handler serves several unrelated paths, so it is registered on
/// several routes. Only duplicate route paths are rejected, not duplicate scripts.
fn sushy_config(tls: &support::Tls, bmc: std::net::SocketAddr) -> String {
    let dir = script(tls, "sushy.rn", SUSHY);
    std::fs::write(
        dir.join("nics.json"),
        r#"{"aa:bb:cc:dd:ee:01":"PciRoot(0x0)/Pci(0x1C,0x0)/MAC(AABBCCDDEE01,0x1)"}"#,
    )
    .expect("write nic table");

    let mut config = format!("{}\n", base_config(tls, bmc));
    for path in [
        "/redfish/v1/Systems/**",
        "/redfish/v1/AccountService/Accounts",
        "/redfish/v1/ComponentIntegrity",
        "/redfish/v1/Chassis/*/PCIeDevices",
        "/redfish/v1/UpdateService/FirmwareInventory",
        "/redfish/v1/Managers/*/NetworkProtocol",
    ] {
        let _ = write!(
            config,
            "\n        [[route]]\n        path   = \"{path}\"\n        script = \"sushy.rn\"\n"
        );
    }
    config
}

/// As [`rune_config`], with the route path and methods spelled out, since the
/// ported handlers key off paths that are not `Chassis`.
fn route_config(
    tls: &support::Tls,
    bmc: std::net::SocketAddr,
    name: &str,
    body: &str,
    path: &str,
    method: &str,
) -> String {
    script(tls, name, body);
    format!(
        r#"{base}
        [[route]]
        method = [{method}]
        path   = "{path}"
        script = "{name}"
        "#,
        base = base_config(tls, bmc),
    )
}

#[tokio::test]
async fn a_bios_write_falls_back_to_the_other_spelling() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    // The read path already retries the other casing, so a write must too, or
    // reads work on this firmware while every attribute write 404s.
    let response = client()
        .patch(format!(
            "https://{}/redfish/v1/Systems/Sys-1/Bios",
            proxy.addr
        ))
        .header("content-type", "application/json")
        .body(r#"{"Attributes":{"BootMode":"Uefi"}}"#)
        .send()
        .await
        .expect("request");
    assert!(response.status().is_success(), "{}", response.status());

    let paths: Vec<String> = seen.all().into_iter().map(|c| c.path).collect();
    assert!(
        paths
            .iter()
            .any(|p| p == "/redfish/v1/Systems/Sys-1/Bios/Settings"),
        "the write never reached the spelling this firmware serves: {paths:?}"
    );
}

#[tokio::test]
async fn a_boot_override_falls_back_from_uefi_http_to_pxe() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &sushy_config(&tls, bmc));
    let url = format!("https://{}/redfish/v1/Systems/Sys-1", proxy.addr);

    // This is set_boot_order_dpu_first decomposed. sushy stores UefiHttp as Pxe
    // and rejects the former, so the handler retries rather than failing.
    let response = client()
        .patch(&url)
        .json(&serde_json::json!({
            "Boot": {"BootSourceOverrideTarget": "UefiHttp", "BootSourceOverrideEnabled": "Continuous"}
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-boot-target-fallback"], "Pxe");

    let patches: Vec<_> = seen
        .all()
        .into_iter()
        .filter(|r| r.method == "PATCH" && r.path == "/redfish/v1/Systems/Sys-1")
        .collect();
    assert_eq!(patches.len(), 2, "expected the retry, got {patches:?}");

    // A target the emulator accepts goes through first time, which is what
    // boot_once and boot_first reduce to.
    let once = client()
        .patch(&url)
        .json(&serde_json::json!({
            "Boot": {"BootSourceOverrideTarget": "Pxe", "BootSourceOverrideEnabled": "Once"}
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(once.status(), 200);
    assert!(!once.headers().contains_key("x-boot-target-fallback"));
    let body: serde_json::Value = once.json().await.expect("json");
    assert_eq!(body["Patched"]["Boot"]["BootSourceOverrideEnabled"], "Once");
}

#[tokio::test]
async fn a_refused_boot_write_is_not_reported_as_applied() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    // The BMC refuses with no JSON to say why. Answering 204 would tell the
    // caller the setting landed, which is the one thing that must not happen.
    let response = client()
        .patch(format!(
            "https://{}/redfish/v1/Systems/Sys-Sulk/Settings",
            proxy.addr
        ))
        .header("content-type", "application/json")
        .body(r#"{"Boot":{"BootSourceOverrideTarget":"Pxe"}}"#)
        .send()
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        500,
        "a refused write must not become a 204"
    );
}

#[tokio::test]
async fn a_serial_the_bmc_does_set_is_left_alone() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &sushy_config(&tls, bmc));

    // Synthesising over a real serial would corrupt asset tracking, which is
    // the whole reason the emulator's blank one has to be filled at all.
    let real: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-Serial",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(real["SerialNumber"], "CN-0PN2MF-74261");

    // A missing key is as blank as an empty string, and takes the same path.
    let absent: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-Absent",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(absent["SerialNumber"], "DEADBEEF04000500000600070008000F");

    // The caller's id is honoured, not a resolved one, so each answer is for
    // the system that was actually asked for.
    assert_eq!(real["Id"], "Sys-Serial");
    assert_eq!(absent["Id"], "Sys-Absent");
}

#[tokio::test]
async fn a_stored_setting_is_scoped_to_the_member_that_set_it() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    let secure_boot = |id: &'static str| {
        let url = format!("https://{}/redfish/v1/Systems/{id}/SecureBoot", proxy.addr);
        async move {
            client()
                .get(url)
                .send()
                .await
                .expect("request")
                .json::<serde_json::Value>()
                .await
                .expect("json")["SecureBootEnable"]
                .clone()
        }
    };

    let response = client()
        .patch(format!(
            "https://{}/redfish/v1/Systems/Sys-1/SecureBoot",
            proxy.addr
        ))
        .header("content-type", "application/json")
        .body(r#"{"SecureBootEnable":true}"#)
        .send()
        .await
        .expect("request");
    assert!(response.status().is_success());

    assert_eq!(secure_boot("Sys-1").await, serde_json::json!(true));
    // A key not namespaced by the member would make this true as well.
    assert_eq!(
        secure_boot("HGX_Baseboard_0").await,
        serde_json::json!(false),
        "one member's write changed what another reads back"
    );
}

#[tokio::test]
async fn an_ntp_write_is_accepted_without_reaching_the_emulator() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &sushy_config(&tls, bmc));

    let response = client()
        .patch(format!(
            "https://{}/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol",
            proxy.addr
        ))
        .json(&serde_json::json!({"NTP": {"NTPServers": ["10.0.0.1"]}}))
        .send()
        .await
        .expect("request");

    // sushy has no NTP backend, so the write is accepted and dropped.
    assert_eq!(response.status(), 204);
    assert!(
        !seen
            .all()
            .iter()
            .any(|r| r.path.contains("NetworkProtocol")),
        "the no-op write was forwarded to the emulator"
    );
}

#[tokio::test]
async fn the_dell_handler_validates_against_the_registry_and_clears_jobs() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let config = route_config(
        &tls,
        bmc,
        "dell.rn",
        DELL,
        "/redfish/v1/Systems/*/Bios/Settings",
        "\"PATCH\"",
    );
    let proxy = start_proxy(&tls, &config);
    let url = format!(
        "https://{}/redfish/v1/Systems/Sys-1/Bios/Settings",
        proxy.addr
    );

    // A value the registry lists is staged, and the queued job is cleared first.
    let response = client()
        .patch(&url)
        .json(&serde_json::json!({"Attributes": {"HttpDev1Interface": "NIC.2"}}))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 202);
    let body: serde_json::Value = response.json().await.expect("json");
    assert_eq!(body["ClearedJobs"][0], "JID_001");
    assert_eq!(body["Staged"]["HttpDev1Interface"], "NIC.2");

    let all = seen.all();
    let deleted = all
        .iter()
        .find(|r| r.method == "DELETE")
        .expect("the queued job was never deleted");
    assert!(deleted.path.ends_with("/Jobs/JID_001"), "{deleted:?}");
    let patched = all.iter().position(|r| r.method == "PATCH").expect("patch");
    let cleared = all
        .iter()
        .position(|r| r.method == "DELETE")
        .expect("clear");
    assert!(
        cleared < patched,
        "the job queue was cleared after the PATCH"
    );

    // A value the registry does not list is refused before anything is written.
    let refused = client()
        .patch(&url)
        .json(&serde_json::json!({"Attributes": {"HttpDev1Interface": "NIC.9"}}))
        .send()
        .await
        .expect("request");
    assert_eq!(refused.status(), 400);
    let body: serde_json::Value = refused.json().await.expect("json");
    assert_eq!(body["error"]["code"], "Base.1.0.PropertyValueNotInList");
    assert_eq!(
        seen.all().iter().filter(|r| r.method == "PATCH").count(),
        1,
        "a rejected attribute still reached the BMC"
    );
}

#[tokio::test]
async fn the_supermicro_scripts_accept_the_actions_the_emulator_lacks() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));
    let system = "/redfish/v1/Systems/Sys-1";
    let manager = "/redfish/v1/Managers/iDRAC.Embedded.1";

    // The UEFI password action. The BMC has no route for it under any spelling,
    // so a 204 here is the whole substitution.
    let changed = client()
        .post(format!(
            "https://{}{system}/Bios/Actions/Bios.ChangePassword",
            proxy.addr
        ))
        .json(&serde_json::json!({
            "PasswordName": "AdministratorPassword",
            "OldPassword": "",
            "NewPassword": "sekrit",
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(changed.status(), 204);

    // The value is not kept anywhere. Storing a UEFI password would be holding a
    // credential nothing can check.
    for path in [system, &format!("{system}/Bios")] {
        let body = client()
            .get(format!("https://{}{path}", proxy.addr))
            .send()
            .await
            .expect("request")
            .text()
            .await
            .expect("body");
        assert!(
            !body.contains("sekrit"),
            "the password leaked into {path}: {body}"
        );
    }

    // A body that names no password is refused rather than silently accepted.
    let refused = client()
        .post(format!(
            "https://{}{system}/Bios/Actions/Bios.ChangePassword",
            proxy.addr
        ))
        .json(&serde_json::json!({"PasswordName": "AdministratorPassword"}))
        .send()
        .await
        .expect("request");
    assert_eq!(refused.status(), 400);

    // The BMC serves no manager actions at all.
    let reset = client()
        .post(format!(
            "https://{}{manager}/Actions/Manager.Reset",
            proxy.addr
        ))
        .json(&serde_json::json!({"ResetType": "GracefulRestart"}))
        .send()
        .await
        .expect("request");
    assert_eq!(reset.status(), 204);

    // A BIOS reset is relayed rather than faked, because the BMC does implement
    // it, just under the capitalised spelling.
    let before = seen.count();
    let reset_bios = client()
        .post(format!(
            "https://{}{system}/Bios/Actions/Bios.ResetBios",
            proxy.addr
        ))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("request");
    assert!(reset_bios.status().is_success(), "{}", reset_bios.status());
    assert!(
        seen.all()[before..]
            .iter()
            .any(|r| r.path == "/redfish/v1/Systems/Sys-1/BIOS/Actions/Bios.ResetBios"),
        "the reset never reached the BMC at the capitalised path: {:?}",
        seen.all()[before..]
            .iter()
            .map(|r| &r.path)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn the_supermicro_scripts_answer_the_endpoints_the_emulator_lacks() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    // The fake BMC 404s every one of these, so a 200 through the proxy is the
    // whole substitution, proven against the absence rather than a fixture.
    for (path, key, value) in [
        (
            "/redfish/v1/Systems/Sys-1/SecureBoot",
            "SecureBootCurrentBoot",
            serde_json::json!("Disabled"),
        ),
        (
            "/redfish/v1/Systems/Sys-1/SecureBoot",
            "SecureBootEnable",
            serde_json::json!(false),
        ),
        (
            "/redfish/v1/UpdateService/FirmwareInventory",
            "@odata.type",
            serde_json::json!("#SoftwareInventoryCollection.SoftwareInventoryCollection"),
        ),
        (
            "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Supermicro/SysLockdown",
            "SysLockdownEnabled",
            serde_json::json!(false),
        ),
        (
            "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Supermicro/KCSInterface",
            "Privilege",
            serde_json::json!("Administrator"),
        ),
        (
            "/redfish/v1/Managers/iDRAC.Embedded.1/EthernetInterfaces/eth0",
            "MACAddress",
            serde_json::json!("02:00:00:00:00:01"),
        ),
        (
            "/redfish/v1/Chassis/1/PCIeDevices/PCIeDevice0",
            "PartNumber",
            serde_json::json!("VIRTIO-NET-1AF4"),
        ),
    ] {
        let direct = client()
            .get(format!("https://{bmc}{path}"))
            .send()
            .await
            .expect("direct request");
        assert_eq!(
            direct.status(),
            404,
            "{path} unexpectedly exists on the BMC"
        );

        let response = client()
            .get(format!("https://{}{path}", proxy.addr))
            .send()
            .await
            .expect("request");
        assert_eq!(response.status(), 200, "{path} was not substituted");
        let body: serde_json::Value = response.json().await.expect("json");
        assert_eq!(body[key], value, "{path}");
    }

    // The BMC does serve SecureBoot here, and its answer is replaced anyway. An
    // emulator reports a state it cannot apply, so the proxy owns the resource.
    let served: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-Serial/SecureBoot",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        served["SecureBootEnable"], false,
        "the BMC's own secure boot state survived: {served}"
    );
    assert_eq!(served["SecureBootMode"], "UserMode");
    assert_eq!(served["SecureBootCurrentBoot"], "Disabled");

    // The inventory is only reachable through the link, and the BMC serves no
    // UpdateService at all, so the whole document is the proxy's.
    let update: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/UpdateService", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(update["Id"], "UpdateService");
    assert_eq!(update["ServiceEnabled"], true);
    assert_eq!(
        update["FirmwareInventory"]["@odata.id"],
        "/redfish/v1/UpdateService/FirmwareInventory"
    );

    // A collection, not the bare member list the library method returns. A
    // client dispatching on the type needs both the count and the empty array.
    let inventory: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/UpdateService/FirmwareInventory",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(inventory["Name"], "Firmware Inventory Collection");
    assert_eq!(inventory["Members"], serde_json::json!([]));
    assert_eq!(inventory["Members@odata.count"], 0);
}

#[tokio::test]
async fn the_supermicro_scripts_derive_a_predictable_serial_where_the_bmc_has_none() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    let serial_of = |url: String| async move {
        client()
            .get(url)
            .send()
            .await
            .expect("request")
            .json::<serde_json::Value>()
            .await
            .expect("json")["SerialNumber"]
            .as_str()
            .expect("serial")
            .to_string()
    };

    // Plenty of Supermicro hardware reports no serial and no UUID, which leaves
    // the proxy nothing to copy and a machine nothing to be matched on.
    let derived = serial_of(format!(
        "https://{}/redfish/v1/Systems/Sys-Bare",
        proxy.addr
    ))
    .await;

    // A digest, so it is a serial rather than the seed it was made from.
    assert_eq!(derived.len(), 64, "{derived}");
    assert!(
        derived
            .chars()
            .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c)),
        "{derived}"
    );

    // The seed is the target address and the manager id. Neither may be legible
    // in the result, since this serial is handed to anyone who asks for it.
    for leaked in [
        bmc.to_string(),
        bmc.ip().to_string(),
        bmc.port().to_string(),
    ] {
        assert!(!derived.contains(&leaked), "{leaked} leaked into {derived}");
    }
    assert!(
        !derived.contains("iDRAC"),
        "the manager id leaked: {derived}"
    );

    // Predictable, not random. A machine registered under it has to still match
    // on the next read, or it is a new machine every time it is looked at.
    let again = serial_of(format!(
        "https://{}/redfish/v1/Systems/Sys-Bare",
        proxy.addr
    ))
    .await;
    assert_eq!(derived, again);

    // The UUID comes first where there is one, so the digest is the last resort
    // rather than the answer everywhere.
    assert_ne!(derived, SUPERMICRO_SERIAL);
    assert_eq!(
        serial_of(format!("https://{}/redfish/v1/Systems/Sys-1", proxy.addr)).await,
        SUPERMICRO_SERIAL
    );

    // A serial the BMC does set on the SYSTEM is the machine's own and survives.
    assert_eq!(
        serial_of(format!(
            "https://{}/redfish/v1/Systems/Sys-Serial",
            proxy.addr
        ))
        .await,
        "CN-0PN2MF-74261"
    );

    // The chassis is the exception. Its serial has to agree with the system's or
    // the fallback match names a different machine, so a BMC value is replaced.
    let chassis_serial =
        serial_of(format!("https://{}/redfish/v1/Chassis/Ser-1", proxy.addr)).await;
    assert_ne!(
        chassis_serial, "CHASSIS-REAL-9",
        "the BMC's sample chassis serial survived"
    );
    assert_eq!(chassis_serial, SUPERMICRO_SERIAL);

    // The two scripts derive independently, so what matters is that they agree
    // whichever branch they took, not which value this fixture happens to hit.
    let system_serial = serial_of(format!("https://{}/redfish/v1/Systems/Sys-1", proxy.addr)).await;
    assert_eq!(
        chassis_serial, system_serial,
        "the chassis and the system disagree on the machine's serial"
    );
}

#[tokio::test]
async fn the_supermicro_scripts_derive_the_serial_and_the_boot_interface() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    let system: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Systems/Sys-1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // The BMC sets a blank serial, so filling it is observable rather than
    // merely written down.
    assert_eq!(system["SerialNumber"], SUPERMICRO_SERIAL);
    assert_eq!(system["Manufacturer"], "Supermicro");
    // Still the BMC's own document underneath, not a synthesised stand-in.
    assert_eq!(system["Id"], "Sys-1");
    assert_eq!(
        system["@Redfish.Settings"]["SettingsObject"]["@odata.id"],
        "/redfish/v1/Systems/Sys-1/Settings"
    );
    assert_eq!(
        system["Boot"]["BootOptions"]["@odata.id"],
        "/redfish/v1/Systems/Sys-1/BootOptions"
    );
    assert_eq!(system["Boot"]["BootOrder"][0], "Boot0000");

    // libredfish dials `{odata_id}/` as well as `{odata_id}`, and undressed that
    // spelling carries no serial, failing machine creation with the right vendor.
    let trailing: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Systems/Sys-1/", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(trailing["SerialNumber"], SUPERMICRO_SERIAL, "{trailing}");
    assert_eq!(trailing["Manufacturer"], "Supermicro", "{trailing}");

    // A client that fails to match the system serial falls back to the chassis
    // one, so the two have to agree rather than each being separately plausible.
    let chassis: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(chassis["SerialNumber"], SUPERMICRO_SERIAL);
    assert_eq!(
        chassis["PCIeDevices"]["@odata.id"],
        "/redfish/v1/Chassis/1/PCIeDevices"
    );

    // The boot order resolves through BootOptionReference, and the network
    // option's device path is the only place the boot MAC can be read from.
    for reference in ["Boot0000", "Boot0001"] {
        let option: serde_json::Value = client()
            .get(format!(
                "https://{}/redfish/v1/Systems/Sys-1/BootOptions/{reference}",
                proxy.addr
            ))
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("json");
        assert_eq!(option["BootOptionReference"], reference);
    }

    let network: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-1/BootOptions/Boot0000",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    let path = network["UefiDevicePath"].as_str().expect("device path");
    // The BMC's own NIC, read live, rather than a value pinned in the script.
    assert!(path.contains("/MAC(AABBCCDDEE01,"), "{path}");
    assert!(path.contains("/IPv4("), "{path}");
    assert!(path.ends_with("/Uri()"), "{path}");

    // The boot interface is matched on this string rather than the device path,
    // so it names a supported adapter and carries the MAC or nothing matches.
    let display = network["DisplayName"].as_str().expect("display name");
    assert!(
        display.contains("UEFI HTTP IPv4 Mellanox Network Adapter")
            || display.contains("UEFI HTTP IPv4 Nvidia Network Adapter"),
        "{display}"
    );
    // Both spellings of the MAC, since either may be the one matched against.
    assert!(display.contains("AA:BB:CC:DD:EE:01"), "{display}");
    assert!(display.contains("AABBCCDDEE01"), "{display}");
}

// The shipped Supermicro scripts.

/// Registers every shipped `supermicro/` script on its route, and writes the
/// deployment facts the three that read them expect.
fn supermicro_config(tls: &support::Tls, bmc: std::net::SocketAddr) -> String {
    let mut config = format!("{}\n", base_config(tls, bmc));
    let mut dir = std::path::PathBuf::new();
    for (path, script) in [
        ("/redfish/v1", "supermicro/service_root.rn"),
        ("/redfish/v1/Systems/*", "supermicro/systems.rn"),
        ("/redfish/v1/Systems/*/", "supermicro/systems.rn"),
        (
            "/redfish/v1/Systems/*/Settings",
            "supermicro/system_settings.rn",
        ),
        (
            "/redfish/v1/Systems/*/SecureBoot",
            "supermicro/secure_boot.rn",
        ),
        (
            "/redfish/v1/Systems/*/BootOptions",
            "supermicro/boot_options.rn",
        ),
        (
            "/redfish/v1/Systems/*/BootOptions/*",
            "supermicro/boot_option.rn",
        ),
        (
            "/redfish/v1/Systems/*/BootOptions/*/Settings",
            "supermicro/boot_option_settings.rn",
        ),
        ("/redfish/v1/Chassis/*", "supermicro/chassis.rn"),
        (
            "/redfish/v1/Chassis/*/PCIeDevices",
            "supermicro/pcie_devices.rn",
        ),
        (
            "/redfish/v1/Chassis/*/PCIeDevices/*",
            "supermicro/pcie_device.rn",
        ),
        ("/redfish/v1/Managers/*", "supermicro/manager.rn"),
        (
            "/redfish/v1/Managers/*/EthernetInterfaces/*",
            "supermicro/manager_ethernet_interface.rn",
        ),
        (
            "/redfish/v1/Managers/*/HostInterfaces",
            "supermicro/host_interfaces.rn",
        ),
        (
            "/redfish/v1/Managers/*/HostInterfaces/*",
            "supermicro/host_interface.rn",
        ),
        (
            "/redfish/v1/Managers/*/SerialInterfaces",
            "supermicro/serial_interfaces.rn",
        ),
        (
            "/redfish/v1/Managers/*/SerialInterfaces/*",
            "supermicro/serial_interface.rn",
        ),
        (
            "/redfish/v1/Managers/*/NetworkProtocol",
            "supermicro/network_protocol.rn",
        ),
        ("/redfish/v1/Systems/*/Bios", "supermicro/bios.rn"),
        (
            "/redfish/v1/Systems/*/Bios/Actions/Bios.ChangePassword",
            "supermicro/bios_change_password.rn",
        ),
        (
            "/redfish/v1/Systems/*/Bios/Actions/Bios.ResetBios",
            "supermicro/bios_reset_bios.rn",
        ),
        (
            "/redfish/v1/Managers/*/Actions/Manager.Reset",
            "supermicro/manager_reset.rn",
        ),
        (
            "/redfish/v1/Managers/*/Actions/Oem/SmcManagerConfig.Reset",
            "supermicro/smc_manager_config_reset.rn",
        ),
        (
            "/redfish/v1/AccountService",
            "supermicro/account_service.rn",
        ),
        (
            "/redfish/v1/AccountService/Accounts",
            "supermicro/accounts.rn",
        ),
        (
            "/redfish/v1/AccountService/Accounts/*",
            "supermicro/account.rn",
        ),
        (
            "/redfish/v1/Systems/*/Storage",
            "supermicro/empty_collection.rn",
        ),
        (
            "/redfish/v1/TaskService/Tasks",
            "supermicro/empty_collection.rn",
        ),
        (
            "/redfish/v1/Managers/*/Oem/Supermicro/SysLockdown",
            "supermicro/sys_lockdown.rn",
        ),
        (
            "/redfish/v1/Managers/*/Oem/Supermicro/KCSInterface",
            "supermicro/kcs_interface.rn",
        ),
        ("/redfish/v1/UpdateService", "supermicro/update_service.rn"),
        (
            "/redfish/v1/UpdateService/FirmwareInventory",
            "supermicro/firmware_inventory.rn",
        ),
    ] {
        dir = support::shipped(tls, script);
        let _ = write!(
            config,
            "\n        [[route]]\n        path   = \"{path}\"\n        script = \"{script}\"\n"
        );
    }
    std::fs::write(
        dir.join("supermicro/facts.json"),
        r#"{"BmcMacAddress":"02:00:00:00:00:01",
            "PCIeDevices":[{"Id":"PCIeDevice0","Name":"Ethernet Controller",
            "Manufacturer":"Red Hat, Inc.","PartNumber":"VIRTIO-NET-1AF4",
            "SerialNumber":"VIRT0000000001"}]}"#,
    )
    .expect("facts file");
    config
}

/// The fake BMC's `Sys-1` UUID as a Redfish serial, hyphens stripped and
/// uppercased. The lab computes exactly this, so anything else matches nothing.
const SUPERMICRO_SERIAL: &str = "03000200040005000006ABCDEF080009";

#[tokio::test]
async fn the_supermicro_scripts_hand_a_collection_back_untouched() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    // A glob star accepts an empty segment, so `Systems/*` matches `Systems/`
    // too, and dressing that member list yields doubled links on a collection.
    let collection: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Systems/", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    assert_eq!(collection["Members@odata.count"], 1, "{collection}");
    for injected in [
        "Manufacturer",
        "Model",
        "@Redfish.Settings",
        "Boot",
        "SecureBoot",
    ] {
        assert!(
            collection[injected].is_null(),
            "{injected} was added to a collection: {collection}"
        );
    }
    assert!(
        !collection.to_string().contains("Systems//"),
        "a doubled separator escaped: {collection}"
    );

    // `Chassis/*` has the same hole, and chassis.rn stamps a Manufacturer and a
    // PCIeDevices link, so an undressed member list is what proves the guard.
    let chassis: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    assert_eq!(chassis["Members@odata.count"], 1, "{chassis}");
    for injected in ["Manufacturer", "SerialNumber", "PCIeDevices"] {
        assert!(
            chassis[injected].is_null(),
            "{injected} was added to a collection: {chassis}"
        );
    }
    assert!(
        !chassis.to_string().contains("Chassis//"),
        "a doubled separator escaped: {chassis}"
    );
}

#[tokio::test]
async fn the_supermicro_scripts_keep_a_lockdown_write_and_read_it_back() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));
    let lockdown = format!(
        "https://{}/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Supermicro/SysLockdown",
        proxy.addr
    );
    let kcs = format!(
        "https://{}/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Supermicro/KCSInterface",
        proxy.addr
    );

    let read = async |url: String| -> serde_json::Value {
        client()
            .get(url)
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("json")
    };

    // Disabled is what a fresh proxy reports, since locked-by-default would
    // park a machine waiting for a disable it never sees.
    assert_eq!(read(lockdown.clone()).await["SysLockdownEnabled"], false);

    let written = client()
        .patch(&lockdown)
        .json(&serde_json::json!({"SysLockdownEnabled": true}))
        .send()
        .await
        .expect("request");
    assert_eq!(written.status(), 204);

    // The point of the store, since a client writes the flag and then polls for
    // it, which a constant never satisfies.
    assert_eq!(read(lockdown.clone()).await["SysLockdownEnabled"], true);

    // A body that names nothing usable is refused rather than silently kept.
    let refused = client()
        .patch(&lockdown)
        .json(&serde_json::json!({"SysLockdownEnabled": "yes"}))
        .send()
        .await
        .expect("request");
    assert_eq!(refused.status(), 400);
    let lockdown_after_reset = lockdown.clone();
    assert_eq!(read(lockdown).await["SysLockdownEnabled"], true);

    // The KCS privilege is read as the pair with lockdown, so it is kept the
    // same way rather than pinned.
    assert_eq!(read(kcs.clone()).await["Privilege"], "Administrator");
    let written = client()
        .patch(&kcs)
        .json(&serde_json::json!({"Privilege": "User"}))
        .send()
        .await
        .expect("request");
    assert_eq!(written.status(), 204);
    assert_eq!(read(kcs.clone()).await["Privilege"], "User");

    // The vendor factory reset drops the state this proxy holds rather than being
    // accepted and changing nothing, which the next read would expose.
    let cleared = client()
        .post(format!(
            "https://{}/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/SmcManagerConfig.Reset",
            proxy.addr
        ))
        .json(&serde_json::json!({"Option": "ClearConfig"}))
        .send()
        .await
        .expect("request");
    assert_eq!(cleared.status(), 204);
    assert_eq!(
        read(lockdown_after_reset).await["SysLockdownEnabled"],
        false
    );
    assert_eq!(read(kcs).await["Privilege"], "Administrator");
}

#[tokio::test]
async fn the_supermicro_scripts_keep_a_secure_boot_write_and_read_it_back() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    let secure_boot = format!("https://{}/redfish/v1/Systems/Sys-1/SecureBoot", proxy.addr);
    let read = |url: String| async move {
        client()
            .get(url)
            .send()
            .await
            .expect("request")
            .json::<serde_json::Value>()
            .await
            .expect("json")
    };

    // The BMC 404s this system, so the answer is the proxy's own and starts off.
    let initial = read(secure_boot.clone()).await;
    assert_eq!(initial["SecureBootEnable"], false);
    assert_eq!(initial["SecureBootCurrentBoot"], "Disabled");

    let written = client()
        .patch(&secure_boot)
        .json(&serde_json::json!({"SecureBootEnable": true}))
        .send()
        .await
        .expect("request");
    assert_eq!(written.status(), 204);

    // The write is the proxy's to keep, since the BMC has no resource to apply
    // it to, and the derived field has to move with the flag it is derived from.
    let after = read(secure_boot.clone()).await;
    assert_eq!(after["SecureBootEnable"], true);
    assert_eq!(after["SecureBootCurrentBoot"], "Enabled");

    // The BMC still has nothing there, so the state that came back is the
    // proxy's own rather than something the write applied upstream.
    let direct = client()
        .get(format!("https://{bmc}/redfish/v1/Systems/Sys-1/SecureBoot"))
        .send()
        .await
        .expect("direct request");
    assert_eq!(direct.status(), 404);
}

#[tokio::test]
async fn the_supermicro_scripts_list_the_boot_options_the_emulator_lacks() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    let direct = client()
        .get(format!(
            "https://{bmc}/redfish/v1/Systems/Sys-1/BootOptions"
        ))
        .send()
        .await
        .expect("direct request");
    assert_eq!(
        direct.status(),
        404,
        "the BMC unexpectedly serves BootOptions"
    );

    let response = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-1/BootOptions",
            proxy.addr
        ))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);
    let collection: serde_json::Value = response.json().await.expect("json");

    assert_eq!(
        collection["@odata.type"],
        "#BootOptionCollection.BootOptionCollection"
    );
    assert_eq!(
        collection["@odata.id"],
        "/redfish/v1/Systems/Sys-1/BootOptions"
    );
    // The count is written by hand beside the array, so both are asserted.
    assert_eq!(collection["Members@odata.count"], 2, "{collection}");

    let members: Vec<&str> = collection["Members"]
        .as_array()
        .expect("members")
        .iter()
        .map(|m| m["@odata.id"].as_str().expect("member id"))
        .collect();
    assert_eq!(members.len(), 2, "{collection}");
    // Network first, which is the order the system document reports and the
    // order boot_option.rn assigns its two shapes by.
    assert!(
        members[0].ends_with("/BootOptions/Boot0000"),
        "{collection}"
    );

    // The two scripts are only useful together, so the collection is walked
    // rather than the ids being repeated here, which would let them drift.
    for member in &members {
        let option: serde_json::Value = client()
            .get(format!("https://{}{member}", proxy.addr))
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("json");
        let id = member.rsplit('/').next().expect("id");
        assert_eq!(option["BootOptionReference"], id, "{member}");
        assert_eq!(option["@odata.id"], *member, "{member}");
    }

    // A BMC that reports no order at all gets the stub, since an empty one sends
    // a client down the OEM fixed-boot-order path this proxy deliberately 404s.
    let stubbed: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Systems/Sys-1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        stubbed["Boot"]["BootOrder"],
        serde_json::json!(["Boot0000", "Boot0001"]),
        "{stubbed}"
    );

    // A BMC that does report one keeps it. Those names are the boot options it
    // really has, so replacing them with the stub would name options it lacks.
    let served: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-Serial",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        served["Boot"]["BootOrder"],
        serde_json::json!(["BootFFFF", "BootEEEE"]),
        "the BMC's own boot order was replaced: {served}"
    );

    // The order the system reports has to name options this collection lists,
    // or a client resolving it by reference finds nothing to boot.
    let system: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Systems/Sys-1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    let order: Vec<&str> = system["Boot"]["BootOrder"]
        .as_array()
        .expect("boot order")
        .iter()
        .map(|v| v.as_str().expect("reference"))
        .collect();
    for reference in &order {
        assert!(
            members
                .iter()
                .any(|m| m.ends_with(&format!("/{reference}"))),
            "{reference} is in the boot order but not the collection"
        );
    }

    // The id comes off the URL, so a second system gets its own collection
    // rather than one pinned to whichever system was asked for first.
    let other: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/HGX_Baseboard_0/BootOptions",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        other["@odata.id"],
        "/redfish/v1/Systems/HGX_Baseboard_0/BootOptions"
    );
}

#[tokio::test]
async fn the_supermicro_scripts_name_the_vendor_a_client_matches_on() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    // The BMC underneath claims a different vendor, a product that would select
    // yet another, and its own Oem block. None of it may survive.
    let direct: serde_json::Value = client()
        .get(format!("https://{bmc}/redfish/v1"))
        .send()
        .await
        .expect("direct request")
        .json()
        .await
        .expect("json");
    assert_eq!(direct["Vendor"], "Dell", "{direct}");
    assert_eq!(direct["Product"], "GB NVL", "{direct}");

    let root: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // Matched exactly and case sensitively, so this string is the whole
    // mechanism and a near miss is an unrecognised BMC.
    assert_eq!(root["Vendor"], "Supermicro");
    // Read together with the vendor, where "Supermicro" plus this product selects
    // a different one, so leaving the target's value through would undo it.
    assert_eq!(root["Product"], "Super Server");
    // The fallback a client uses when `Vendor` is absent is the first key of
    // `Oem`, so the block is replaced rather than merged into.
    assert!(root["Oem"]["Supermicro"].is_object(), "{root}");
    assert!(
        root["Oem"]["Dell"].is_null(),
        "a foreign Oem survived: {root}"
    );
    // The BMC's own document is still underneath it.
    assert_eq!(root["Relative"], "/redfish/v1/Chassis");
}

#[tokio::test]
async fn the_supermicro_scripts_refuse_a_password_write() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));
    let account = "/redfish/v1/AccountService/Accounts/admin";

    // The service and its one account exist, because a client walks them.
    let service: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/AccountService", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        service["Accounts"]["@odata.id"],
        "/redfish/v1/AccountService/Accounts"
    );

    let accounts: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/AccountService/Accounts",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(accounts["Members@odata.count"], 1, "{accounts}");

    // Matched on UserName, so the id and the name have to agree.
    let one: serde_json::Value = client()
        .get(format!("https://{}{account}", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(one["UserName"], "admin");
    assert_eq!(one["Id"], "admin");

    // The lockout policy is the one write worth accepting.
    let policy = client()
        .patch(format!("https://{}/redfish/v1/AccountService", proxy.addr))
        .json(&serde_json::json!({"AccountLockoutThreshold": 0}))
        .send()
        .await
        .expect("request");
    assert_eq!(policy.status(), 204);

    // A password write is refused, and says why. Accepting it would have the
    // caller record a credential the BMC goes on rejecting.
    let refused = client()
        .patch(format!("https://{}{account}", proxy.addr))
        .json(&serde_json::json!({"Password": "nope"}))
        .send()
        .await
        .expect("request");
    assert_eq!(refused.status(), 501);
    let body: serde_json::Value = refused.json().await.expect("json");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("cannot be rotated"),
        "{body}"
    );

    // A write that is not about the password is not the thing being refused.
    let other = client()
        .patch(format!("https://{}{account}", proxy.addr))
        .json(&serde_json::json!({"Enabled": true}))
        .send()
        .await
        .expect("request");
    assert_eq!(other.status(), 204);
}

#[tokio::test]
async fn the_supermicro_scripts_relay_a_boot_override_and_keep_the_order() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));
    let system = "/redfish/v1/Systems/Sys-1";

    // A boot override is real state that steers the next boot, so it is relayed
    // rather than answered here.
    let response = client()
        .patch(format!("https://{}{system}", proxy.addr))
        .header("content-type", "application/json")
        .body(
            r#"{"Boot":{"BootSourceOverrideTarget":"Pxe","BootSourceOverrideEnabled":"Continuous",
                        "BootSourceOverrideMode":null,"HttpBootUri":null}}"#,
        )
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    // The fixture echoes the body it received, so this is the wire rather than
    // the intent, which the recorder cannot show since it keeps only a length.
    let echoed: serde_json::Value = response.json().await.expect("json");
    let asked = &echoed["Patched"]["Boot"];
    assert_eq!(asked["BootSourceOverrideTarget"], "Pxe");
    assert_eq!(asked["BootSourceOverrideEnabled"], "Continuous");
    // A JSON null arrives as the unit value and is dropped rather than relayed,
    // which is what the library expresses by omitting an `Option` argument.
    assert!(asked.get("BootSourceOverrideMode").is_none(), "{asked}");
    assert!(asked.get("HttpBootUri").is_none(), "{asked}");
    assert!(
        seen.all()
            .iter()
            .any(|c| c.path == system && c.method == "PATCH"),
        "no PATCH reached the BMC"
    );

    // The order is the proxy's own, since relaying it would be refused and
    // dropping it silently has the caller believe a reorder took effect.
    let before = seen.all().iter().filter(|c| c.method == "PATCH").count();
    let reordered = client()
        .patch(format!("https://{}{system}", proxy.addr))
        .json(&serde_json::json!({"Boot": {"BootOrder": ["Boot0001", "Boot0000"]}}))
        .send()
        .await
        .expect("request");
    assert_eq!(reordered.status(), 204);
    assert_eq!(
        seen.all().iter().filter(|c| c.method == "PATCH").count(),
        before,
        "a boot order reached the BMC, which would have refused it"
    );

    // And it reads back, rather than reverting to the default.
    let system_doc: serde_json::Value = client()
        .get(format!("https://{}{system}", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        system_doc["Boot"]["BootOrder"],
        serde_json::json!(["Boot0001", "Boot0000"]),
        "{system_doc}"
    );
}

#[tokio::test]
async fn the_supermicro_scripts_relay_the_update_service_the_emulator_serves() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    // The BMC serves a real one for this caller, so the document handed back has
    // to be that one, with only the link it is missing added to it.
    let update: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/UpdateService?served=1",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // A field only the BMC's document carries, so a synthesised answer fails.
    assert_eq!(
        update["HttpPushUri"], "/redfish/v1/UpdateService/upload",
        "the BMC's own service was replaced: {update}"
    );
    // Its value, not the one the fallback would have stamped.
    assert_eq!(update["ServiceEnabled"], false, "{update}");
    // The inventory is reachable only through this link, which the BMC omits.
    assert_eq!(
        update["FirmwareInventory"]["@odata.id"],
        "/redfish/v1/UpdateService/FirmwareInventory"
    );
}

#[tokio::test]
async fn the_supermicro_scripts_report_ipmi_already_enabled() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    // Upstream this is a bare predicate. At a URL it is the document that
    // predicate reads, so a client sees IPMI on and skips a refused write.
    let protocol: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Managers/BMC-Other/NetworkProtocol",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(protocol["IPMI"]["ProtocolEnabled"], true);
    // The id in the URL, not one the handler resolved for itself.
    assert!(
        protocol["@odata.id"]
            .as_str()
            .expect("id")
            .ends_with("/Managers/BMC-Other/NetworkProtocol"),
        "{protocol}"
    );
}

#[tokio::test]
async fn the_supermicro_scripts_satisfy_the_lockdown_and_setup_reads() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));
    let manager = "/redfish/v1/Managers/iDRAC.Embedded.1";

    // Lockdown is read as three things at once, being lockdown off, KCS at
    // Administrator and the host interface on. All three have to agree.
    let collection: serde_json::Value = client()
        .get(format!("https://{}{manager}/HostInterfaces", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    // Exactly one, since the caller refuses a collection of any other size
    // rather than picking one out of it.
    assert_eq!(collection["Members@odata.count"], 1, "{collection}");

    let interface: serde_json::Value = client()
        .get(format!(
            "https://{}{manager}/HostInterfaces/Self",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(interface["InterfaceEnabled"], true);

    // Serial over LAN counts as configured only when every one of these nine
    // matches the vendor default, so a single wrong field fails the check.
    let serial: serde_json::Value = client()
        .get(format!(
            "https://{}{manager}/SerialInterfaces/1",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    for (key, value) in [
        ("InterfaceEnabled", serde_json::json!(true)),
        ("SignalType", serde_json::json!("Rs232")),
        ("BitRate", serde_json::json!("115200")),
        ("Parity", serde_json::json!("None")),
        ("DataBits", serde_json::json!("8")),
        ("StopBits", serde_json::json!("1")),
        ("FlowControl", serde_json::json!("None")),
        ("ConnectorType", serde_json::json!("RJ45")),
        ("PinOut", serde_json::json!("Cyclades")),
    ] {
        assert_eq!(serial[key], value, "{key}");
    }

    // The setup step refuses to configure anything at all when the TPM
    // attribute is absent, so it is added to a BIOS that does not name it.
    let bios: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-1/Bios",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(bios["Attributes"]["SecurityDeviceSupport"], "Enabled");
    // The BMC's own attributes are still underneath it.
    assert_eq!(bios["Attributes"]["BootMode"], "Uefi");

    // Serial console is reported on the system, and the check reads both the
    // SSH block and the session limit.
    let system: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Systems/Sys-1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(system["SerialConsole"]["SSH"]["ServiceEnabled"], true);
    assert_eq!(system["SerialConsole"]["MaxConcurrentSessions"], 1);
}

#[tokio::test]
async fn the_supermicro_scripts_satisfy_the_lockdown_contract_in_both_directions() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    let manager = "/redfish/v1/Managers/iDRAC.Embedded.1";
    let host_interfaces = format!("https://{}{manager}/HostInterfaces", proxy.addr);
    let kcs = format!(
        "https://{}{manager}/Oem/Supermicro/KCSInterface",
        proxy.addr
    );
    let lockdown = format!("https://{}{manager}/Oem/Supermicro/SysLockdown", proxy.addr);

    let read = |url: String| async move {
        client()
            .get(url)
            .send()
            .await
            .expect("request")
            .json::<serde_json::Value>()
            .await
            .expect("json")
    };
    let write = |url: String, body: serde_json::Value| async move {
        client()
            .patch(url)
            .json(&body)
            .send()
            .await
            .expect("request")
            .status()
    };

    // The caller reads the collection first and refuses any size but one, then
    // builds the member URL from the id it found rather than a fixed name.
    let collection = read(host_interfaces.clone()).await;
    assert_eq!(collection["Members@odata.count"], 1, "{collection}");
    let member = collection["Members"][0]["@odata.id"]
        .as_str()
        .expect("member id")
        .to_string();
    let interface = format!("https://{}{member}", proxy.addr);

    // The three are read together and only these values count as unlocked. Any
    // other combination reads as half-locked, which the caller waits on for ever.
    let unlocked = |lock: &serde_json::Value, k: &serde_json::Value, hi: &serde_json::Value| {
        assert_eq!(lock["SysLockdownEnabled"], false, "{lock}");
        assert_eq!(k["Privilege"], "Administrator", "{k}");
        assert_eq!(hi["InterfaceEnabled"], true, "{hi}");
    };
    let locked = |lock: &serde_json::Value, k: &serde_json::Value, hi: &serde_json::Value| {
        assert_eq!(lock["SysLockdownEnabled"], true, "{lock}");
        assert_eq!(k["Privilege"], "Callback", "{k}");
        assert_eq!(hi["InterfaceEnabled"], false, "{hi}");
    };

    // A machine arrives unlocked, which is what lets setup proceed at all.
    unlocked(
        &read(lockdown.clone()).await,
        &read(kcs.clone()).await,
        &read(interface.clone()).await,
    );

    // Locking, in the order the caller issues it, host interface first and the
    // lockdown flag last.
    assert_eq!(
        write(
            interface.clone(),
            serde_json::json!({"InterfaceEnabled": false})
        )
        .await,
        204
    );
    assert_eq!(
        write(kcs.clone(), serde_json::json!({"Privilege": "Callback"})).await,
        204
    );
    assert_eq!(
        write(
            lockdown.clone(),
            serde_json::json!({"SysLockdownEnabled": true})
        )
        .await,
        204
    );
    locked(
        &read(lockdown.clone()).await,
        &read(kcs.clone()).await,
        &read(interface.clone()).await,
    );

    // Some callers toggle only the lockdown flag and then require the whole
    // triple to read locked again, so the other two have to hold their values.
    assert_eq!(
        write(
            lockdown.clone(),
            serde_json::json!({"SysLockdownEnabled": false})
        )
        .await,
        204
    );
    let half = read(kcs.clone()).await;
    assert_eq!(
        half["Privilege"], "Callback",
        "a lockdown write moved the KCS privilege"
    );
    let half_hi = read(interface.clone()).await;
    assert_eq!(
        half_hi["InterfaceEnabled"], false,
        "a lockdown write moved the host interface"
    );
    assert_eq!(
        write(
            lockdown.clone(),
            serde_json::json!({"SysLockdownEnabled": true})
        )
        .await,
        204
    );
    locked(
        &read(lockdown.clone()).await,
        &read(kcs.clone()).await,
        &read(interface.clone()).await,
    );

    // Unlocking, in the reverse order the caller issues it.
    assert_eq!(
        write(
            lockdown.clone(),
            serde_json::json!({"SysLockdownEnabled": false})
        )
        .await,
        204
    );
    assert_eq!(
        write(
            kcs.clone(),
            serde_json::json!({"Privilege": "Administrator"})
        )
        .await,
        204
    );
    assert_eq!(
        write(
            interface.clone(),
            serde_json::json!({"InterfaceEnabled": true})
        )
        .await,
        204
    );
    unlocked(
        &read(lockdown.clone()).await,
        &read(kcs.clone()).await,
        &read(interface.clone()).await,
    );

    // A privilege outside the vendor's four would be stored and then fail to
    // parse on the next read, which stalls the caller rather than erroring here.
    assert_eq!(
        write(kcs.clone(), serde_json::json!({"Privilege": "Wizard"})).await,
        400
    );
    assert_eq!(read(kcs).await["Privilege"], "Administrator");
}

#[tokio::test]
async fn the_supermicro_scripts_serve_a_settings_object_for_every_boot_option() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    let settings = format!(
        "https://{}/redfish/v1/Systems/Sys-1/BootOptions/Boot0000/Settings",
        proxy.addr
    );

    // Supermicro hangs one of these off every object, and the option's own
    // document links to it, so the two have to name the same URL.
    let option: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-1/BootOptions/Boot0000",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        option["@Redfish.Settings"]["SettingsObject"]["@odata.id"],
        "/redfish/v1/Systems/Sys-1/BootOptions/Boot0000/Settings",
        "{option}"
    );

    let response = client().get(&settings).send().await.expect("request");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    assert_eq!(body["Id"], "Settings");
    // Both ids come off the URL rather than being pinned in the script.
    assert_eq!(body["BootOptionReference"], "Boot0000");
    assert_eq!(
        body["@odata.id"],
        "/redfish/v1/Systems/Sys-1/BootOptions/Boot0000/Settings"
    );
    assert_eq!(body["BootOptionEnabled"], true);

    // Nothing is ever pending, so a write is accepted rather than met with the
    // 405 a client has no way to act on.
    let written = client()
        .patch(&settings)
        .json(&serde_json::json!({"BootOptionEnabled": false}))
        .send()
        .await
        .expect("request");
    assert_eq!(written.status(), 204);

    // The BMC has no such resource, so a relayed write would only have 404ed.
    assert!(
        !seen
            .all()
            .iter()
            .any(|call| call.path.contains("/BootOptions/") && call.path.ends_with("/Settings")),
        "a settings write reached the BMC"
    );
}

#[tokio::test]
async fn the_supermicro_scripts_serve_the_collections_the_emulator_breaks_on() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &supermicro_config(&tls, bmc));

    for (path, kind) in [
        (
            "/redfish/v1/Systems/Sys-1/Storage",
            "#StorageCollection.StorageCollection",
        ),
        (
            "/redfish/v1/TaskService/Tasks",
            "#TaskCollection.TaskCollection",
        ),
    ] {
        let body: serde_json::Value = client()
            .get(format!("https://{}{path}", proxy.addr))
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("json");
        // An empty collection reads as "none of these", which is true. The BMC
        // answers one of these with a 500, which reads as a broken BMC.
        assert_eq!(body["@odata.type"], kind, "{path}");
        assert_eq!(body["Members@odata.count"], 0, "{path}");
    }

    // Deliberately still absent, because a client that finds this takes the OEM
    // boot path instead of the override the BMC really applies.
    let absent = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-1/Oem/Supermicro/FixedBootOrder",
            proxy.addr
        ))
        .send()
        .await
        .expect("request");
    assert_eq!(absent.status(), 404, "FixedBootOrder must stay unserved");
}

#[tokio::test]
async fn the_sushy_handler_answers_the_endpoints_the_emulator_lacks() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &sushy_config(&tls, bmc));

    // Each of these 404s upstream. An empty collection is the useful answer,
    // and a 502 would be what a missing error arm produced.
    for path in [
        "/redfish/v1/Systems/Sys-1/BootOptions",
        "/redfish/v1/UpdateService/FirmwareInventory",
        "/redfish/v1/Chassis/Sys-1/PCIeDevices",
    ] {
        let response = client()
            .get(format!("https://{}{path}", proxy.addr))
            .send()
            .await
            .expect("request");
        assert_eq!(response.status(), 200, "{path} did not tolerate the 404");
        let body: serde_json::Value = response.json().await.expect("json");
        assert_eq!(body["Members"], serde_json::json!([]), "{path}");
        assert_eq!(body["Members@odata.count"], 0, "{path}");
    }
}

#[tokio::test]
async fn the_sushy_handler_expands_the_collections_left_shallow() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &sushy_config(&tls, bmc));

    let accounts: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/AccountService/Accounts",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    // The collection shape, not the bare Members array libredfish returns, since
    // a Redfish client asking for this URL expects a collection.
    assert_eq!(accounts["Members"][0]["RoleId"], "Administrator");
    assert_eq!(accounts["Members"][1]["Id"], "admin");

    let integrity: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/ComponentIntegrity",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(integrity["Members"][0]["ComponentIntegrityType"], "SPDM");
}

#[tokio::test]
async fn the_sushy_handler_fills_the_gaps_that_emulator_leaves() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &sushy_config(&tls, bmc));

    // Derived from the UUID with hyphens out and uppercased. The fixture UUID
    // carries hex letters, so dropping either step fails this.
    let system: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Systems/Sys-1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(system["SerialNumber"], "03000200040005000006ABCDEF080009");
    assert_eq!(system["Id"], "Sys-1");

    // The two predicates that have no endpoint of their own ride along here.
    assert_eq!(system["Oem"]["Proxy"]["BiosSetup"], true);
    assert_eq!(system["Oem"]["Proxy"]["BootOrderSetup"], false);

    // The BMC ignores `$expand`, so members must have been fetched one by one.
    let before = seen.count();
    let interfaces: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-1/EthernetInterfaces",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(interfaces["Members"][0]["MACAddress"], "AA:BB:CC:DD:EE:01");
    assert_eq!(interfaces["Members"][1]["Id"], "NIC.2");

    let fetched: Vec<_> = seen.all().split_off(before);
    assert!(
        fetched.iter().any(|r| r.path.ends_with("/NIC.1")),
        "the shallow members were never walked: {fetched:?}"
    );
    // This branch needs no system id, so it must not walk the service root.
    assert!(
        !fetched.iter().any(|r| r.path == "/redfish/v1/Systems"),
        "an id was resolved for a request that never uses one: {fetched:?}"
    );

    // UefiDevicePath is absent upstream and comes from the table on disk.
    let nic: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-1/EthernetInterfaces/NIC.1",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(
        nic["UefiDevicePath"],
        "PciRoot(0x0)/Pci(0x1C,0x0)/MAC(AABBCCDDEE01,0x1)"
    );

    // No response leaked the BMC, through any of the three paths.
    let rendered = format!("{system}{interfaces}{nic}");
    assert!(!rendered.contains(&bmc.to_string()), "{rendered}");
}

#[tokio::test]
async fn the_sushy_handler_filters_and_sorts_pcie_devices() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &sushy_config(&tls, bmc));

    let body: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Chassis/1/PCIeDevices",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // Four upstream, of which one is Disabled and one names no manufacturer.
    // Zeta enumerates first, so the sort is doing work.
    let members = body["Members"].as_array().expect("members");
    let makers: Vec<&str> = members
        .iter()
        .map(|m| m["Manufacturer"].as_str().unwrap())
        .collect();
    assert_eq!(makers, ["Alpha", "Zeta"]);
    assert_eq!(members[0]["Id"], "Dev-A");
    assert_eq!(body["Members@odata.count"], 2);
}

#[tokio::test]
async fn the_sushy_handler_inlines_drives_and_skips_usb() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &sushy_config(&tls, bmc));

    let body: serde_json::Value = client()
        .get(format!(
            "https://{}/redfish/v1/Systems/Sys-1/Storage",
            proxy.addr
        ))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    // Each Drive ref is replaced by the document it points at, USB excluded.
    let drives = body["Members"][0]["Drives"].as_array().expect("drives");
    assert_eq!(drives.len(), 1, "the USB drive was not skipped: {drives:?}");
    assert_eq!(drives[0]["Id"], "Drive-1");
    assert_eq!(drives[0]["CapacityBytes"], 1_000_204_886_016u64);

    assert!(
        !seen.all().iter().any(|r| r.path.contains("USB-1")),
        "the USB drive was fetched before being skipped"
    );
}

// Logging.

const PASSWORD: &str = "supersecretpassword123";

const SESSION_TOKEN: &str = "session-token-that-must-not-be-logged";

// The base64 of `root` and PASSWORD joined, as Basic auth encodes them.
const ENCODED: &str = "cm9vdDpzdXBlcnNlY3JldHBhc3N3b3JkMTIz";

#[tokio::test]
async fn a_handler_can_log_a_response_it_built() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // A response the handler assembled has its own record, which is a different
    // path from logging one that came back from the BMC.
    let handler = r#"
        pub async fn handle(req) {
            resp::json(200, #{"Made": "up"}).log("info", true)
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "logbuilt.rn", handler));

    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    let logs = proxy.wait_for_log("response");
    assert!(
        logs.contains("Made"),
        "the built body was not logged\n{logs}"
    );
    assert!(logs.contains("application/json"), "{logs}");
}

#[tokio::test]
async fn a_handler_that_logs_nothing_leaves_no_record() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // The proxy emits nothing of its own now, so silence is a script's choice.
    let handler = "pub async fn handle(req) { bmc::forward().await?.rewrite() }";
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "quiet.rn", handler));

    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);
    let _ = response.text().await;

    let logs = proxy.logs();
    assert!(
        !logs.contains("\"request\""),
        "a request record appeared: {logs}"
    );
    assert!(
        !logs.contains("\"response\""),
        "a response record appeared: {logs}"
    );
}

#[tokio::test]
async fn a_level_typo_is_refused_rather_than_silently_narrowing() {
    let tls = tls();
    // `EnvFilter` reads an unknown word as a target name, so an unvalidated
    // typo would switch almost everything off instead of failing.
    let config = base_config(&tls, "192.0.2.10:443".parse().unwrap())
        .replace("level = \"info\"", "level = \"shout\"");
    let (ok, out) = check(&tls, &config);
    assert!(!ok, "a level that is not a level must fail startup");
    assert!(out.contains("logging.level"), "{out}");
    assert!(out.contains("shout"), "{out}");
}

#[tokio::test]
async fn a_script_cannot_read_a_credential_off_a_response() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // The BMC hands back an x-auth-token on this path. It must reach the
    // caller and stay invisible to the handler.
    let handler = r#"
        pub async fn handle(req) {
            let session = bmc::post("/redfish/v1/SessionService/Sessions", #{}).await?;
            let forwarded = bmc::forward().await?;
            resp::json(200, #{
                "from_subrequest": session.header("x-auth-token"),
                "from_forward": forwarded.header("x-auth-token"),
                "cookie": session.header("set-cookie"),
                "ordinary": session.header("content-type"),
            })
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "peek.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");

    assert_eq!(body["from_subrequest"], serde_json::Value::Null);
    assert_eq!(body["from_forward"], serde_json::Value::Null);
    // A response credential too, not only a request one.
    assert_eq!(body["cookie"], serde_json::Value::Null);
    // A header that is not a credential is still readable, or the filter is
    // simply hiding everything.
    assert_eq!(body["ordinary"], "application/json");
}

#[tokio::test]
async fn a_streaming_body_is_never_read_to_log_it() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // Asking to log a body the handler is streaming must not drain it, or an
    // event stream is buffered by the logger rather than by the proxy.
    let handler = r#"
        pub async fn handle(req) {
            bmc::forward().await?.rewrite()?.log("info", true)
        }
    "#;
    let proxy = start_proxy(
        &tls,
        &route_config(
            &tls,
            bmc,
            "sselog.rn",
            handler,
            "/redfish/v1/EventService/SSE",
            "",
        ),
    );

    let started = std::time::Instant::now();
    let response = client()
        .get(format!(
            "https://{}/redfish/v1/EventService/SSE",
            proxy.addr
        ))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    // The fixture holds the stream for 30 seconds, so returning at all is what
    // proves the logger did not wait for the body.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "logging drained the stream"
    );

    let logs = proxy.wait_for_log("response");
    let record: serde_json::Value = logs
        .lines()
        .filter(|line| line.trim_start().starts_with('{'))
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line.trim()).ok())
        .find(|r| r["fields"]["message"] == "response")
        .expect("no response record");
    assert_eq!(
        record["fields"]["body"], "None",
        "a streaming body was logged"
    );
}

#[tokio::test]
async fn an_oversized_body_is_logged_clipped_and_marked() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let response = client()
        .get(format!("https://{}/redfish/v1/Multibyte", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    // Over the cap it is clipped and marked, not dropped, and the clip must not
    // land inside a multi-byte character.
    let logs = proxy.wait_for_log("truncated");
    assert!(!logs.contains('\u{fffd}'), "a character was split\n{logs}");
    assert!(logs.contains('é'), "the clipped prefix is missing\n{logs}");
}

#[tokio::test]
async fn credentials_never_reach_the_log() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let response = client()
        .post(format!(
            "https://{}/redfish/v1/SessionService/Sessions",
            proxy.addr
        ))
        .basic_auth("root", Some(PASSWORD))
        .header("x-auth-token", SESSION_TOKEN)
        .header("cookie", "sessionid=alsosecret")
        .json(&serde_json::json!({"UserName": "root"}))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 201);

    // The real binary's real logging, not a subscriber a test installed. Wait
    // for the response line, so absence below means redacted, not not-yet-logged.
    let logs = proxy.wait_for_log("response");

    for secret in [PASSWORD, SESSION_TOKEN, ENCODED, "alsosecret"] {
        assert!(!logs.contains(secret), "credential {secret:?} leaked");
    }
    // The BMC response carried a token and a cookie too, and neither survives.
    assert!(
        !logs.contains("session-token-abc"),
        "an upstream token leaked"
    );
    assert!(!logs.contains("cookie-secret-xyz"), "a set-cookie leaked");
    assert!(
        logs.contains("set-cookie"),
        "the header name should be kept"
    );

    // Header names are kept, so an operator still sees auth was present.
    assert!(logs.contains("authorization"), "{logs}");
    assert!(logs.contains("<redacted>"), "{logs}");
    assert!(
        logs.contains("/redfish/v1/SessionService/Sessions"),
        "{logs}"
    );
}

#[test]
fn every_script_logs_both_halves() {
    // Logging is manual by design, so nothing but this stops a shipped script
    // serving a request silently. 59 of 72 exits had drifted that way once.
    fn handle_body(src: &str) -> Option<&str> {
        let start = src.find("pub async fn handle(")?;
        let open = src[start..].find('{')? + start;
        let mut depth = 0usize;
        for (offset, ch) in src[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&src[open + 1..open + offset]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Every `return` statement, at any nesting, as its own text.
    fn returns(body: &str) -> Vec<&str> {
        let bytes = body.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while let Some(found) = body[i..].find("return") {
            let at = i + found;
            let boundary = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
            if !boundary {
                i = at + 6;
                continue;
            }
            let mut depth = 0i32;
            let mut end = at;
            for (offset, ch) in body[at..].char_indices() {
                match ch {
                    '{' | '(' | '[' => depth += 1,
                    '}' | ')' | ']' => depth -= 1,
                    ';' if depth == 0 => {
                        end = at + offset;
                        break;
                    }
                    _ => {}
                }
            }
            if end == at {
                break;
            }
            out.push(&body[at..end]);
            i = end + 1;
        }
        out
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts");
    let mut checked = 0;
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read scripts dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rn") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read script");
            let name = path.display().to_string();
            checked += 1;

            assert!(
                src.contains("log::request"),
                "{name} logs no request; an operator would see the reply and not the ask"
            );

            let body = handle_body(&src).unwrap_or_else(|| panic!("{name} has no handle"));
            for statement in returns(body) {
                assert!(
                    statement.contains(".log("),
                    "{name} has a return that logs nothing:\n{statement}"
                );
            }

            // What is left after the last statement is the trailing expression,
            // which is an exit as much as any `return` is.
            let trimmed: String = body
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let trimmed = trimmed.trim_end();
            if !trimmed.ends_with(';') {
                let tail = trimmed.rsplit(';').next().unwrap_or(trimmed);
                assert!(
                    tail.contains(".log("),
                    "{name} ends with an expression that logs nothing:\n{tail}"
                );
            }
        }
    }
    assert!(checked >= 30, "only {checked} scripts were checked");
}

#[tokio::test]
async fn every_level_reaches_the_log_and_a_bad_one_is_refused() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            log::trace("at-trace");
            log::debug("at-debug");
            log::info("at-info");
            log::warn("at-warn");
            log::error("at-error");
            log::at("warn", "at-computed")?;
            log::event("info", "structured", #{"chassis": 1, "fan": "Fan1"})?;
            let refused = match log::at("shout", "never") {
                Ok(_) => "allowed",
                Err(_) => "refused",
            };
            resp::json(200, #{"refused": refused})
        }
    "#;
    let proxy = start_proxy(&tls, &rune_config(&tls, bmc, "levels.rn", handler));

    let body: serde_json::Value = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request")
        .json()
        .await
        .expect("json");
    assert_eq!(body["refused"], "refused");

    let logs = proxy.wait_for_log("at-computed");
    // trace and debug are below the default filter, so their absence is the
    // subscriber working rather than the helper failing.
    for present in ["at-info", "at-warn", "at-error", "at-computed"] {
        assert!(
            logs.contains(present),
            "{present} never reached the log: {logs}"
        );
    }
    assert!(logs.contains("structured"), "{logs}");
    assert!(
        logs.contains("Fan1"),
        "the event fields were dropped: {logs}"
    );
    assert!(!logs.contains("never"), "a bad level still logged: {logs}");
}

#[tokio::test]
async fn the_configured_level_and_timestamp_switch_are_honoured() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    let handler = r#"
        pub async fn handle(req) {
            log::debug("below-the-default-floor");
            resp::text(200, "ok")
        }
    "#;
    // The floor is lowered rather than raised, since the harness reads the
    // bound port out of the `listening` record and that is emitted at info.
    let config = rune_config(&tls, bmc, "levels2.rn", handler)
        .replace("level = \"info\"", "level = \"debug\"")
        .replace("timestamps = true", "timestamps = false");
    let proxy = start_proxy(&tls, &config);

    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    // A debug record only appears because the config asked for it.
    let logs = proxy.wait_for_log("below-the-default-floor");

    // Output is JSON, so the timestamp is a field rather than a prefix.
    let records: Vec<serde_json::Value> = logs
        .lines()
        .filter(|line| line.trim_start().starts_with('{'))
        .filter_map(|line| serde_json::from_str(line.trim()).ok())
        .collect();
    assert!(!records.is_empty(), "no JSON records at all: {logs}");
    for record in records {
        assert!(
            record.get("timestamp").is_none(),
            "timestamps = false still stamped a record: {record}"
        );
    }
}

// Reload and TLS.

#[tokio::test]
async fn a_custom_ca_verifies_the_bmc_and_a_wrong_one_refuses_it() {
    let tls = tls();
    let (bmc, seen) = spawn_bmc(&tls).await;

    // The fake BMC presents a leaf signed by this CA, so trusting it works.
    let trusted = start_proxy(
        &tls,
        &config_with(
            &tls,
            bmc,
            &format!(
                "accept_invalid_certs = false\n        ca_path = \"{}\"",
                tls.ca.display()
            ),
        ),
    );
    let ok = client()
        .get(format!("https://{}/redfish/v1", trusted.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(ok.status(), 200);
    assert_eq!(seen.count(), 1);
    drop(trusted);

    // Verification has to actually reject, or the passing half proves nothing.
    let untrusted = start_proxy(
        &tls,
        &config_with(
            &tls,
            bmc,
            &format!(
                "accept_invalid_certs = false\n        ca_path = \"{}\"",
                tls.other_ca.display()
            ),
        ),
    );
    let refused = client()
        .get(format!("https://{}/redfish/v1", untrusted.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(refused.status(), 502, "an untrusted BMC was accepted");
    assert_eq!(seen.count(), 1, "the request reached an unverified BMC");
}

#[tokio::test]
async fn reload_swaps_scripts_and_a_broken_one_keeps_the_old() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    script(
        &tls,
        "v.rn",
        "pub async fn handle(req) { resp::text(200, \"one\") }",
    );
    let config = format!(
        r#"{base}
        [[route]]
        path   = "/redfish/v1/Chassis/*"
        script = "v.rn"
        "#,
        base = base_config(&tls, bmc),
    );
    let proxy = start_proxy(&tls, &config);

    let get = || async {
        client()
            .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
            .send()
            .await
            .expect("request")
            .text()
            .await
            .expect("body")
    };
    assert_eq!(get().await, "one");

    script(
        &tls,
        "v.rn",
        "pub async fn handle(req) { resp::text(200, \"two\") }",
    );
    proxy.reload();
    assert_eq!(get().await, "two");

    // A typo must not take the listener down or start failing requests.
    script(&tls, "v.rn", "pub async fn handle( {{{");
    proxy.reload();
    assert_eq!(
        get().await,
        "two",
        "a broken reload replaced a working script"
    );
}

#[tokio::test]
async fn self_signed_bmcs_work_by_default() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // No ca_path, so accept_invalid_certs stays on, which is the common case.
    let proxy = start_proxy(&tls, &base_config(&tls, bmc));

    let response = client()
        .get(format!("https://{}/redfish/v1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);
}

// Startup validation, through `--check` on the real binary.

#[test]
fn a_base_url_with_a_path_is_refused() {
    let tls = tls();
    // `swap_authorities` substitutes the whole base, so a path here is prepended
    // to every rewritten link and nothing strips it back off on the way in.
    let config = base_config(&tls, "192.0.2.10:443".parse().unwrap()).replace(
        "external_base_url = \"https://proxy.example.net:8443\"",
        "external_base_url = \"https://proxy.example.net:8443/bmc1\"",
    );
    let (ok, out) = check(&tls, &config);

    assert!(!ok, "a base URL with a path must be refused");
    assert!(out.contains("external_base_url"), "{out}");
    assert!(out.contains("/bmc1"), "{out}");
}

#[test]
fn a_broken_script_fails_startup_rather_than_panicking() {
    let tls = tls();
    script(&tls, "bad.rn", "pub async fn handle( {{{");
    let config = format!(
        "{base}\n        [[route]]\n        path = \"/x\"\n        script = \"bad.rn\"\n",
        base = base_config(&tls, "192.0.2.10:443".parse().unwrap()),
    );
    let (ok, out) = check(&tls, &config);
    assert!(!ok, "a syntactically broken script must fail startup");
    assert!(out.contains("compil"), "{out}");
}

#[test]
fn a_ca_file_with_no_certificate_is_refused() {
    let tls = tls();
    // Present but useless, which is a different failure from absent. Dropping
    // the public roots for an empty bundle leaves nothing at all to trust.
    let junk = tls.path("not-a-ca.pem");
    std::fs::write(
        &junk,
        "-----BEGIN NOTHING-----\nzz\n-----END NOTHING-----\n",
    )
    .expect("write");
    let config = config_with(
        &tls,
        "192.0.2.10:443".parse().unwrap(),
        &format!(
            "accept_invalid_certs = false\n        ca_path = \"{}\"",
            junk.display()
        ),
    );
    let (ok, out) = check(&tls, &config);

    assert!(!ok, "a CA file with no usable certificate must be refused");
    assert!(out.contains("not-a-ca.pem"), "{out}");
}

#[test]
fn a_ca_path_with_verification_disabled_is_refused() {
    let tls = tls();
    let config = config_with(
        &tls,
        "192.0.2.10:443".parse().unwrap(),
        &format!(
            "accept_invalid_certs = true\n        ca_path = \"{}\"",
            tls.ca.display()
        ),
    );
    let (ok, out) = check(&tls, &config);
    // Accepting the pair silently would leave an operator believing their CA is
    // enforced when nothing is.
    assert!(!ok, "contradictory TLS settings must be refused");
    assert!(out.contains("contradict"), "{out}");
}

#[test]
fn a_config_file_that_does_not_exist_is_reported() {
    let tls = tls();
    let absent = tls.path("no-such-config.toml");
    let (ok, out) = support::check_path(&absent);

    assert!(!ok, "a missing config file must be refused");
    assert!(out.contains("no-such-config.toml"), "{out}");
}

#[test]
fn a_default_script_that_does_not_exist_is_refused() {
    let tls = tls();
    let config = base_config(&tls, "192.0.2.10:443".parse().unwrap()).replace(
        "default_script = \"passthrough.rn\"",
        "default_script = \"absent.rn\"",
    );
    let (ok, out) = check(&tls, &config);
    assert!(
        !ok,
        "a default script that is not on disk must fail startup"
    );
    assert!(out.contains("absent.rn"), "{out}");
}

#[tokio::test]
async fn a_generated_certificate_serves_and_names_what_a_client_dials() {
    let tls = tls();
    let (bmc, _) = spawn_bmc(&tls).await;
    // Names no material at all, which is how an operator asks for a generated one.
    let proxy = start_proxy(&tls, &config_without_tls(&tls, bmc, ""));

    // It has to actually terminate TLS rather than merely start, since a
    // certificate the handshake rejects still lets the process come up.
    let response = client()
        .get(format!("https://{}/redfish/v1/Chassis/1", proxy.addr))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);

    // The names are the point and nothing in this suite verifies them, so what
    // gets asserted is the proxy saying which ones it chose.
    let logs = proxy.logs();
    for name in ["localhost", "127.0.0.1", "proxy.example.net"] {
        assert!(
            logs.contains(name),
            "the generated certificate does not name {name}\n{logs}"
        );
    }
    // The listen address is loopback here and already named, so it must not be
    // repeated, and a wildcard must never be named at all.
    assert!(!logs.contains("0.0.0.0"), "a wildcard was named\n{logs}");
}

#[test]
fn a_half_configured_tls_pair_is_refused() {
    let tls = tls();
    let bmc = "192.0.2.10:443".parse().unwrap();

    // Naming one half is a mistake, and generating over the top of it would run
    // a proxy that quietly ignores the file the operator meant to serve.
    for (present, missing) in [("cert_path", "key_path"), ("key_path", "cert_path")] {
        let line = format!(r#"{present} = "{}""#, tls.cert.display());
        let (ok, output) = check(&tls, &config_without_tls(&tls, bmc, &line));
        assert!(!ok, "{present} alone was accepted\n{output}");
        assert!(
            output.contains(missing),
            "the failure does not name {missing}\n{output}"
        );
    }
}

#[test]
fn a_missing_ca_file_is_reported_with_its_path() {
    let tls = tls();
    let config = config_with(
        &tls,
        "192.0.2.10:443".parse().unwrap(),
        "accept_invalid_certs = false\n        ca_path = \"/nonexistent/site-ca.pem\"",
    );
    let (ok, out) = check(&tls, &config);
    assert!(!ok, "a missing CA bundle must fail at startup");
    assert!(out.contains("/nonexistent/site-ca.pem"), "{out}");
}

#[test]
fn a_missing_mandatory_key_is_refused_and_named() {
    let tls = tls();
    let complete = base_config(&tls, "192.0.2.10:443".parse().unwrap());

    // Every key is mandatory, so removing any one must fail startup naming the
    // key. The TLS pair is the exception, covered separately below.
    let mandatory = [
        ("listen", "listen"),
        ("address", "address"),
        ("accept_invalid_certs", "accept_invalid_certs"),
        ("timeout", "timeout"),
        ("external_base_url", "external_base_url"),
        ("level", "level"),
        ("timestamps", "timestamps"),
        ("script_dir", "script_dir"),
        ("default_script", "default_script"),
    ];
    assert!(
        mandatory
            .iter()
            .all(|(key, _)| complete.contains(&format!("{key} "))),
        "the complete config no longer sets every key this test removes"
    );

    for (key, named) in mandatory {
        let without: String = complete
            .lines()
            .filter(|line| !line.trim_start().starts_with(&format!("{key} ")))
            .collect::<Vec<_>>()
            .join("\n");
        let (ok, out) = check(&tls, &without);
        assert!(!ok, "a config missing {key} started anyway");
        assert!(out.contains(named), "the failure never named {key}: {out}");
        // `main` walks the source chain, so an error must not also render its
        // own source or the operator reads the same cause twice.
        assert_eq!(
            out.matches(&format!("missing field `{key}`")).count(),
            1,
            "the cause was rendered more than once: {out}"
        );
    }
}

#[test]
fn a_missing_script_dir_is_refused() {
    let tls = tls();
    // Every request needs a script, so a script_dir that is not there cannot be
    // deferred to first use.
    let config = base_config(&tls, "192.0.2.10:443".parse().unwrap()).replace(
        &tls.dir().join("scripts").display().to_string(),
        &tls.path("absent-scripts").display().to_string(),
    );
    let (ok, out) = check(&tls, &config);

    assert!(!ok, "a missing script_dir must be refused");
    assert!(out.contains("absent-scripts"), "{out}");
}

#[test]
fn a_pem_without_a_private_key_is_rejected_clearly() {
    let tls = tls();
    // The certificate file in both slots, so certs parse and the key does not.
    let cert = tls.path("cert.pem").display().to_string();
    let config = support::config_with_material(&tls, &cert, &cert);
    let (ok, out) = check(&tls, &config);

    assert!(!ok, "a PEM with no private key must be refused");
    assert!(out.contains("no private key"), "{out}");
}

#[test]
fn a_pem_without_certificates_is_rejected_clearly() {
    let tls = tls();
    let empty = tls.path("empty.pem");
    std::fs::write(&empty, "# no PEM blocks here\n").expect("write");
    let config = support::config_with_material(
        &tls,
        &empty.display().to_string(),
        &empty.display().to_string(),
    );
    let (ok, out) = check(&tls, &config);
    assert!(!ok, "a PEM with no certificates must be refused");
    assert!(out.contains("no certificates"), "{out}");
}

#[test]
fn a_route_naming_a_missing_script_is_refused() {
    let tls = tls();
    // The guard that makes `make install` ship scripts/ alongside the config.
    // A route may name a script the default_script check would never look at.
    let config = format!(
        "{base}\n        [[route]]\n        path   = \"/redfish/v1/Chassis/*\"\n        \
         script = \"never-written.rn\"\n",
        base = base_config(&tls, "192.0.2.10:443".parse().unwrap()),
    );
    let (ok, out) = check(&tls, &config);

    assert!(!ok, "a route naming a missing script must fail startup");
    assert!(out.contains("never-written.rn"), "{out}");
}

#[test]
fn a_route_with_an_invalid_method_is_refused() {
    let tls = tls();
    script(
        &tls,
        "m.rn",
        "pub async fn handle(req) { resp::status(200) }",
    );
    let route = |method: &str| {
        format!(
            "{base}\n        [[route]]\n        method = [\"{method}\"]\n        \
             path   = \"/redfish/v1/Chassis/*\"\n        script = \"m.rn\"\n",
            base = base_config(&tls, "192.0.2.10:443".parse().unwrap()),
        )
    };

    // A space is not a token character, so this is not a method at all.
    let (ok, out) = check(&tls, &route("GET POST"));
    assert!(!ok, "a malformed method must be refused");
    assert!(out.contains("GET POST"), "{out}");

    // An unfamiliar but well-formed name is accepted, because an extension
    // method is legal HTTP and the proxy is not the arbiter of which exist.
    let (ok, _) = check(&tls, &route("FETCH"));
    assert!(ok, "a token-shaped extension method should be allowed");
}

#[test]
fn a_stale_key_from_an_older_deployment_still_loads() {
    let tls = tls();
    let mut config = base_config(&tls, "192.0.2.10:443".parse().unwrap());
    config.push_str("\n[upstream]\nrequest_timeout = \"60s\"\nmetrics_listen = \"[::]:9090\"\n");
    let (ok, out) = check(&tls, &config);
    assert!(ok, "unknown keys must be tolerated, not fatal\n{out}");
}

#[test]
fn a_target_address_is_required() {
    let tls = tls();
    let (ok, out) = check(
        &tls,
        &format!(
            "[tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\n[target]\n",
            tls.cert.display(),
            tls.key.display()
        ),
    );
    assert!(!ok, "a config with no target must fail");
    assert!(out.contains("address"), "{out}");
}

#[test]
fn an_invalid_env_pattern_is_rejected_at_startup() {
    let tls = tls();
    let config = base_config(&tls, "192.0.2.10:443".parse().unwrap()).replace(
        "[rune]\n        script_dir",
        "[rune]\n        env_allow = \"BMC_[\"\n        script_dir",
    );
    let (ok, out) = check(&tls, &config);
    assert!(!ok, "an uncompilable regex must fail startup");
    assert!(out.contains("env_allow"), "{out}");
}

#[test]
fn an_invalid_route_glob_is_rejected_at_startup() {
    let tls = tls();
    script(
        &tls,
        "a.rn",
        "pub async fn handle(req) { resp::status(200) }",
    );
    let config = format!(
        "{base}\n        [[route]]\n        path = \"/redfish/[\"\n        script = \"a.rn\"\n",
        base = base_config(&tls, "192.0.2.10:443".parse().unwrap()),
    );
    let (ok, out) = check(&tls, &config);
    assert!(!ok, "a broken glob must be refused");
    assert!(out.contains("glob"), "{out}");
}

#[test]
fn an_ipv6_listen_address_is_refused() {
    let tls = tls();
    let config = format!(
        "listen = \"[::]:8443\"\n[tls]\ncert_path = \"{cert}\"\nkey_path = \"{key}\"\n[target]\naddress = \"192.0.2.10:443\"\n",
        cert = tls.cert.display(),
        key = tls.key.display(),
    );
    let (ok, out) = check(&tls, &config);
    assert!(
        !ok,
        "the proxy binds IPv4 only, so a v6 listen address must fail"
    );
    assert!(out.contains("listen"), "{out}");
}

#[test]
fn an_ipv6_target_address_is_refused() {
    let tls = tls();
    let config = format!(
        "[tls]\ncert_path = \"{cert}\"\nkey_path = \"{key}\"\n[target]\naddress = \"[2001:db8::1]:443\"\n",
        cert = tls.cert.display(),
        key = tls.key.display(),
    );
    let (ok, out) = check(&tls, &config);
    assert!(!ok, "the proxy dials IPv4 only, so a v6 target must fail");
    assert!(out.contains("address"), "{out}");
}

#[test]
fn duplicate_routes_are_rejected() {
    let tls = tls();
    script(
        &tls,
        "a.rn",
        "pub async fn handle(req) { resp::status(200) }",
    );
    let config = format!(
        r#"{base}
        [[route]]
        path   = "/redfish/v1/Chassis/*"
        script = "a.rn"

        [[route]]
        path   = "/redfish/v1/Chassis/*"
        script = "a.rn"
        "#,
        base = base_config(&tls, "192.0.2.10:443".parse().unwrap()),
    );
    let (ok, out) = check(&tls, &config);
    assert!(!ok, "ambiguous precedence must be refused");
    assert!(out.contains("duplicate route"), "{out}");
}

#[test]
fn missing_tls_material_is_reported_with_its_path() {
    let tls = tls();
    let config =
        support::config_with_material(&tls, "/nonexistent/cert.pem", "/nonexistent/key.pem");
    let (ok, out) = check(&tls, &config);
    assert!(!ok, "missing TLS material must fail");
    assert!(out.contains("/nonexistent/cert.pem"), "{out}");

    // main walks the source chain, so an error must not also render its own
    // source or the operator reads the same cause twice.
    assert_eq!(out.matches("os error 2").count(), 1, "{out}");
}

#[test]
fn scripts_cannot_reach_ambient_io() {
    let tls = tls();
    // The sandbox property. `http`, `fs` and `process` live in rune-modules,
    // which is deliberately not a dependency.
    for forbidden in [
        "pub async fn handle(r) { fs::read_to_string(\"/etc/shadow\").await }",
        "pub async fn handle(r) { http::Client::new() }",
        "pub async fn handle(r) { process::Command::new(\"sh\") }",
    ] {
        script(&tls, "io.rn", forbidden);
        let config = format!(
            "{base}\n        [[route]]\n        path = \"/x\"\n        script = \"io.rn\"\n",
            base = base_config(&tls, "192.0.2.10:443".parse().unwrap()),
        );
        let (ok, _) = check(&tls, &config);
        assert!(!ok, "a script reached ambient I/O: {forbidden}");
    }
}

// The harness. Inlined rather than a sibling file, since any `tests/*.rs`
// becomes its own binary and `tests/support/` existed only to dodge that.
mod support {
    //! Black-box harness. A fake BMC, and the real proxy run as a subprocess.

    // Nothing here imports the crate under test. The proxy is exercised only
    // through its binary, its config file, its socket and its stderr.

    #![allow(dead_code)]

    use std::io::{BufRead, BufReader, Write};
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::body::{Body, Bytes};
    use http::{HeaderValue, Request, Response, StatusCode};
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::{self, ServerConfig};

    /// The proxy binary, located by cargo rather than rebuilt by the test.
    const BINARY: &str = env!("CARGO_BIN_EXE_programmable-redfish-proxy");

    // TLS material.

    /// A CA, a leaf it signed, and an unrelated CA, all in one temp directory.
    pub struct Tls {
        dir: TempDir,
        pub ca: PathBuf,
        pub cert: PathBuf,
        pub key: PathBuf,
        pub other_ca: PathBuf,
    }

    impl Tls {
        pub fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        pub fn dir(&self) -> &Path {
            self.dir.path()
        }
    }

    /// Issues fresh material per test, so nothing is shared and nothing leaks.
    pub fn tls() -> Tls {
        let dir = tempfile::tempdir().expect("temp dir");
        let (ca, cert, key) = issue_chain();
        let (other_ca, _, _) = issue_chain();

        let material = Tls {
            ca: dir.path().join("ca.pem"),
            cert: dir.path().join("cert.pem"),
            key: dir.path().join("key.pem"),
            other_ca: dir.path().join("other-ca.pem"),
            dir,
        };
        std::fs::write(&material.ca, ca).expect("write ca");
        std::fs::write(&material.cert, cert).expect("write cert");
        std::fs::write(&material.key, key).expect("write key");
        std::fs::write(&material.other_ca, other_ca).expect("write other ca");
        material
    }

    /// A CA and a leaf it signs. rustls rejects a self-signed leaf as its own
    /// anchor, so the chain is required rather than tidy.
    fn issue_chain() -> (String, String, String) {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
            ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
        };

        fn named(name: &str) -> DistinguishedName {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, name);
            dn
        }

        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params.distinguished_name = named("programmable-redfish-proxy test CA");

        let ca_key = KeyPair::generate().expect("ca key");
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca self-signs");

        let mut leaf = CertificateParams::new(vec![
            "programmable-redfish-proxy.test".to_string(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ])
        .expect("leaf params");
        leaf.is_ca = IsCa::ExplicitNoCa;
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.distinguished_name = named("programmable-redfish-proxy.test");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let signed = leaf.signed_by(&leaf_key, &ca).expect("ca signs leaf");

        (ca.pem(), signed.pem(), leaf_key.serialize_pem())
    }

    /// The harness builds its own acceptor rather than calling the proxy's, so one
    /// TLS bug cannot break both sides identically and still pass.
    fn acceptor(cert_path: &Path, key_path: &Path) -> TlsAcceptor {
        static INSTALLED: std::sync::Once = std::sync::Once::new();
        INSTALLED.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(
            std::fs::read(cert_path).expect("read cert").as_slice(),
        ))
        .collect::<Result<_, _>>()
        .expect("parse certs");

        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(
            std::fs::read(key_path).expect("read key").as_slice(),
        ))
        .expect("parse key")
        .expect("a key is present");

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config");
        // The proxy speaks HTTP/1.1 upstream, so the fake BMC offers only that.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }

    // The fake BMC.

    /// What the fake BMC saw, so tests can assert on what was relayed.
    #[derive(Clone, Debug)]
    pub struct Seen {
        pub method: String,
        pub path: String,
        /// Kept apart from `path`, since dropping it is a real forwarding bug
        /// and `$expand` or `$select` living there changes what was asked for.
        pub query: String,
        pub body_len: usize,
        headers: Vec<(String, String)>,
    }

    impl Seen {
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }

        pub fn has_header(&self, name: &str) -> bool {
            self.header(name).is_some()
        }

        /// How many times a name arrived. `header` answers with the first, so a
        /// duplicate the peer must not receive is invisible without this.
        pub fn header_count(&self, name: &str) -> usize {
            self.headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .count()
        }
    }

    #[derive(Clone, Default)]
    pub struct Recorder(Arc<Mutex<Vec<Seen>>>);

    impl Recorder {
        pub fn all(&self) -> Vec<Seen> {
            self.0.lock().unwrap().clone()
        }

        pub fn last(&self) -> Seen {
            self.all().last().cloned().expect("the BMC saw no request")
        }

        pub fn count(&self) -> usize {
            self.0.lock().unwrap().len()
        }
    }

    fn json(status: StatusCode, body: String) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .expect("response builds")
    }

    use futures_util::StreamExt;

    /// Every response carrying a URL emits an absolute one, so a missing rewrite
    /// shows up as a leaked address rather than as nothing.
    async fn route(
        self_addr: SocketAddr,
        recorder: Recorder,
        request: Request<hyper::body::Incoming>,
    ) -> Result<Response<Body>, std::convert::Infallible> {
        let path = request.uri().path().to_string();
        let method = request.method().as_str().to_string();
        // Whether the caller asked for server-side expansion. Some collections
        // below honour it and some ignore it, which is the split sushy exposes.
        let expand = request.uri().query().is_some_and(|q| q.contains("$expand"));
        // Whether this caller wants the arms a plain BMC does not serve, so one
        // path can back both the relayed and the synthesised branch of a script.
        let served = request.uri().query().is_some_and(|q| q.contains("served"));
        let query = request.uri().query().unwrap_or_default().to_string();
        let verb = method.clone();
        let headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .filter_map(|(n, v)| Some((n.as_str().to_string(), v.to_str().ok()?.to_string())))
            .collect();

        let body = axum::body::to_bytes(Body::new(request.into_body()), 64 * 1024 * 1024)
            .await
            .unwrap_or_default();

        recorder.0.lock().unwrap().push(Seen {
            method,
            path: path.clone(),
            query,
            body_len: body.len(),
            headers,
        });

        let me = format!("https://{self_addr}");

        let response = match path.as_str() {
            // Claims a foreign vendor, plus a product that redirects even a
            // Supermicro claim. All three are overwritten or it is inherited.
            "/redfish/v1" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1","Relative":"/redfish/v1/Chassis",
                     "Vendor":"Dell","Product":"GB NVL","Oem":{{"Dell":{{"x":1}}}}}}"#
                ),
            ),
            "/redfish/v1/Chassis/1" => json(
                StatusCode::OK,
                format!(r#"{{"@odata.id":"{me}/redfish/v1/Chassis/1","Id":"1"}}"#),
            ),
            // A chassis the BMC does give a serial, which is its own and has to
            // survive rather than being overwritten with a derived one.
            "/redfish/v1/Chassis/Ser-1" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Chassis/Ser-1","Id":"Ser-1",
                     "SerialNumber":"CHASSIS-REAL-9"}}"#
                ),
            ),
            // The collection at the trailing-slash spelling, which `Chassis/*`
            // also matches, so a resource script has to hand it back as it came.
            "/redfish/v1/Chassis/" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Chassis","Members":[
                     {{"@odata.id":"{me}/redfish/v1/Chassis/1"}}],"Members@odata.count":1}}"#
                ),
            ),
            "/redfish/v1/Chassis/1/Thermal" => json(
                StatusCode::OK,
                format!(r#"{{"@odata.id":"{me}/x","Fans":[{{"Name":"Fan1"}}]}}"#),
            ),
            "/redfish/v1/SessionService/Sessions" => Response::builder()
                .status(StatusCode::CREATED)
                .header("content-type", "application/json")
                .header(
                    "location",
                    format!("{me}/redfish/v1/SessionService/Sessions/1"),
                )
                .header("x-auth-token", "session-token-abc")
                .header("set-cookie", "SessionToken=cookie-secret-xyz; Path=/")
                .body(Body::from(format!(r#"{{"@odata.id":"{me}/redfish/v1"}}"#)))
                .expect("response builds"),
            // `Content-Location` is BMC-relative like `Location`, so any absolute
            // URL in it is rewritten whatever authority it names.
            "/redfish/v1/Staged" => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header(
                    "content-location",
                    format!("{me}/redfish/v1/Staged/Settings"),
                )
                .body(Body::from(r#"{"Staged":true}"#))
                .expect("response builds"),
            // Declared JSON the parser cannot read, which is what a compressed
            // body looks like here since no decompression feature is built in.
            "/redfish/v1/Opaque" => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Body::from(format!("not-json {me}/redfish/v1/Leak")))
                .expect("response builds"),
            // Refuses a boot write with no JSON to describe why, which is how
            // real firmware answers with an HTML error page.
            "/redfish/v1/Systems/Sys-Sulk" if verb == "PATCH" => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", "text/plain")
                .body(Body::from("no"))
                .expect("response builds"),
            "/redfish/v1/Systems/Sys-Sulk" => json(
                StatusCode::OK,
                format!(r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-Sulk","Id":"Sys-Sulk"}}"#),
            ),
            // Two Link values, one of them not UTF-8, so rewriting one must not
            // take the other with it.
            "/redfish/v1/TwoLinks" => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("link", format!("<{me}/redfish/v1/Ours>; rel=describedby"))
                .header(
                    "link",
                    HeaderValue::from_bytes(b"<\xff\xfe>; rel=odd").expect("bytes"),
                )
                .body(Body::from(r#"{"Two":true}"#))
                .expect("response builds"),
            "/redfish/v1/Redirect" => Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("location", format!("{me}/redfish/v1/Elsewhere"))
                .body(Body::empty())
                .expect("response builds"),
            "/redfish/v1/Elsewhere" => json(StatusCode::OK, r#"{"Reached":"elsewhere"}"#.into()),
            "/redfish/v1/Unauthorized" => json(StatusCode::UNAUTHORIZED, r#"{"e":1}"#.into()),
            "/redfish/v1/Boom" => json(StatusCode::INTERNAL_SERVER_ERROR, r#"{"e":1}"#.into()),
            // Every URL shape that once slipped past the rewriter, in one response.
            "/redfish/v1/Awkward" => Response::builder()
                .status(StatusCode::CREATED)
                .header("content-type", "application/json")
                .header("location", "https://bmc01.corp.example/redfish/v1/ByName")
                .header(
                    "link",
                    "<https://redfish.dmtf.org/schemas/v1/Chassis.json>; rel=describedby",
                )
                .header(
                    "link",
                    format!("<{me}/redfish/v1/$metadata>; rel=describedby"),
                )
                .body(Body::from(format!(
                    r#"{{"OddPort":"https://{ip}:9999/redfish/v1/Odd",
                     "Vendor":"https://vendor.example/kb/1",
                     "Bracketed":"https://[2001:db8::1]:443/redfish/v1/Six",
                     "Bare":"see ://nothing here",
                     "Upper":"HTTPS://{ip}/redfish/v1/Up"}}"#,
                    ip = self_addr.ip(),
                )))
                .expect("response builds"),
            // Large enough to prove no size cap skips a body when rewriting.
            "/redfish/v1/Huge" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1","Pad":"{}"}}"#,
                    "x".repeat(4096)
                ),
            ),
            "/redfish/v1/EventService/SSE" => {
                let stream = futures_util::stream::once(async {
                    Ok::<Bytes, std::io::Error>(Bytes::from_static(b"data: first\n\n"))
                })
                .chain(futures_util::stream::once(async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok(Bytes::from_static(b"data: never\n\n"))
                }));
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/event-stream")
                    .body(Body::from_stream(stream))
                    .expect("response builds")
            }
            // A vendor `+json` type, which must still be buffered and rewritten
            // rather than streamed past the rewriter as an unknown type.
            "/redfish/v1/VendorJson" => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/vnd.dmtf.redfish+json")
                .body(Body::from(format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/VendorJson"}}"#
                )))
                .expect("response builds"),
            // Textual but not JSON, and it carries an absolute URL, which is the
            // case `util::rewrite_links_text` exists for.
            "/redfish/v1/$metadata" => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/xml")
                .body(Body::from(format!(
                    r#"<edmx:Edmx><edmx:Reference Uri="{me}/redfish/v1/schema.xml"/></edmx:Edmx>"#
                )))
                .expect("response builds"),
            "/redfish/v1/UpdateService/upload" => {
                json(StatusCode::ACCEPTED, r#"{"TaskState":"Running"}"#.into())
            }
            // A BMC that serves its own UpdateService, gated so the default stays
            // the 404 the synthesised branch needs. It has no inventory link.
            "/redfish/v1/UpdateService" if served => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/UpdateService","Id":"UpdateService",
                     "ServiceEnabled":false,"HttpPushUri":"/redfish/v1/UpdateService/upload"}}"#
                ),
            ),
            // Multi-byte throughout, so a clip lands mid-character unless the
            // proxy walks back to a boundary.
            "/redfish/v1/Multibyte" => json(
                StatusCode::OK,
                format!(r#"{{"Note":"{}"}}"#, "é".repeat(20_000)),
            ),
            "/redfish/v1/Slow" => {
                tokio::time::sleep(Duration::from_secs(30)).await;
                json(StatusCode::OK, r#"{"Slow":true}"#.into())
            }

            // Echoes the method and body back, so a script can prove what actually
            // reached the BMC rather than only that the call returned.
            "/redfish/v1/Echo" => json(
                StatusCode::OK,
                format!(
                    r#"{{"SawMethod":"{verb}","SawBody":{}}}"#,
                    match std::str::from_utf8(&body) {
                        Ok(text) if !text.is_empty() => text,
                        _ => "null",
                    }
                ),
            ),

            // A Redfish surface shaped like the hardware the libredfish scripts
            // target, enough to run the ported sushy and Dell handlers against.

            // The same collection at the trailing-slash spelling a real client
            // sends, which `Systems/*` matches since a star accepts an empty one.
            "/redfish/v1/Systems/" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems","Members":[
                     {{"@odata.id":"{me}/redfish/v1/Systems/Sys-1"}}],"Members@odata.count":1}}"#
                ),
            ),
            "/redfish/v1/Systems" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems","Members":[
                     {{"@odata.id":"{me}/redfish/v1/Systems/HGX_Baseboard_0"}},
                     {{"@odata.id":"{me}/redfish/v1/Systems/Sys-1"}}]}}"#
                ),
            ),
            // Enumerated first and carries no Bios, so the probe must move past it.
            "/redfish/v1/Systems/HGX_Baseboard_0" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/HGX_Baseboard_0","Id":"HGX_Baseboard_0"}}"#
                ),
            ),
            // Rejects a UefiHttp boot target, which is what makes the script's
            // fallback to Pxe observable rather than merely written down.
            "/redfish/v1/Systems/Sys-1" if verb == "PATCH" => {
                let asked = std::str::from_utf8(&body).unwrap_or_default();
                if asked.contains("UefiHttp") {
                    json(
                        StatusCode::BAD_REQUEST,
                        r#"{"error":{"code":"Base.1.0.PropertyValueNotInList"}}"#.into(),
                    )
                } else {
                    json(StatusCode::OK, format!(r#"{{"Patched":{asked}}}"#))
                }
            }
            // No SerialNumber, which is the gap the sushy script fills from UUID.
            "/redfish/v1/Systems/Sys-1" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-1","Id":"Sys-1",
                     "UUID":"03000200-0400-0500-0006-abcdef080009",
                     "SerialNumber":"  ",
                     "Bios":{{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/Bios"}},
                     "Links":{{"ManagedBy":[{{"@odata.id":"{me}/redfish/v1/Managers/iDRAC.Embedded.1"}}]}}}}"#
                ),
            ),
            // Neither a serial nor a UUID, which is the Supermicro that has no
            // serial at all and leaves nothing to derive one from.
            "/redfish/v1/Systems/Sys-Bare" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-Bare","Id":"Sys-Bare",
                     "SerialNumber":""}}"#
                ),
            ),
            // A serial the BMC does set, which must survive untouched, and one with
            // no SerialNumber key at all rather than a blank string.
            "/redfish/v1/Systems/Sys-Serial" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-Serial","Id":"Sys-Serial",
                     "UUID":"11111111-2222-3333-4444-555555555555",
                     "SerialNumber":"CN-0PN2MF-74261",
                     "Boot":{{"BootOrder":["BootFFFF","BootEEEE"]}}}}"#
                ),
            ),
            // The same system at the trailing-slash spelling libredfish dials,
            // which `Systems/*` does NOT match since a star never crosses a slash.
            "/redfish/v1/Systems/Sys-1/" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-1","Id":"Sys-1",
                     "UUID":"03000200-0400-0500-0006-abcdef080009","SerialNumber":"  "}}"#
                ),
            ),
            "/redfish/v1/Systems/Sys-1/BIOS/Actions/Bios.ResetBios" => {
                json(StatusCode::NO_CONTENT, String::new())
            }
            // A BIOS resource whose attributes lack the TPM key, which is the
            // gap the setup step refuses to start without.
            "/redfish/v1/Systems/Sys-1/Bios" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/Bios","Id":"BIOS",
                     "Attributes":{{"QuietBoot":true,"BootMode":"Uefi"}}}}"#
                ),
            ),
            // A BMC that serves SecureBoot itself, which is what the relay
            // path exists for. `Sys-1` deliberately has none.
            "/redfish/v1/Systems/Sys-Serial/SecureBoot" => json(
                StatusCode::OK,
                r#"{"@odata.id":"/redfish/v1/Systems/Sys-Serial/SecureBoot","Id":"SecureBoot",
                 "SecureBootEnable":true,"SecureBootCurrentBoot":"Enabled",
                 "SecureBootMode":"DeployedMode"}"#
                    .into(),
            ),
            "/redfish/v1/Systems/Sys-Absent" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-Absent","Id":"Sys-Absent",
                     "UUID":"deadbeef-0400-0500-0006-00070008000f"}}"#
                ),
            ),
            // First member is deliberately not the managing one, so a manager id
            // taken from here rather than from Links.ManagedBy is visibly wrong.
            "/redfish/v1/Managers" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Managers","Members":[
                     {{"@odata.id":"{me}/redfish/v1/Managers/BMC-Other"}},
                     {{"@odata.id":"{me}/redfish/v1/Managers/iDRAC.Embedded.1"}}]}}"#
                ),
            ),
            "/redfish/v1/Managers/iDRAC.Embedded.1" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Managers/iDRAC.Embedded.1","Id":"iDRAC.Embedded.1",
                     "Oem":{{"Dell":{{"DelliDRACCard":{{"IPMIVersion":"2.0"}}}}}}}}"#
                ),
            ),
            // Ignores `$expand`, so Members stay shallow and the client must walk them.
            "/redfish/v1/Systems/Sys-1/EthernetInterfaces" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/EthernetInterfaces","Members":[
                     {{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/EthernetInterfaces/NIC.1"}},
                     {{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/EthernetInterfaces/NIC.2"}}]}}"#
                ),
            ),
            "/redfish/v1/Systems/Sys-1/EthernetInterfaces/NIC.1" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/EthernetInterfaces/NIC.1",
                     "Id":"NIC.1","MACAddress":"AA:BB:CC:DD:EE:01"}}"#
                ),
            ),
            "/redfish/v1/Systems/Sys-1/EthernetInterfaces/NIC.2" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/EthernetInterfaces/NIC.2",
                     "Id":"NIC.2","MACAddress":"AA:BB:CC:DD:EE:02"}}"#
                ),
            ),
            // Valid values are discovered here rather than hardcoded in the script.
            "/redfish/v1/Systems/Sys-1/Bios/BiosRegistry" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/Bios/BiosRegistry",
                     "RegistryEntries":{{"Attributes":[
                       {{"AttributeName":"HttpDev1Interface","Type":"Enumeration",
                         "Value":[{{"ValueName":"NIC.1"}},{{"ValueName":"NIC.2"}}]}},
                       {{"AttributeName":"HttpDev1TlsMode","Type":"Enumeration",
                         "Value":[{{"ValueName":"None"}},{{"ValueName":"OneWay"}}]}}]}}}}"#
                ),
            ),
            // Honours `$expand`, unlike the interfaces collection above.
            "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs" if expand => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs","Members":[
                     {{"@odata.id":"{me}/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/JID_001",
                       "Id":"JID_001","JobState":"Scheduled"}}]}}"#
                ),
            ),
            "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs","Members":[
                     {{"@odata.id":"{me}/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/JID_001"}}]}}"#
                ),
            ),
            "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/JID_001" => json(
                StatusCode::OK,
                r#"{"Id":"JID_001","JobState":"Scheduled"}"#.into(),
            ),
            // The rest of the emulator's surface, defects included. Every collection
            // here ignores `$expand`, which is why the script expands them itself.
            "/redfish/v1/AccountService/Accounts" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/AccountService/Accounts","Members":[
                     {{"@odata.id":"{me}/redfish/v1/AccountService/Accounts/root"}},
                     {{"@odata.id":"{me}/redfish/v1/AccountService/Accounts/admin"}}]}}"#
                ),
            ),
            "/redfish/v1/AccountService/Accounts/root" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/AccountService/Accounts/root","Id":"root","RoleId":"Administrator"}}"#
                ),
            ),
            "/redfish/v1/AccountService/Accounts/admin" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/AccountService/Accounts/admin","Id":"admin","RoleId":"Operator"}}"#
                ),
            ),
            "/redfish/v1/ComponentIntegrity" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/ComponentIntegrity","Members":[
                     {{"@odata.id":"{me}/redfish/v1/ComponentIntegrity/CI-1"}}]}}"#
                ),
            ),
            "/redfish/v1/ComponentIntegrity/CI-1" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/ComponentIntegrity/CI-1","Id":"CI-1","ComponentIntegrityType":"SPDM"}}"#
                ),
            ),
            // Zeta enumerates before Alpha, so an unsorted result is visibly wrong.
            // One member is Disabled and one has no Manufacturer, so both drop out.
            "/redfish/v1/Chassis/1/PCIeDevices" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Chassis/1/PCIeDevices","Members":[
                     {{"@odata.id":"{me}/redfish/v1/Chassis/1/PCIeDevices/Dev-Z"}},
                     {{"@odata.id":"{me}/redfish/v1/Chassis/1/PCIeDevices/Dev-A"}},
                     {{"@odata.id":"{me}/redfish/v1/Chassis/1/PCIeDevices/Dev-Off"}},
                     {{"@odata.id":"{me}/redfish/v1/Chassis/1/PCIeDevices/Dev-Bare"}}]}}"#
                ),
            ),
            "/redfish/v1/Chassis/1/PCIeDevices/Dev-Z" => json(
                StatusCode::OK,
                r#"{"Id":"Dev-Z","Manufacturer":"Zeta","Status":{"State":"Enabled"}}"#.into(),
            ),
            "/redfish/v1/Chassis/1/PCIeDevices/Dev-A" => json(
                StatusCode::OK,
                r#"{"Id":"Dev-A","Manufacturer":"Alpha","Status":{"State":"Enabled"}}"#.into(),
            ),
            "/redfish/v1/Chassis/1/PCIeDevices/Dev-Off" => json(
                StatusCode::OK,
                r#"{"Id":"Dev-Off","Manufacturer":"Alpha","Status":{"State":"Disabled"}}"#.into(),
            ),
            "/redfish/v1/Chassis/1/PCIeDevices/Dev-Bare" => json(
                StatusCode::OK,
                r#"{"Id":"Dev-Bare","Status":{"State":"Enabled"}}"#.into(),
            ),
            "/redfish/v1/Systems/Sys-1/Storage" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/Storage","Members":[
                     {{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/Storage/S1"}}]}}"#
                ),
            ),
            "/redfish/v1/Systems/Sys-1/Storage/S1" => json(
                StatusCode::OK,
                format!(
                    r#"{{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/Storage/S1","Id":"S1","Drives":[
                     {{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/Drives/Drive-1"}},
                     {{"@odata.id":"{me}/redfish/v1/Systems/Sys-1/Drives/USB-1"}}]}}"#
                ),
            ),
            "/redfish/v1/Systems/Sys-1/Drives/Drive-1" => json(
                StatusCode::OK,
                r#"{"Id":"Drive-1","CapacityBytes":1000204886016}"#.into(),
            ),
            "/redfish/v1/Systems/Sys-1/Drives/USB-1" => json(
                StatusCode::OK,
                r#"{"Id":"USB-1","CapacityBytes":8000000}"#.into(),
            ),
            // Vanilla sushy has none of these at all, which the script tolerates.
            "/redfish/v1/Systems/Sys-1/BootOptions"
            | "/redfish/v1/UpdateService/FirmwareInventory"
            | "/redfish/v1/Chassis/Sys-1/PCIeDevices" => {
                json(StatusCode::NOT_FOUND, r#"{"e":"missing"}"#.into())
            }

            "/redfish/v1/Systems/Sys-1/Bios/Settings" if verb == "PATCH" => Response::builder()
                .status(StatusCode::ACCEPTED)
                .header("content-type", "application/json")
                .header(
                    "location",
                    format!("{me}/redfish/v1/TaskService/Tasks/JID_100"),
                )
                .body(Body::from(r#"{"Accepted":true}"#))
                .expect("response builds"),

            _ => json(StatusCode::NOT_FOUND, r#"{"e":"missing"}"#.into()),
        };

        Ok(response)
    }

    /// Starts the fake BMC on an ephemeral IPv4 port.
    pub async fn spawn_bmc(tls: &Tls) -> (SocketAddr, Recorder) {
        start_bmc(tls).await
    }

    async fn start_bmc(tls: &Tls) -> (SocketAddr, Recorder) {
        let acceptor = acceptor(&tls.cert, &tls.key);
        let tcp = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake bmc");
        let addr = tcp.local_addr().expect("local addr");
        let recorder = Recorder::default();

        let served = recorder.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = tcp.accept().await else {
                    continue;
                };
                let acceptor = acceptor.clone();
                let recorder = served.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |r| route(addr, recorder.clone(), r));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });

        (addr, recorder)
    }

    /// The RFC 7541 codes for the characters header names use.
    const HUFFMAN: &[(&str, char)] = &[
        ("00010", '-'),
        ("00011", '.'),
        ("00111", '0'),
        ("01000", '1'),
        ("01001", '2'),
        ("100011", 'a'),
        ("100100", 'b'),
        ("100101", 'c'),
        ("100110", 'd'),
        ("100111", 'e'),
        ("101000", 'f'),
        ("101001", 'g'),
        ("101010", 'h'),
        ("101011", 'i'),
        ("1101110", 'j'),
        ("1101111", 'k'),
        ("101100", 'l'),
        ("101101", 'm'),
        ("101110", 'n'),
        ("101111", 'o'),
        ("110000", 'p'),
        ("1110001", 'q'),
        ("110001", 'r'),
        ("110010", 's'),
        ("110011", 't'),
        ("1110010", 'u'),
        ("1110011", 'v'),
        ("1110100", 'w'),
        ("1110101", 'x'),
        ("1110110", 'y'),
        ("1110111", 'z'),
    ];

    // The proxy, as a subprocess.

    /// A running proxy. Killed on drop, so a failing test leaves nothing behind.
    pub struct Proxy {
        child: Child,
        pub addr: SocketAddr,
        logs: Arc<Mutex<String>>,
    }

    impl Proxy {
        /// Everything the proxy has logged so far.
        pub fn logs(&self) -> String {
            self.logs.lock().unwrap().clone()
        }

        /// Waits for a line matching `needle`, then returns the whole log. The
        /// proxy logs on its own thread, so reading straight after a response races.
        pub fn wait_for_log(&self, needle: &str) -> String {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while std::time::Instant::now() < deadline {
                let logs = self.logs();
                if logs.contains(needle) {
                    return logs;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("{needle:?} never appeared in the log\n{}", self.logs());
        }

        /// Sends SIGHUP, which is how an operator reloads scripts, then waits for
        /// the proxy to say it finished rather than sleeping and hoping.
        pub fn reload(&self) {
            let before = self.logs().matches("reload").count();
            let _ = Command::new("kill")
                .arg("-HUP")
                .arg(self.child.id().to_string())
                .status();

            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while std::time::Instant::now() < deadline {
                if self.logs().matches("reload").count() > before {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("the proxy never reported a reload\n{}", self.logs());
        }
    }

    impl Drop for Proxy {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Writes `config` and starts the proxy, waiting for it to report a bound port.
    /// Use `listen = "127.0.0.1:0"` so the OS picks and no test races for a port.
    pub fn start_proxy(tls: &Tls, config: &str) -> Proxy {
        start_proxy_env(tls, config, &[])
    }

    /// As [`start_proxy`], with variables set on the child only. Setting them in
    /// the test process would race, since tests share one environment.
    pub fn start_proxy_env(tls: &Tls, config: &str, env: &[(&str, &str)]) -> Proxy {
        let path = tls.path("proxy.toml");
        std::fs::write(&path, config).expect("write config");

        let mut command = Command::new(BINARY);
        command.arg("--config-path").arg(&path);
        for (name, value) in env {
            command.env(name, value);
        }

        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the proxy binary");

        let logs = Arc::new(Mutex::new(String::new()));
        let (tx, rx) = std::sync::mpsc::channel();

        // tracing_subscriber writes to stdout, and a panic would go to stderr, so
        // drain both or a full pipe would block the proxy.
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        drain(stdout, Arc::clone(&logs), Some(tx));
        drain(stderr, Arc::clone(&logs), None);

        let addr = rx
            .recv_timeout(Duration::from_secs(30))
            .unwrap_or_else(|_| {
                panic!(
                    "proxy never reported a bound port\n{}",
                    logs.lock().unwrap()
                )
            });

        Proxy { child, addr, logs }
    }

    /// Reads a child stream into the shared log, reporting the bound port once.
    fn drain<R: std::io::Read + Send + 'static>(
        stream: R,
        logs: Arc<Mutex<String>>,
        found: Option<std::sync::mpsc::Sender<SocketAddr>>,
    ) {
        std::thread::spawn(move || {
            let mut found = found;
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if let Some(addr) = bound_addr(&line)
                    && let Some(sender) = found.take()
                {
                    let _ = sender.send(addr);
                }
                let mut logs = logs.lock().unwrap();
                logs.push_str(&line);
                logs.push('\n');
            }
        });
    }

    /// Pulls the bound address out of the `listening` record, now a JSON field
    /// rather than an `addr=` token.
    fn bound_addr(line: &str) -> Option<SocketAddr> {
        let record: serde_json::Value = serde_json::from_str(strip_ansi(line).trim()).ok()?;
        record["fields"]["addr"].as_str()?.parse().ok()
    }

    fn strip_ansi(line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for skip in chars.by_ref() {
                    if skip.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Runs the binary with `--check`, returning success and its output. Assert on a
    /// stable substring, since a whole message breaks on any rewording.
    pub fn check(tls: &Tls, config: &str) -> (bool, String) {
        let path = tls.path("check.toml");
        std::fs::write(&path, config).expect("write config");
        check_path(&path)
    }

    /// As [`check`], against a path the caller owns, which is the only way to
    /// exercise a config file that is not there.
    pub fn check_path(path: &std::path::Path) -> (bool, String) {
        let out = Command::new(BINARY)
            .arg("--config-path")
            .arg(path)
            .arg("--check")
            .output()
            .expect("run the proxy binary");

        let mut text = String::from_utf8_lossy(&out.stderr).to_string();
        text.push_str(&String::from_utf8_lossy(&out.stdout));
        (out.status.success(), strip_ansi(&text))
    }

    // Config building.

    pub const PROXY_BASE: &str = "https://proxy.example.net:8443";

    /// The config every test starts from. Port zero, so the OS picks.
    pub fn base_config(tls: &Tls, bmc: SocketAddr) -> String {
        config_with(tls, bmc, "")
    }

    /// The shipped pass-through. Every config needs one on disk now.
    pub const PASSTHROUGH: &str = concat!(
        "pub async fn handle(req) { log::request(\"info\", true)?; ",
        "bmc::forward().await?.rewrite()?.log(\"info\", true) }"
    );

    /// As [`base_config`], with extra keys spliced into the `[target]` section.
    /// Explicit, because a key appended on the end lands under `[rewrite]`.
    pub fn config_with(tls: &Tls, bmc: SocketAddr, target_extra: &str) -> String {
        script(tls, "passthrough.rn", PASSTHROUGH);
        // Every key is mandatory now, so the harness has to state them all. The
        // two the extra may also set are skipped, since a duplicate key is fatal.
        let mut target = format!("address = \"{bmc}\"\n        {target_extra}\n");
        if !target_extra.contains("accept_invalid_certs") {
            target.push_str("        accept_invalid_certs = true\n");
        }
        if !target_extra.contains("timeout") {
            target.push_str("        timeout = \"60s\"\n");
        }

        format!(
            r#"
        listen = "127.0.0.1:0"

        [tls]
        cert_path = "{cert}"
        key_path  = "{key}"

        [target]
        {target}
        [rewrite]
        external_base_url = "{PROXY_BASE}"

        [logging]
        level = "info"
        timestamps = true

        [rune]
        script_dir = "{scripts}"
        default_script = "passthrough.rn"
        "#,
            cert = tls.cert.display(),
            key = tls.key.display(),
            scripts = tls.dir().join("scripts").display(),
        )
    }

    /// A complete config that names no TLS material, so the proxy mints its own.
    /// `extra` is spliced into `[tls]`, for the half-configured cases.
    pub fn config_without_tls(tls: &Tls, bmc: SocketAddr, extra: &str) -> String {
        let full = config_with(tls, bmc, "");
        let mut out = String::new();
        for line in full.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("cert_path") || trimmed.starts_with("key_path") {
                continue;
            }
            out.push_str(line);
            out.push('\n');
            if trimmed == "[tls]" && !extra.is_empty() {
                out.push_str("        ");
                out.push_str(extra);
                out.push('\n');
            }
        }
        out
    }

    /// A complete config whose TLS material is named explicitly, for the startup
    /// cases about the material rather than about serving.
    pub fn config_with_material(tls: &Tls, cert: &str, key: &str) -> String {
        script(tls, "passthrough.rn", PASSTHROUGH);
        format!(
            r#"
        listen = "127.0.0.1:0"

        [tls]
        cert_path = "{cert}"
        key_path  = "{key}"

        [target]
        address = "192.0.2.10:443"
        accept_invalid_certs = true
        timeout = "60s"

        [rewrite]
        external_base_url = "{PROXY_BASE}"

        [logging]
        level = "info"
        timestamps = true

        [rune]
        script_dir = "{scripts}"
        default_script = "passthrough.rn"
        "#,
            scripts = tls.dir().join("scripts").display(),
        )
    }

    /// Completes a TLS handshake offering both protocols and reports what the
    /// server picked, so a test can assert h2 was never on the table.
    pub async fn negotiated_protocol(tls: &Tls, addr: SocketAddr) -> Option<String> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut BufReader::new(
            std::fs::read(&tls.ca).expect("read ca").as_slice(),
        )) {
            roots.add(cert.expect("parse ca")).expect("add ca");
        }
        let mut config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")
            .expect("server name");
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .expect("tls handshake");
        tls.get_ref()
            .1
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string())
    }

    /// A client that behaves like a Redfish one, verifying nothing and following no
    /// redirects, so tests can see them.
    pub fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .expect("client builds")
    }

    /// Copies a script the repo actually ships into the temp `script_dir`, so a
    /// test proves the artifact rather than a second copy of it.
    pub fn shipped(tls: &Tls, name: &str) -> PathBuf {
        let dir = tls.dir().join("scripts");
        let dest = dir.join(name);
        std::fs::create_dir_all(dest.parent().unwrap_or(&dir)).expect("script dir");
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scripts")
            .join(name);
        std::fs::copy(&src, &dest)
            .unwrap_or_else(|error| panic!("copying {}: {error}", src.display()));
        dir
    }

    /// Writes a Rune script into the material directory and returns its directory.
    pub fn script(tls: &Tls, name: &str, body: &str) -> PathBuf {
        let dir = tls.dir().join("scripts");
        std::fs::create_dir_all(&dir).expect("script dir");
        let mut file = std::fs::File::create(dir.join(name)).expect("script file");
        file.write_all(body.as_bytes()).expect("write script");
        dir
    }
}
