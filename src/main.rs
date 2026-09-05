// SPDX-License-Identifier: Unlicense

//! A standalone Redfish/BMC reverse proxy with Rune-scripted endpoints.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

mod config;
mod http;
mod proxy;
mod rune_host;
mod script_bmc;
mod script_store;
mod script_util;
// The TLS listener. Inlined rather than its own file, since `main` is its
// only consumer. Kept as a module so `read` is not a file-scope name.
mod listener {
    //! TLS listener. No client certificate is requested and a self-signed server
    //! certificate is fine, because callers authenticate to the BMC, not to us.

    use std::io::BufReader;
    use std::net::SocketAddrV4;
    use std::path::Path;
    use std::sync::Arc;

    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{self, ServerConfig};

    #[derive(Debug, thiserror::Error)]
    pub enum TlsError {
        #[error("reading {path}")]
        Read {
            path: String,
            #[source]
            source: std::io::Error,
        },
        #[error("no certificates found in {0}")]
        NoCertificates(String),
        #[error("no private key found in {0}")]
        NoPrivateKey(String),
        #[error("building TLS configuration: {0}")]
        Config(#[from] rustls::Error),
        #[error("generating a self-signed certificate")]
        Generate(#[from] rcgen::Error),
    }

    /// Certificate chain and key, however they were come by.
    pub struct Material {
        pub certs: Vec<CertificateDer<'static>>,
        pub key: PrivateKeyDer<'static>,
    }

    fn read(path: &Path) -> Result<Vec<u8>, TlsError> {
        std::fs::read(path).map_err(|source| TlsError::Read {
            path: path.display().to_string(),
            source,
        })
    }

    /// Reads a certificate chain and key off disk. A named but unusable path is
    /// an error, since serving a different certificate would hide the typo.
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Material, TlsError> {
        let cert_bytes = read(cert_path)?;
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut BufReader::new(cert_bytes.as_slice()))
                .collect::<Result<_, _>>()
                .map_err(|source| TlsError::Read {
                    path: cert_path.display().to_string(),
                    source,
                })?;
        if certs.is_empty() {
            return Err(TlsError::NoCertificates(cert_path.display().to_string()));
        }

        let key_bytes = read(key_path)?;
        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
                .map_err(|source| TlsError::Read {
                    path: key_path.display().to_string(),
                    source,
                })?
                .ok_or_else(|| TlsError::NoPrivateKey(key_path.display().to_string()))?;

        Ok(Material { certs, key })
    }

    /// Mints a certificate for the names a client might dial us by. Held in
    /// memory and reissued every start, since nothing verifies or pins it.
    pub fn generate(names: Vec<String>) -> Result<Material, TlsError> {
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        };

        let mut params = CertificateParams::new(names)?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "programmable-redfish-proxy");
        params.distinguished_name = name;

        // A year, counted from now. Nothing here outlives the process, so this
        // bounds a certificate that has already been replaced by then.
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(365);

        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;

        Ok(Material {
            certs: vec![cert.der().clone()],
            // rcgen serialises PKCS#8, which is the shape rustls wants.
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        })
    }

    /// Wraps material in a rustls acceptor.
    pub fn acceptor(material: Material) -> Result<TlsAcceptor, TlsError> {
        // The process-level provider. With more than one candidate rustls refuses to
        // choose, and an error here means one is already installed, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let Material { certs, key } = material;

        let mut config = ServerConfig::builder()
            // No client auth, since callers authenticate to the BMC, not to us.
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        // HTTP/1.1 only. Many BMCs speak nothing else, and one protocol on
        // both sides means one set of framing rules to reason about.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// Binds and reports the address actually bound, not the one requested.
    /// With a port of zero the OS picks, and the requested value would say nothing.
    pub async fn bind(addr: SocketAddrV4) -> std::io::Result<tokio::net::TcpListener> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound = listener.local_addr().unwrap_or_else(|_| addr.into());
        tracing::info!(addr = %bound, "listening");
        Ok(listener)
    }

    /// Accepts connections until `shutdown` resolves. The TLS handshake happens
    /// inside the spawned task, so a stalled client cannot hold up the accept loop.
    pub async fn serve(
        listener: tokio::net::TcpListener,
        acceptor: TlsAcceptor,
        router: axum::Router,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) -> std::io::Result<()> {
        let mut shutdown = std::pin::pin!(shutdown);

        loop {
            let (stream, peer) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // Accept errors are transient, and returning here would
                        // take the whole proxy down on one bad socket.
                        tracing::warn!(%error, "accept failed");
                        continue;
                    }
                },
                () = &mut shutdown => {
                    tracing::info!("shutdown signalled; no longer accepting connections");
                    return Ok(());
                }
            };

            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(error) => {
                        tracing::debug!(%peer, %error, "TLS handshake failed");
                        return;
                    }
                };

                // The router is a tower service, which hyper serves through this
                // adapter. It clones per call, so one clone per connection is enough.
                let service = TowerToHyperService::new(router);

                // No `_with_upgrades`. `upgrade` is hop-by-hop and stripped both
                // ways, so serving one we then refuse to relay would contradict that.
                if let Err(error) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await
                {
                    tracing::debug!(%peer, %error, "connection closed with an error");
                }
            });
        }
    }
}

#[derive(Parser)]
#[command(name = "programmable-redfish-proxy", version, about)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(long, value_name = "PATH")]
    config_path: PathBuf,

    /// Validate configuration and scripts, then exit without binding.
    #[arg(long)]
    check: bool,
}

/// Structured output, always. One record shape for startup, serving and
/// scripts alike means nothing has to parse two formats.
fn init_tracing(config: &config::LoggingConfig) -> anyhow::Result<()> {
    let builder = tracing_subscriber::fmt()
        .json()
        .with_env_filter(config.filter()?);
    if config.timestamps {
        builder.init();
    } else {
        builder.without_time().init();
    }
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(signal) => signal,
        Err(error) => {
            tracing::error!(%error, "cannot listen for SIGINT");
            return std::future::pending().await;
        }
    };
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            tracing::error!(%error, "cannot listen for SIGTERM");
            return std::future::pending().await;
        }
    };

    tokio::select! {
        _ = interrupt.recv() => tracing::info!("received SIGINT"),
        _ = terminate.recv() => tracing::info!("received SIGTERM"),
    }
}

/// Recompiles scripts on SIGHUP.
fn spawn_reload_listener(state: proxy::SharedState) {
    tokio::spawn(async move {
        let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(hangup) => hangup,
            Err(error) => {
                tracing::error!(%error, "cannot listen for SIGHUP; reload is disabled");
                return;
            }
        };
        tracing::info!("SIGHUP will reload scripts");
        while hangup.recv().await.is_some() {
            state.scripts.reload();
            // A reload swaps units and nothing else. Saying what the store still
            // holds is how an operator sees that for themselves.
            tracing::info!(kept = state.store.len(), "scripts reloaded; store kept");
        }
    });
}

async fn run(config: config::Config, check: bool) -> anyhow::Result<()> {
    // Fail fast on what an operator can fix before traffic arrives. TLS lands
    // here, route globs and scripts inside `AppState::build`.
    let listen = config.listen;
    let material = match (&config.tls.cert_path, &config.tls.key_path) {
        (Some(cert), Some(key)) => listener::load(cert, key)?,
        _ => {
            // Whatever a client might dial us by. A wildcard listen address
            // names nothing, and `external_base_url` is what callers were told.
            let mut names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
            if !listen.ip().is_unspecified() && !listen.ip().is_loopback() {
                names.push(listen.ip().to_string());
            }
            if let Some(host) = config.rewrite.external_base_url.host_str()
                && !names.iter().any(|name| name == host)
            {
                names.push(host.to_string());
            }
            tracing::info!(
                names = names.join(","),
                "no TLS material configured; generated a certificate"
            );
            listener::generate(names)?
        }
    };
    let acceptor = listener::acceptor(material)?;

    let state = proxy::AppState::build(config)?;

    tracing::info!(
        %listen,
        target = %state.config.target.address,
        routes = state.config.route.len(),
        scripts = state.scripts.current().count(),
        "configuration validated"
    );

    if check {
        return Ok(());
    }

    spawn_reload_listener(Arc::clone(&state));

    let socket = listener::bind(listen).await?;
    let router = proxy::router(state);
    listener::serve(socket, acceptor, router, shutdown_signal()).await?;
    tracing::info!("shut down");
    Ok(())
}

fn main() -> ExitCode {
    let args = Args::parse();

    // The config decides how logging is rendered, so it is read before there is
    // anywhere to log to. A failure here goes straight to stderr.
    let config = match config::Config::load(&args.config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration: {:#}", anyhow::Error::new(error));
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = init_tracing(&config.logging) {
        eprintln!("configuration: {error:#}");
        return ExitCode::FAILURE;
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!("building the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(config, args.check)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Startup failures are the operator's to fix, so report the whole
            // chain. That is what anyhow's alternate Display does.
            tracing::error!("{error:#}");
            ExitCode::FAILURE
        }
    }
}
