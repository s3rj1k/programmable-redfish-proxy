// SPDX-License-Identifier: Unlicense

//! TOML configuration. The file is the only source, so nothing in the
//! environment can change how a proxy behaves.

//! Deliberately not `deny_unknown_fields`, so a stale key is not a crash loop.

//! Route matching lives here too, since compiling a glob is the same job as
//! parsing the key it came from, and both are validated before traffic arrives.

use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};
use std::time::Duration;

use globset::{GlobBuilder, GlobMatcher};
use http::Method;
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing configuration")]
    Parse(#[from] Box<toml::de::Error>),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Both absent means the listener mints its own certificate at startup. Callers
/// authenticate to the BMC through this proxy and never to the proxy itself.
#[derive(Debug, Default, Deserialize)]
pub struct TlsConfig {
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

/// Everything about the one BMC this instance fronts, connection included.
#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    /// The one BMC this instance proxies to. Run another instance for another.
    /// IPv4 only, which is what BMC management networks use.
    pub address: SocketAddrV4,

    /// Trust nothing about the BMC's certificate, which is what a site wants
    /// unless it runs its own CA, since BMC certificates are self-signed.
    pub accept_invalid_certs: bool,

    /// PEM bundle to verify the BMC against, which replaces the public roots.
    /// Absent means no site CA, and serde makes an `Option` optional regardless.
    pub ca_path: Option<PathBuf>,

    /// Covers a whole request, connecting included, and applies to a firmware
    /// push as much as a GET. Raise it for a site that pushes large images.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
pub struct RewriteConfig {
    /// What every rewritten link points at. Mandatory, since the proxy cannot
    /// infer it behind a load balancer and a guess strands half the clients.
    pub external_base_url: url::Url,
}

/// How the daemon's own output is rendered. What gets logged is a script's
/// decision, so this configures only the subscriber.
#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    /// The lowest level that reaches the log. `RUST_LOG` is deliberately not
    /// consulted, so one file is the whole truth.
    pub level: String,

    /// Whether each record carries a timestamp. Off suits a supervisor that
    /// stamps its own, such as journald or a container runtime.
    pub timestamps: bool,
}

impl LoggingConfig {
    /// A level, deliberately not an `EnvFilter` directive string. `EnvFilter`
    /// reads an unknown word as a target name, so a typo would go unnoticed.
    pub fn filter(&self) -> Result<tracing_subscriber::filter::EnvFilter, ConfigError> {
        use tracing_subscriber::filter::{EnvFilter, LevelFilter};

        let level: LevelFilter = self.level.parse().map_err(|_| {
            ConfigError::Invalid(format!(
                "logging.level {:?} is not a level; use trace, debug, info, warn, error or off",
                self.level
            ))
        })?;
        Ok(EnvFilter::builder()
            .with_default_directive(level.into())
            .parse_lossy(""))
    }
}

#[derive(Debug, Deserialize)]
pub struct RuneConfig {
    pub script_dir: PathBuf,

    /// Handles every request no `[[route]]` claims, which is most of them. The
    /// proxy has no pass-through of its own, so this script is the pass-through.
    pub default_script: PathBuf,

    /// Which environment variables `util::read_env` may see, as a regex over the
    /// whole name. Unset means none, so the allowlist fails closed.
    pub env_allow: Option<String>,
}

impl RuneConfig {
    /// Compiles the environment allowlist. Anchored at both ends, so a pattern
    /// names whole variables and `BMC_` cannot also admit `AWS_SECRET_BMC_KEY`.
    pub fn env_matcher(&self) -> Result<Option<regex::Regex>, ConfigError> {
        let Some(pattern) = &self.env_allow else {
            return Ok(None);
        };
        regex::Regex::new(&format!("^(?:{pattern})$"))
            .map(Some)
            .map_err(|error| ConfigError::Invalid(format!("rune.env_allow {pattern:?}: {error}")))
    }
}

#[derive(Debug, Deserialize)]
pub struct RouteConfig {
    /// Empty means any method, which is why this one keeps a default.
    #[serde(default)]
    pub method: Vec<String>,
    pub path: String,
    pub script: PathBuf,
}

/// Every value is mandatory. A daemon that relays credentials into a management
/// network should run on nothing an operator did not write down and review.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: SocketAddrV4,
    /// The one section that may be left out entirely, since an empty one and an
    /// absent one both mean generate.
    #[serde(default)]
    pub tls: TlsConfig,
    pub target: TargetConfig,
    pub rewrite: RewriteConfig,
    pub logging: LoggingConfig,
    pub rune: RuneConfig,

    /// The exception, since a proxy with no scripted endpoint is ordinary and
    /// `route = []` would be noise in every config that has none.
    #[serde(default)]
    pub route: Vec<RouteConfig>,
}

impl Config {
    /// Fails closed, rejecting at startup rather than at the first request.
    fn validate(&self) -> Result<(), ConfigError> {
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for route in &self.route {
            *seen.entry(route.path.as_str()).or_default() += 1;
        }
        if let Some((path, _)) = seen.iter().find(|(_, n)| **n > 1) {
            return Err(ConfigError::Invalid(format!(
                "duplicate route path {path:?}; route precedence would be ambiguous"
            )));
        }

        // `swap_authorities` substitutes the whole base for `scheme://authority`,
        // so a path here is prepended to every link and nothing strips it back.
        let base = self.rewrite.external_base_url.path();
        if !base.is_empty() && base != "/" {
            return Err(ConfigError::Invalid(format!(
                "rewrite.external_base_url has path {base:?}; it must name a scheme, \
                 host and port only, since no path prefix is stripped on the way in"
            )));
        }

        // Naming one half of the pair is a mistake rather than a third mode, and
        // generating over it would leave a proxy ignoring the file that was meant.
        match (&self.tls.cert_path, &self.tls.key_path) {
            (Some(_), None) => {
                return Err(ConfigError::Invalid(
                    "tls.cert_path is set but tls.key_path is not; set both to serve \
                     your own material, or neither to generate one at startup"
                        .to_string(),
                ));
            }
            (None, Some(_)) => {
                return Err(ConfigError::Invalid(
                    "tls.key_path is set but tls.cert_path is not; set both to serve \
                     your own material, or neither to generate one at startup"
                        .to_string(),
                ));
            }
            _ => {}
        }

        Ok(())
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|e| ConfigError::Parse(Box::new(e)))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text)
    }
}

// Route matching.

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("route {path:?} has an invalid path glob")]
    Glob {
        path: String,
        #[source]
        source: globset::Error,
    },
    #[error("route {path:?} has an invalid method {method:?}")]
    Method { path: String, method: String },
}

pub struct Route {
    matcher: GlobMatcher,
    /// Empty means "any method".
    methods: Vec<Method>,
    /// Literal prefix length, used for precedence. Most specific wins.
    specificity: usize,
    pub script: PathBuf,
}

impl Route {
    fn matches_path(&self, path: &str) -> bool {
        self.matcher.is_match(path)
    }

    fn allows(&self, method: &Method) -> bool {
        self.methods.is_empty() || self.methods.contains(method)
    }

    fn matches(&self, method: &Method, path: &str) -> bool {
        self.allows(method) && self.matches_path(path)
    }
}

/// Length of the leading run of literal (non-wildcard) characters.
fn literal_prefix_len(pattern: &str) -> usize {
    pattern.find(['*', '?', '[', '{']).unwrap_or(pattern.len())
}

pub struct Router {
    /// Sorted most-specific first, so the first match wins.
    routes: Vec<Route>,
}

impl Router {
    pub fn build(configs: &[RouteConfig]) -> Result<Self, RouteError> {
        let mut routes = Vec::with_capacity(configs.len());

        for config in configs {
            // `literal_separator` makes `*` match within one path segment and
            // `**` cross them, which is what every route here already assumes.
            let glob = GlobBuilder::new(&config.path)
                .literal_separator(true)
                .build()
                .map_err(|source| RouteError::Glob {
                    path: config.path.clone(),
                    source,
                })?;

            let mut methods = Vec::with_capacity(config.method.len());
            for raw in &config.method {
                let method = raw.parse::<Method>().map_err(|_| RouteError::Method {
                    path: config.path.clone(),
                    method: raw.clone(),
                })?;
                methods.push(method);
            }

            routes.push(Route {
                matcher: glob.compile_matcher(),
                methods,
                specificity: literal_prefix_len(&config.path),
                script: config.script.clone(),
            });
        }

        // Most specific first. Ties broken by declaration order, which is stable.
        routes.sort_by_key(|route| std::cmp::Reverse(route.specificity));
        Ok(Self { routes })
    }

    /// Returns the handling route, or `None` for direct pass-through.
    pub fn resolve(&self, method: &Method, path: &str) -> Option<&Route> {
        self.routes.iter().find(|route| route.matches(method, path))
    }

    /// Whether some route claims this path for a different method. Without this
    /// a `method` list reads as "read only" and silently passes the write through.
    pub fn claims_path(&self, path: &str) -> bool {
        self.routes.iter().any(|route| route.matches_path(path))
    }
}
