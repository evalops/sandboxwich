use crate::bootstrap_handoff::{
    BOOTSTRAP_HANDOFF_KEY_BYTES, DEFAULT_BOOTSTRAP_HANDOFF_TTL, parse_bootstrap_handoff_key,
};
use anyhow::Context;
use sandboxwich_core::{
    DbVariant, SandboxRuntimeProfile, SterileCellReleaseTrustClassV1, SterileCellRuntimeClass,
};
use std::{
    io::Read as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

pub(crate) const IDENTITY_SERVICE_CLIENT_URI: &str =
    "spiffe://identity.evalops.dev/service/identity/sandboxwich-fence";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMtlsConfig {
    pub(crate) bind: SocketAddr,
    pub(crate) cert_file: PathBuf,
    pub(crate) key_file: PathBuf,
    pub(crate) client_ca_file: PathBuf,
    pub(crate) client_uri: String,
}

#[derive(Clone)]
pub(crate) struct AuthConfig {
    pub(crate) shared_token: Option<String>,
    pub(crate) tenant_tokens: Vec<TenantToken>,
    /// Service credentials allowed to bind a provider-specific organization/workspace
    /// routing scope while retaining the configured Sandboxwich ownership tenant.
    pub(crate) provider_routing_tokens: Vec<TenantToken>,
    /// Distinct from `shared_token`/`tenant_tokens`: gates operator-only routes
    /// (currently `/snapshots/cleanup`) that act across tenant boundaries.
    pub(crate) operator_token: Option<String>,
    /// Explicit, off-by-default opt-out that lets the API serve with no
    /// authentication configured, trusting the `x-sandboxwich-tenant` header.
    /// Intended only for local development and benchmark harnesses.
    pub(crate) allow_insecure_no_auth: bool,
}

#[derive(Clone)]
pub(crate) struct TenantToken {
    pub(crate) tenant_id: String,
    pub(crate) token: String,
}

pub(crate) enum ApiCommand {
    Serve,
    Migrate,
    CheckSchema,
    OpenApi,
}

pub(crate) struct ApiConfig {
    pub(crate) command: ApiCommand,
    pub(crate) database_url: String,
    pub(crate) bind: SocketAddr,
    pub(crate) database_max_connections: u32,
    pub(crate) auto_migrate: bool,
    pub(crate) shared_token: Option<String>,
    pub(crate) tenant_tokens: Vec<TenantToken>,
    pub(crate) provider_routing_tokens: Vec<TenantToken>,
    pub(crate) operator_token: Option<String>,
    pub(crate) allow_insecure_no_auth: bool,
    pub(crate) default_tenant_id: String,
    pub(crate) sweep_interval_ms: u64,
    pub(crate) disable_expiry_sweeper: bool,
    pub(crate) apex_callback_base_url: Option<String>,
    pub(crate) placement_attestation_derivation_key: Option<String>,
    /// Sealing key for the shared ephemeral resident-bootstrap handoff.
    /// Unset means no shared tier: bootstrap bytes stay in the process that
    /// admitted them, and an API restart or a read on another replica
    /// strands the resident process exactly as it did before the handoff
    /// existed.
    pub(crate) bootstrap_handoff_key: Option<[u8; BOOTSTRAP_HANDOFF_KEY_BYTES]>,
    pub(crate) bootstrap_handoff_ttl: Duration,
    pub(crate) identity_mtls: Option<IdentityMtlsConfig>,
    pub(crate) sandbox_lifetime: SandboxLifetimeConfig,
    pub(crate) sterile_cell_signing_key: Option<String>,
    pub(crate) sterile_resident_activation_enabled: bool,
    pub(crate) sterile_pool: Option<SterilePoolConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SterilePoolConfig {
    pub(crate) target: u32,
    pub(crate) tenant_id: String,
    pub(crate) release: SterileCellReleaseTrustClassV1,
    pub(crate) sandbox_profile: SandboxRuntimeProfile,
    pub(crate) template: String,
    pub(crate) agent_image: String,
    pub(crate) maestro_image: String,
    pub(crate) ready_ttl: Duration,
}

/// Server-side default/ceiling for the two active-lifetime reaping knobs
/// (`max_lifetime_seconds`, `idle_ttl_seconds`). Every field defaults to
/// `None` (unset): with no operator configuration at all, `create`/`fork`
/// behavior is byte-for-byte what it was before these knobs existed, and
/// `workspace_mode: persistent` sandboxes in particular get no lifetime cap
/// unless the operator (or the caller) explicitly opts in.
#[derive(Clone, Default)]
pub(crate) struct SandboxLifetimeConfig {
    pub(crate) default_max_lifetime_seconds: Option<u64>,
    pub(crate) max_max_lifetime_seconds: Option<u64>,
    pub(crate) default_idle_ttl_seconds: Option<u64>,
    pub(crate) max_idle_ttl_seconds: Option<u64>,
}

pub(crate) fn parse_apex_callback_base_url(
    value: Option<String>,
) -> anyhow::Result<Option<String>> {
    let Some(value) = value.map(|value| value.trim().trim_end_matches('/').to_string()) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let scheme_end = value.find("://");
    let valid_scheme = value.starts_with("http://") || value.starts_with("https://");
    let authority = scheme_end
        .and_then(|index| value.get(index + 3..))
        .unwrap_or_default();
    if !valid_scheme
        || authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || value.chars().any(char::is_whitespace)
    {
        anyhow::bail!(
            "invalid SANDBOXWICH_APEX_CALLBACK_BASE_URL: expected an http(s) origin without credentials, path, query, or fragment"
        );
    }
    Ok(Some(value))
}

pub(crate) fn load_api_config() -> anyhow::Result<ApiConfig> {
    let command = parse_api_command(std::env::args().skip(1))?;
    let bind = std::env::var("SANDBOXWICH_BIND").unwrap_or_else(|_| "127.0.0.1:3217".to_string());
    let bind: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid SANDBOXWICH_BIND value: {bind}"))?;

    let database_url = std::env::var("SANDBOXWICH_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://sandboxwich.db".to_string());
    let database_max_connections = parse_env_u32("SANDBOXWICH_DATABASE_MAX_CONNECTIONS", 5)?.max(1);
    let auto_migrate = parse_env_bool("SANDBOXWICH_AUTO_MIGRATE", true)?;
    let shared_token = std::env::var("SANDBOXWICH_API_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty());
    let tenant_tokens =
        parse_tenant_tokens(std::env::var("SANDBOXWICH_TENANT_TOKENS").ok().as_deref())?;
    let provider_routing_tokens = parse_scoped_tokens(
        "SANDBOXWICH_PROVIDER_ROUTING_TOKENS",
        std::env::var("SANDBOXWICH_PROVIDER_ROUTING_TOKENS")
            .ok()
            .as_deref(),
    )?;
    let operator_token = std::env::var("SANDBOXWICH_OPERATOR_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty());
    let allow_insecure_no_auth = parse_env_bool("SANDBOXWICH_ALLOW_INSECURE_NO_AUTH", false)?;
    let default_tenant_id = std::env::var("SANDBOXWICH_DEFAULT_TENANT")
        .ok()
        .filter(|tenant| !tenant.trim().is_empty())
        .unwrap_or_else(|| "default".to_string());
    let sweep_interval_ms = u64::from(parse_env_u32("SANDBOXWICH_SWEEP_INTERVAL_MS", 1000)?.max(1));
    let disable_expiry_sweeper = parse_env_bool("SANDBOXWICH_DISABLE_EXPIRY_SWEEPER", false)?;
    let apex_callback_base_url =
        parse_apex_callback_base_url(std::env::var("SANDBOXWICH_APEX_CALLBACK_BASE_URL").ok())?;
    let placement_attestation_derivation_key =
        std::env::var("SANDBOXWICH_PLACEMENT_ATTESTATION_DERIVATION_KEY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
    let bootstrap_handoff_key = std::env::var("SANDBOXWICH_BOOTSTRAP_HANDOFF_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| parse_bootstrap_handoff_key(&value))
        .transpose()?;
    let bootstrap_handoff_ttl = match parse_env_u32("SANDBOXWICH_BOOTSTRAP_HANDOFF_TTL_SECONDS", 0)?
    {
        0 => DEFAULT_BOOTSTRAP_HANDOFF_TTL,
        seconds => Duration::from_secs(u64::from(seconds)),
    };
    if placement_attestation_derivation_key
        .as_ref()
        .is_some_and(|key| key.len() < 32)
    {
        anyhow::bail!(
            "SANDBOXWICH_PLACEMENT_ATTESTATION_DERIVATION_KEY must contain at least 32 bytes"
        );
    }
    let identity_mtls = parse_identity_mtls_config(
        std::env::var("SANDBOXWICH_IDENTITY_MTLS_BIND").ok(),
        std::env::var("SANDBOXWICH_IDENTITY_MTLS_CERT_FILE").ok(),
        std::env::var("SANDBOXWICH_IDENTITY_MTLS_KEY_FILE").ok(),
        std::env::var("SANDBOXWICH_IDENTITY_MTLS_CLIENT_CA_FILE").ok(),
        std::env::var("SANDBOXWICH_IDENTITY_MTLS_CLIENT_URI").ok(),
    )?;
    let sandbox_lifetime = SandboxLifetimeConfig {
        default_max_lifetime_seconds: parse_env_optional_u64(
            "SANDBOXWICH_DEFAULT_MAX_LIFETIME_SECONDS",
        )?,
        max_max_lifetime_seconds: parse_env_optional_u64("SANDBOXWICH_MAX_MAX_LIFETIME_SECONDS")?,
        default_idle_ttl_seconds: parse_env_optional_u64("SANDBOXWICH_DEFAULT_IDLE_TTL_SECONDS")?,
        max_idle_ttl_seconds: parse_env_optional_u64("SANDBOXWICH_MAX_IDLE_TTL_SECONDS")?,
    };
    let sterile_cells_enabled = parse_env_bool("SANDBOXWICH_STERILE_CELLS_ENABLED", false)?;
    let sterile_cell_signing_key = load_sterile_cell_signing_key(
        sterile_cells_enabled,
        std::env::var_os("SANDBOXWICH_STERILE_CELL_SIGNING_KEY_FILE")
            .map(PathBuf::from)
            .as_deref(),
    )?;
    let sterile_resident_activation_enabled =
        parse_env_bool("SANDBOXWICH_STERILE_RESIDENT_ACTIVATION_ENABLED", false)?;
    require_sterile_activation_handoff_key(
        sterile_resident_activation_enabled,
        bootstrap_handoff_key.as_ref(),
    )?;
    let sterile_pool = parse_sterile_pool_config(
        parse_env_u32("SANDBOXWICH_STERILE_POOL_TARGET", 0)?,
        std::env::var("SANDBOXWICH_STERILE_POOL_TENANT_ID").ok(),
        std::env::var("SANDBOXWICH_STERILE_POOL_RELEASE_SET_ID").ok(),
        std::env::var("SANDBOXWICH_STERILE_POOL_RUNTIME_CLASS").ok(),
        std::env::var("SANDBOXWICH_STERILE_POOL_POLICY_DIGEST").ok(),
        std::env::var("SANDBOXWICH_STERILE_POOL_RELEASE_SIGNATURE").ok(),
        std::env::var("SANDBOXWICH_STERILE_POOL_SANDBOX_PROFILE").ok(),
        std::env::var("SANDBOXWICH_STERILE_POOL_TEMPLATE").ok(),
        std::env::var("SANDBOXWICH_STERILE_POOL_AGENT_IMAGE").ok(),
        std::env::var("SANDBOXWICH_STERILE_POOL_MAESTRO_IMAGE").ok(),
        parse_env_u32("SANDBOXWICH_STERILE_POOL_READY_TTL_SECONDS", 300)?,
        sterile_cell_signing_key.as_deref(),
    )?;

    Ok(ApiConfig {
        command,
        database_url,
        bind,
        database_max_connections,
        auto_migrate,
        shared_token,
        tenant_tokens,
        provider_routing_tokens,
        operator_token,
        allow_insecure_no_auth,
        default_tenant_id,
        sweep_interval_ms,
        disable_expiry_sweeper,
        apex_callback_base_url,
        placement_attestation_derivation_key,
        bootstrap_handoff_key,
        bootstrap_handoff_ttl,
        identity_mtls,
        sandbox_lifetime,
        sterile_cell_signing_key,
        sterile_resident_activation_enabled,
        sterile_pool,
    })
}

fn require_sterile_activation_handoff_key(
    sterile_resident_activation_enabled: bool,
    bootstrap_handoff_key: Option<&[u8; BOOTSTRAP_HANDOFF_KEY_BYTES]>,
) -> anyhow::Result<()> {
    if sterile_resident_activation_enabled && bootstrap_handoff_key.is_none() {
        anyhow::bail!(
            "SANDBOXWICH_BOOTSTRAP_HANDOFF_KEY is required when SANDBOXWICH_STERILE_RESIDENT_ACTIVATION_ENABLED is enabled"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn parse_sterile_pool_config(
    target: u32,
    tenant_id: Option<String>,
    release_set_id: Option<String>,
    runtime_class: Option<String>,
    policy_digest: Option<String>,
    release_signature: Option<String>,
    sandbox_profile: Option<String>,
    template: Option<String>,
    agent_image: Option<String>,
    maestro_image: Option<String>,
    ready_ttl_seconds: u32,
    signing_key: Option<&str>,
) -> anyhow::Result<Option<SterilePoolConfig>> {
    if target == 0 {
        return Ok(None);
    }
    let required = |name: &'static str, value: Option<String>| -> anyhow::Result<String> {
        value
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .with_context(|| {
                format!("{name} is required when SANDBOXWICH_STERILE_POOL_TARGET is non-zero")
            })
    };
    let runtime_class = SterileCellRuntimeClass::parse_db_str(&required(
        "SANDBOXWICH_STERILE_POOL_RUNTIME_CLASS",
        runtime_class,
    )?)
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let sandbox_profile = SandboxRuntimeProfile::parse_db_str(&required(
        "SANDBOXWICH_STERILE_POOL_SANDBOX_PROFILE",
        sandbox_profile,
    )?)
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let release = SterileCellReleaseTrustClassV1 {
        release_set_id: required("SANDBOXWICH_STERILE_POOL_RELEASE_SET_ID", release_set_id)?,
        runtime_class,
        policy_digest: required("SANDBOXWICH_STERILE_POOL_POLICY_DIGEST", policy_digest)?
            .to_ascii_lowercase(),
        signature: required(
            "SANDBOXWICH_STERILE_POOL_RELEASE_SIGNATURE",
            release_signature,
        )?,
    };
    let signing_key = signing_key.context(
        "sterile-cell signing must be enabled before SANDBOXWICH_STERILE_POOL_TARGET can be non-zero",
    )?;
    crate::handlers::sterile_cells::validate_release(signing_key, &release)
        .map_err(|error| anyhow::anyhow!(error.message))?;
    anyhow::ensure!(
        ready_ttl_seconds > 0,
        "SANDBOXWICH_STERILE_POOL_READY_TTL_SECONDS must be non-zero"
    );
    let pinned_image = |name: &'static str, value: Option<String>| -> anyhow::Result<String> {
        let value = required(name, value)?;
        let Some((_, digest)) = value.rsplit_once("@sha256:") else {
            anyhow::bail!("{name} must be pinned by an exact sha256 digest");
        };
        anyhow::ensure!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{name} must be pinned by an exact lowercase sha256 digest"
        );
        Ok(value)
    };
    Ok(Some(SterilePoolConfig {
        target,
        tenant_id: required("SANDBOXWICH_STERILE_POOL_TENANT_ID", tenant_id)?,
        release,
        sandbox_profile,
        template: required("SANDBOXWICH_STERILE_POOL_TEMPLATE", template)?,
        agent_image: pinned_image("SANDBOXWICH_STERILE_POOL_AGENT_IMAGE", agent_image)?,
        maestro_image: pinned_image("SANDBOXWICH_STERILE_POOL_MAESTRO_IMAGE", maestro_image)?,
        ready_ttl: Duration::from_secs(u64::from(ready_ttl_seconds)),
    }))
}

fn load_sterile_cell_signing_key(
    enabled: bool,
    path: Option<&Path>,
) -> anyhow::Result<Option<String>> {
    if !enabled {
        return Ok(None);
    }
    let path = path.context(
        "SANDBOXWICH_STERILE_CELL_SIGNING_KEY_FILE is required when SANDBOXWICH_STERILE_CELLS_ENABLED is true",
    )?;
    let file = std::fs::File::open(path).with_context(|| {
        format!(
            "open SANDBOXWICH_STERILE_CELL_SIGNING_KEY_FILE {}",
            path.display()
        )
    })?;
    let mut bytes = Vec::with_capacity(4097);
    file.take(4097).read_to_end(&mut bytes).with_context(|| {
        format!(
            "read SANDBOXWICH_STERILE_CELL_SIGNING_KEY_FILE {}",
            path.display()
        )
    })?;
    anyhow::ensure!(
        bytes.len() <= 4096,
        "SANDBOXWICH_STERILE_CELL_SIGNING_KEY_FILE exceeds 4096 bytes"
    );
    let key = String::from_utf8(bytes)
        .context("SANDBOXWICH_STERILE_CELL_SIGNING_KEY_FILE is not UTF-8")?;
    let key = key.trim().to_string();
    anyhow::ensure!(
        key.len() >= 32,
        "SANDBOXWICH_STERILE_CELL_SIGNING_KEY_FILE must contain at least 32 bytes"
    );
    Ok(Some(key))
}

pub(crate) fn parse_identity_mtls_config(
    bind: Option<String>,
    cert_file: Option<String>,
    key_file: Option<String>,
    client_ca_file: Option<String>,
    client_uri: Option<String>,
) -> anyhow::Result<Option<IdentityMtlsConfig>> {
    let (bind, cert_file, key_file, client_ca_file, client_uri) =
        match (bind, cert_file, key_file, client_ca_file, client_uri) {
            (None, None, None, None, None) => return Ok(None),
            (Some(bind), Some(cert), Some(key), Some(ca), Some(uri)) => (bind, cert, key, ca, uri),
            _ => anyhow::bail!(
                "SANDBOXWICH_IDENTITY_MTLS_BIND, SANDBOXWICH_IDENTITY_MTLS_CERT_FILE, \
                 SANDBOXWICH_IDENTITY_MTLS_KEY_FILE, \
                 SANDBOXWICH_IDENTITY_MTLS_CLIENT_CA_FILE, and \
                 SANDBOXWICH_IDENTITY_MTLS_CLIENT_URI must be configured together"
            ),
        };
    let bind = bind.trim();
    let cert_file = cert_file.trim();
    let key_file = key_file.trim();
    let client_ca_file = client_ca_file.trim();
    let client_uri = client_uri.trim();
    if cert_file.is_empty() || key_file.is_empty() || client_ca_file.is_empty() {
        anyhow::bail!("Identity mTLS certificate and key paths must be non-empty");
    }
    if client_uri != IDENTITY_SERVICE_CLIENT_URI {
        anyhow::bail!(
            "SANDBOXWICH_IDENTITY_MTLS_CLIENT_URI must be exactly {IDENTITY_SERVICE_CLIENT_URI}"
        );
    }
    Ok(Some(IdentityMtlsConfig {
        bind: bind
            .parse()
            .with_context(|| format!("invalid SANDBOXWICH_IDENTITY_MTLS_BIND value: {bind}"))?,
        cert_file: PathBuf::from(cert_file),
        key_file: PathBuf::from(key_file),
        client_ca_file: PathBuf::from(client_ca_file),
        client_uri: client_uri.to_string(),
    }))
}

pub(crate) fn parse_api_command(
    args: impl IntoIterator<Item = String>,
) -> anyhow::Result<ApiCommand> {
    let mut args = args.into_iter();
    let command = match args.next().as_deref() {
        None | Some("serve") => ApiCommand::Serve,
        Some("migrate") => ApiCommand::Migrate,
        Some("check-schema") => ApiCommand::CheckSchema,
        Some("openapi") => ApiCommand::OpenApi,
        Some("--help") | Some("-h") => {
            println!("usage: sandboxwich-api [serve|migrate|check-schema|openapi]");
            std::process::exit(0);
        }
        Some(command) => anyhow::bail!(
            "unknown sandboxwich-api command {command:?}; expected serve, migrate, check-schema, or openapi"
        ),
    };
    if let Some(extra) = args.next() {
        anyhow::bail!("unexpected extra sandboxwich-api argument {extra:?}");
    }
    Ok(command)
}

pub(crate) fn parse_env_u32(name: &'static str, default: u32) -> anyhow::Result<u32> {
    let Some(value) = std::env::var(name).ok() else {
        return Ok(default);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(default);
    }
    value
        .parse()
        .with_context(|| format!("invalid {name} value: {value}"))
}

/// Like `parse_env_u32`, but for the optional (no forced default) active-
/// lifetime knobs: an unset or blank env var means "not configured"
/// (`None`), not some numeric fallback -- callers that want a default wire it
/// in themselves (see `SandboxLifetimeConfig`).
pub(crate) fn parse_env_optional_u64(name: &'static str) -> anyhow::Result<Option<u64>> {
    parse_optional_u64_value(name, std::env::var(name).ok().as_deref())
}

/// The pure parsing half of `parse_env_optional_u64`, split out so it can be
/// unit tested against plain values instead of mutating real process env vars
/// (this workspace forbids `unsafe_code`, which `std::env::set_var` requires
/// since edition 2024).
pub(crate) fn parse_optional_u64_value(
    name: &'static str,
    value: Option<&str>,
) -> anyhow::Result<Option<u64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .with_context(|| format!("invalid {name} value: {value}"))
}

pub(crate) fn parse_env_bool(name: &'static str, default: bool) -> anyhow::Result<bool> {
    let Some(value) = std::env::var(name).ok() else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default),
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        value => anyhow::bail!("invalid {name} value: {value}"),
    }
}

pub(crate) fn parse_tenant_tokens(value: Option<&str>) -> anyhow::Result<Vec<TenantToken>> {
    parse_scoped_tokens("SANDBOXWICH_TENANT_TOKENS", value)
}

fn parse_scoped_tokens(
    variable_name: &str,
    value: Option<&str>,
) -> anyhow::Result<Vec<TenantToken>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (tenant_id, token) = entry
                .split_once('=')
                .with_context(|| format!("invalid {variable_name} entry: {entry}"))?;
            let tenant_id = tenant_id.trim();
            let token = token.trim();
            if tenant_id.is_empty() || token.is_empty() {
                anyhow::bail!("invalid {variable_name} entry: {entry}");
            }
            Ok(TenantToken {
                tenant_id: tenant_id.to_string(),
                token: token.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    fn signed_pool_release(key: &str) -> (String, String) {
        let digest = "a".repeat(64);
        let canonical =
            format!("sandboxwich-sterile-release-v1\0release-test\0kata_microvm\0{digest}");
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(canonical.as_bytes());
        (
            digest,
            format!(
                "swrs1_{}",
                URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
            ),
        )
    }

    #[test]
    fn sterile_resident_activation_requires_a_shared_bootstrap_handoff_key() {
        assert!(require_sterile_activation_handoff_key(false, None).is_ok());
        assert!(require_sterile_activation_handoff_key(true, Some(&[7; 32])).is_ok());
        let error = require_sterile_activation_handoff_key(true, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("BOOTSTRAP_HANDOFF_KEY is required")
        );
    }

    #[test]
    fn apex_callback_base_is_an_instance_origin_or_startup_fails() {
        assert_eq!(
            parse_apex_callback_base_url(Some(" http://10.0.0.7:3217/ ".into())).unwrap(),
            Some("http://10.0.0.7:3217".into())
        );
        for invalid in [
            "sandboxwich-api:3217",
            "ftp://10.0.0.7",
            "http://user@10.0.0.7",
            "http://10.0.0.7/path",
            "http://10.0.0.7?query=1",
        ] {
            assert!(parse_apex_callback_base_url(Some(invalid.into())).is_err());
        }
    }

    #[test]
    fn identity_mtls_configuration_is_optional_or_complete_with_the_exact_client_uri() {
        assert!(
            parse_identity_mtls_config(None, None, None, None, None)
                .unwrap()
                .is_none()
        );

        let complete = parse_identity_mtls_config(
            Some("127.0.0.1:3443".into()),
            Some("/tls/server.crt".into()),
            Some("/tls/server.key".into()),
            Some("/tls/client-ca.crt".into()),
            Some(IDENTITY_SERVICE_CLIENT_URI.into()),
        )
        .unwrap()
        .expect("complete Identity mTLS config");
        assert_eq!(complete.bind, "127.0.0.1:3443".parse().unwrap());
        assert_eq!(complete.client_uri, IDENTITY_SERVICE_CLIENT_URI);

        for partial in [
            [Some("127.0.0.1:3443"), None, None, None, None],
            [
                None,
                Some("/tls/server.crt"),
                Some("/tls/server.key"),
                Some("/tls/client-ca.crt"),
                Some(IDENTITY_SERVICE_CLIENT_URI),
            ],
            [
                Some("127.0.0.1:3443"),
                Some("/tls/server.crt"),
                Some("/tls/server.key"),
                Some("/tls/client-ca.crt"),
                None,
            ],
        ] {
            assert!(
                parse_identity_mtls_config(
                    partial[0].map(str::to_string),
                    partial[1].map(str::to_string),
                    partial[2].map(str::to_string),
                    partial[3].map(str::to_string),
                    partial[4].map(str::to_string),
                )
                .is_err()
            );
        }

        assert!(
            parse_identity_mtls_config(
                Some("127.0.0.1:3443".into()),
                Some("/tls/server.crt".into()),
                Some("/tls/server.key".into()),
                Some("/tls/client-ca.crt".into()),
                Some("spiffe://identity.evalops.dev/service/other".into()),
            )
            .is_err()
        );
    }

    #[test]
    fn optional_u64_value_is_none_when_unset_or_blank() {
        assert_eq!(parse_optional_u64_value("TEST", None).unwrap(), None);
        assert_eq!(parse_optional_u64_value("TEST", Some("   ")).unwrap(), None);
    }

    #[test]
    fn optional_u64_value_parses_a_set_value_and_rejects_garbage() {
        assert_eq!(
            parse_optional_u64_value("TEST", Some(" 3600 ")).unwrap(),
            Some(3600)
        );
        assert!(parse_optional_u64_value("TEST", Some("not-a-number")).is_err());
    }

    #[test]
    fn sterile_cell_signing_key_is_loaded_only_from_a_bounded_secret_file() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("sterile-signing-key");
        std::fs::write(&key_path, "k".repeat(32)).unwrap();
        assert_eq!(
            load_sterile_cell_signing_key(true, Some(&key_path))
                .unwrap()
                .as_deref(),
            Some("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")
        );
        assert_eq!(
            load_sterile_cell_signing_key(false, Some(&key_path)).unwrap(),
            None
        );
        assert!(load_sterile_cell_signing_key(true, None).is_err());
        std::fs::write(&key_path, "short").unwrap();
        assert!(load_sterile_cell_signing_key(true, Some(&key_path)).is_err());
        std::fs::write(&key_path, "x".repeat(4097)).unwrap();
        assert!(load_sterile_cell_signing_key(true, Some(&key_path)).is_err());
    }

    #[test]
    fn sterile_pool_target_is_zero_until_every_authority_field_is_configured() {
        assert!(
            parse_sterile_pool_config(
                0,
                Some("ignored".into()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                300,
                None,
            )
            .unwrap()
            .is_none()
        );
        assert!(
            parse_sterile_pool_config(
                1,
                Some("default".into()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                300,
                Some("sandboxwich-test-signing-key-32-bytes"),
            )
            .is_err()
        );

        let key = "sandboxwich-test-signing-key-32-bytes";
        let (digest, signature) = signed_pool_release(key);
        let config = parse_sterile_pool_config(
            2,
            Some("default".into()),
            Some("release-test".into()),
            Some("kata_microvm".into()),
            Some(digest),
            Some(signature),
            Some("unprivileged".into()),
            Some("ubuntu-dev@sha256:test".into()),
            Some(format!("agent@sha256:{}", "a".repeat(64))),
            Some(format!("maestro@sha256:{}", "b".repeat(64))),
            300,
            Some(key),
        )
        .unwrap()
        .unwrap();
        assert_eq!(config.target, 2);
        assert_eq!(
            config.release.runtime_class,
            SterileCellRuntimeClass::KataMicrovm
        );
    }
}
