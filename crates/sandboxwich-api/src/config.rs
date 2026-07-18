use anyhow::Context;
use std::net::SocketAddr;

#[derive(Clone)]
pub(crate) struct AuthConfig {
    pub(crate) shared_token: Option<String>,
    pub(crate) tenant_tokens: Vec<TenantToken>,
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
    pub(crate) operator_token: Option<String>,
    pub(crate) allow_insecure_no_auth: bool,
    pub(crate) default_tenant_id: String,
    pub(crate) sweep_interval_ms: u64,
    pub(crate) disable_expiry_sweeper: bool,
    pub(crate) apex_callback_base_url: Option<String>,
    pub(crate) placement_attestation_derivation_key: Option<String>,
    pub(crate) sandbox_lifetime: SandboxLifetimeConfig,
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
    if placement_attestation_derivation_key
        .as_ref()
        .is_some_and(|key| key.len() < 32)
    {
        anyhow::bail!(
            "SANDBOXWICH_PLACEMENT_ATTESTATION_DERIVATION_KEY must contain at least 32 bytes"
        );
    }
    let sandbox_lifetime = SandboxLifetimeConfig {
        default_max_lifetime_seconds: parse_env_optional_u64(
            "SANDBOXWICH_DEFAULT_MAX_LIFETIME_SECONDS",
        )?,
        max_max_lifetime_seconds: parse_env_optional_u64("SANDBOXWICH_MAX_MAX_LIFETIME_SECONDS")?,
        default_idle_ttl_seconds: parse_env_optional_u64("SANDBOXWICH_DEFAULT_IDLE_TTL_SECONDS")?,
        max_idle_ttl_seconds: parse_env_optional_u64("SANDBOXWICH_MAX_IDLE_TTL_SECONDS")?,
    };

    Ok(ApiConfig {
        command,
        database_url,
        bind,
        database_max_connections,
        auto_migrate,
        shared_token,
        tenant_tokens,
        operator_token,
        allow_insecure_no_auth,
        default_tenant_id,
        sweep_interval_ms,
        disable_expiry_sweeper,
        apex_callback_base_url,
        placement_attestation_derivation_key,
        sandbox_lifetime,
    })
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
                .with_context(|| format!("invalid SANDBOXWICH_TENANT_TOKENS entry: {entry}"))?;
            let tenant_id = tenant_id.trim();
            let token = token.trim();
            if tenant_id.is_empty() || token.is_empty() {
                anyhow::bail!("invalid SANDBOXWICH_TENANT_TOKENS entry: {entry}");
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
}
