use anyhow::Context as _;
use clap::{Args, ValueEnum};
use sandboxwich_core::{
    ClaimSterileCellRequestV1, DestroySterileCellRequestV1, PrepareSterileCellRequestV1,
    SterileCellDisposition, SterileCellId, SterileCellReleaseTrustClassV1, SterileCellRuntimeClass,
};
use serde::Serialize;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RuntimeClassArg {
    KataMicrovm,
    GvisorLowerRisk,
}

impl From<RuntimeClassArg> for SterileCellRuntimeClass {
    fn from(value: RuntimeClassArg) -> Self {
        match value {
            RuntimeClassArg::KataMicrovm => Self::KataMicrovm,
            RuntimeClassArg::GvisorLowerRisk => Self::GvisorLowerRisk,
        }
    }
}

#[derive(Debug, Args)]
struct ReleaseArgs {
    #[arg(long)]
    release_set_id: String,
    #[arg(long, value_enum)]
    runtime_class: RuntimeClassArg,
    #[arg(long)]
    policy_digest: String,
    #[arg(long)]
    release_signature: String,
}

impl ReleaseArgs {
    fn into_release(self) -> SterileCellReleaseTrustClassV1 {
        SterileCellReleaseTrustClassV1 {
            release_set_id: self.release_set_id,
            runtime_class: self.runtime_class.into(),
            policy_digest: self.policy_digest,
            signature: self.release_signature,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct PrepareArgs {
    worker_id: Uuid,
    #[arg(long)]
    cell_id: Uuid,
    #[arg(long)]
    provider_cell_id: String,
    #[arg(long, default_value_t = 300)]
    ready_ttl_seconds: u64,
    #[command(flatten)]
    release: ReleaseArgs,
}

#[derive(Debug, Args)]
pub(crate) struct ClaimArgs {
    #[arg(long)]
    claim_id: Uuid,
    #[arg(long)]
    organization_id: String,
    #[arg(long)]
    workspace_id: String,
    #[arg(long)]
    thread_id: String,
    #[arg(long)]
    runner_session_id: String,
    #[arg(long, default_value_t = 120)]
    lease_seconds: u64,
    /// New 0600 file that receives the raw one-time lease attestation. The
    /// file must not already exist; stdout contains only the non-secret lease
    /// locator and this path.
    #[arg(long)]
    attestation_output_file: PathBuf,
    #[command(flatten)]
    release: ReleaseArgs,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClaimOutput {
    ok: bool,
    lease: Option<sandboxwich_core::SterileCellLeaseV1>,
    attestation_file: Option<PathBuf>,
}

fn write_attestation(path: &Path, attestation: &str) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("create sterile lease attestation file {}", path.display()))?;
    file.write_all(attestation.as_bytes())
        .with_context(|| format!("write sterile lease attestation file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync sterile lease attestation file {}", path.display()))?;
    Ok(())
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DispositionArg {
    Destroyed,
    Quarantined,
}

impl From<DispositionArg> for SterileCellDisposition {
    fn from(value: DispositionArg) -> Self {
        match value {
            DispositionArg::Destroyed => Self::Destroyed,
            DispositionArg::Quarantined => Self::Quarantined,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct DestroyArgs {
    worker_id: Uuid,
    cell_id: Uuid,
    #[arg(long)]
    lease_id: Uuid,
    #[arg(long)]
    generation: u64,
    #[arg(long, value_enum)]
    disposition: DispositionArg,
}

pub(crate) async fn prepare(
    client: &reqwest::Client,
    api: &str,
    args: PrepareArgs,
) -> anyhow::Result<reqwest::Response> {
    let endpoint = format!("{api}/workers/{}/sterile-cells/prepare", args.worker_id);
    let ready_ttl = chrono::Duration::seconds(
        i64::try_from(args.ready_ttl_seconds).context("ready TTL is too large")?,
    );
    Ok(client
        .post(endpoint)
        .json(&PrepareSterileCellRequestV1 {
            cell_id: SterileCellId(args.cell_id),
            release: args.release.into_release(),
            provider_cell_id: args.provider_cell_id,
            expires_at: chrono::Utc::now() + ready_ttl,
        })
        .send()
        .await?)
}

pub(crate) async fn claim(
    client: &reqwest::Client,
    api: &str,
    args: ClaimArgs,
) -> anyhow::Result<ClaimOutput> {
    let response = client
        .post(format!("{api}/sterile-cells/claim"))
        .json(&ClaimSterileCellRequestV1 {
            claim_id: Some(args.claim_id),
            release: args.release.into_release(),
            organization_id: args.organization_id,
            workspace_id: args.workspace_id,
            thread_id: args.thread_id,
            runner_session_id: args.runner_session_id,
            lease_seconds: Some(args.lease_seconds),
        })
        .send()
        .await?
        .error_for_status()?
        .json::<sandboxwich_core::ClaimSterileCellResponseV1>()
        .await?;
    match (response.lease, response.lease_attestation) {
        (Some(lease), Some(attestation)) => {
            write_attestation(&args.attestation_output_file, &attestation)?;
            Ok(ClaimOutput {
                ok: response.ok,
                lease: Some(lease),
                attestation_file: Some(args.attestation_output_file),
            })
        }
        (None, None) => Ok(ClaimOutput {
            ok: response.ok,
            lease: None,
            attestation_file: None,
        }),
        _ => anyhow::bail!("sterile claim response contains an incomplete lease attestation"),
    }
}

pub(crate) async fn destroy(
    client: &reqwest::Client,
    api: &str,
    args: DestroyArgs,
) -> anyhow::Result<reqwest::Response> {
    Ok(client
        .post(format!(
            "{api}/workers/{}/sterile-cells/{}/destroy",
            args.worker_id, args.cell_id
        ))
        .json(&DestroySterileCellRequestV1 {
            lease_id: args.lease_id,
            generation: args.generation,
            disposition: args.disposition.into(),
        })
        .send()
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_arguments_preserve_the_explicit_runtime_class() {
        let release = ReleaseArgs {
            release_set_id: "release-set-test".into(),
            runtime_class: RuntimeClassArg::KataMicrovm,
            policy_digest: "a".repeat(64),
            release_signature: "swrs1_test".into(),
        }
        .into_release();
        assert_eq!(release.runtime_class, SterileCellRuntimeClass::KataMicrovm);
        assert_eq!(release.policy_digest, "a".repeat(64));
    }

    #[test]
    fn disposition_arguments_never_map_to_a_reusable_state() {
        assert_eq!(
            SterileCellDisposition::from(DispositionArg::Destroyed),
            SterileCellDisposition::Destroyed
        );
        assert_eq!(
            SterileCellDisposition::from(DispositionArg::Quarantined),
            SterileCellDisposition::Quarantined
        );
    }

    #[test]
    fn attestation_output_is_create_new_and_owner_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lease.attestation");
        write_attestation(&path, "raw-secret-attestation").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "raw-secret-attestation"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(write_attestation(&path, "replacement").is_err());
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "raw-secret-attestation"
        );
    }
}
