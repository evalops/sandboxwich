use anyhow::Context as _;
use clap::{Args, ValueEnum};
use sandboxwich_core::{
    ClaimSterileCellRequestV1, DestroySterileCellRequestV1, PrepareSterileCellRequestV1,
    SterileCellDisposition, SterileCellId, SterileCellReleaseTrustClassV1, SterileCellRuntimeClass,
};
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
    organization_id: String,
    #[arg(long)]
    workspace_id: String,
    #[arg(long)]
    thread_id: String,
    #[arg(long)]
    runner_session_id: String,
    #[arg(long, default_value_t = 120)]
    lease_seconds: u64,
    #[command(flatten)]
    release: ReleaseArgs,
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
) -> anyhow::Result<reqwest::Response> {
    Ok(client
        .post(format!("{api}/sterile-cells/claim"))
        .json(&ClaimSterileCellRequestV1 {
            release: args.release.into_release(),
            organization_id: args.organization_id,
            workspace_id: args.workspace_id,
            thread_id: args.thread_id,
            runner_session_id: args.runner_session_id,
            lease_seconds: Some(args.lease_seconds),
        })
        .send()
        .await?)
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
}
