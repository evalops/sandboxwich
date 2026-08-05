use crate::ProvisioningErrorClass;
use serde::Serialize;
use thiserror::Error;

pub const LIFECYCLE_CONTRACT_SCHEMA: &str = "sandboxwich.lifecycle.v1";
pub const LIFECYCLE_CONTRACT_HEADER: &str = "x-sandboxwich-lifecycle-contract-sha256";
pub const LIFECYCLE_CONTRACT_ENV: &str = "SANDBOXWICH_LIFECYCLE_CONTRACT_SHA256";
pub const LIFECYCLE_SUPPORTED_CONTRACTS_ENV: &str =
    "SANDBOXWICH_SUPPORTED_LIFECYCLE_CONTRACT_SHA256";
pub const LIFECYCLE_CONTRACT_SHA256: &str =
    "839f24fff7a57cf997b0fc6a4064b1dcd0208a045c617dbefe1940562a477f35";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleDisposition {
    RetrySameGeneration,
    QueueSameGeneration,
    TerminalSameGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxStateDisposition {
    Pending,
    Active,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleReasonCode {
    ProviderTransient,
    KubernetesProviderTransient,
    WorkspaceCapacityPending,
    ResourceContractConflict,
    RuntimeClassBoundaryUnverified,
    KubernetesPolicyDenied,
    KubernetesContractInvalid,
    PodUnschedulable,
    ResourceObservationMissing,
    ResourceObservationInvalid,
    ResourceIdentityConflict,
    ResourceIdentityMissing,
    PlacementAttestationPending,
    PlacementAttestationNotFound,
    PlacementAttestationNotLive,
    ResidentMaterializationPending,
    WorkspaceCapacityExhausted,
    IdentityExchangeFailed,
    ResidentMaterializationFailed,
    MaestroWorkloadStaleGeneration,
}

impl LifecycleReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderTransient => "provider_transient",
            Self::KubernetesProviderTransient => "kubernetes_provider_transient",
            Self::WorkspaceCapacityPending => "workspace_capacity_pending",
            Self::ResourceContractConflict => "resource_contract_conflict",
            Self::RuntimeClassBoundaryUnverified => "runtime_class_boundary_unverified",
            Self::KubernetesPolicyDenied => "kubernetes_policy_denied",
            Self::KubernetesContractInvalid => "kubernetes_contract_invalid",
            Self::PodUnschedulable => "pod_unschedulable",
            Self::ResourceObservationMissing => "resource_observation_missing",
            Self::ResourceObservationInvalid => "resource_observation_invalid",
            Self::ResourceIdentityConflict => "resource_identity_conflict",
            Self::ResourceIdentityMissing => "resource_identity_missing",
            Self::PlacementAttestationPending => "placement_attestation_pending",
            Self::PlacementAttestationNotFound => "placement_attestation_not_found",
            Self::PlacementAttestationNotLive => "placement_attestation_not_live",
            Self::ResidentMaterializationPending => "resident_materialization_pending",
            Self::WorkspaceCapacityExhausted => "workspace_capacity_exhausted",
            Self::IdentityExchangeFailed => "identity_exchange_failed",
            Self::ResidentMaterializationFailed => "resident_materialization_failed",
            Self::MaestroWorkloadStaleGeneration => "maestro_workload_stale_generation",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        LIFECYCLE_REASON_CODES
            .iter()
            .copied()
            .find(|code| code.as_str() == value)
    }

    pub const fn default_provisioning_error_class(self) -> ProvisioningErrorClass {
        match self {
            Self::WorkspaceCapacityPending => ProvisioningErrorClass::RetryableCapacity,
            Self::ProviderTransient
            | Self::KubernetesProviderTransient
            | Self::ResourceObservationMissing
            | Self::ResourceObservationInvalid
            | Self::ResourceIdentityMissing => ProvisioningErrorClass::RetryableProvider,
            Self::KubernetesPolicyDenied | Self::RuntimeClassBoundaryUnverified => {
                ProvisioningErrorClass::TerminalSecurity
            }
            _ => ProvisioningErrorClass::TerminalContract,
        }
    }

    pub fn allows_provisioning_error_class(self, class: &ProvisioningErrorClass) -> bool {
        *class == self.default_provisioning_error_class()
            || (self == Self::ResourceContractConflict
                && *class == ProvisioningErrorClass::TerminalSecurity)
    }
}

pub const LIFECYCLE_REASON_CODES: &[LifecycleReasonCode] = &[
    LifecycleReasonCode::ProviderTransient,
    LifecycleReasonCode::KubernetesProviderTransient,
    LifecycleReasonCode::WorkspaceCapacityPending,
    LifecycleReasonCode::ResourceContractConflict,
    LifecycleReasonCode::RuntimeClassBoundaryUnverified,
    LifecycleReasonCode::KubernetesPolicyDenied,
    LifecycleReasonCode::KubernetesContractInvalid,
    LifecycleReasonCode::PodUnschedulable,
    LifecycleReasonCode::ResourceObservationMissing,
    LifecycleReasonCode::ResourceObservationInvalid,
    LifecycleReasonCode::ResourceIdentityConflict,
    LifecycleReasonCode::ResourceIdentityMissing,
    LifecycleReasonCode::PlacementAttestationPending,
    LifecycleReasonCode::PlacementAttestationNotFound,
    LifecycleReasonCode::PlacementAttestationNotLive,
    LifecycleReasonCode::ResidentMaterializationPending,
    LifecycleReasonCode::WorkspaceCapacityExhausted,
    LifecycleReasonCode::IdentityExchangeFailed,
    LifecycleReasonCode::ResidentMaterializationFailed,
    LifecycleReasonCode::MaestroWorkloadStaleGeneration,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleOutcome {
    pub code: &'static str,
    pub disposition: LifecycleDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxStateContract {
    pub state: &'static str,
    pub disposition: SandboxStateDisposition,
}

const fn outcome(code: LifecycleReasonCode, disposition: LifecycleDisposition) -> LifecycleOutcome {
    LifecycleOutcome {
        code: code.as_str(),
        disposition,
    }
}

pub const LIFECYCLE_OUTCOMES: &[LifecycleOutcome] = &[
    outcome(
        LifecycleReasonCode::ProviderTransient,
        LifecycleDisposition::RetrySameGeneration,
    ),
    outcome(
        LifecycleReasonCode::KubernetesProviderTransient,
        LifecycleDisposition::RetrySameGeneration,
    ),
    outcome(
        LifecycleReasonCode::WorkspaceCapacityPending,
        LifecycleDisposition::QueueSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::ResourceObservationMissing,
        LifecycleDisposition::RetrySameGeneration,
    ),
    outcome(
        LifecycleReasonCode::PlacementAttestationPending,
        LifecycleDisposition::RetrySameGeneration,
    ),
    outcome(
        LifecycleReasonCode::PlacementAttestationNotLive,
        LifecycleDisposition::RetrySameGeneration,
    ),
    outcome(
        LifecycleReasonCode::ResidentMaterializationPending,
        LifecycleDisposition::RetrySameGeneration,
    ),
    outcome(
        LifecycleReasonCode::ResourceContractConflict,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::RuntimeClassBoundaryUnverified,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::KubernetesPolicyDenied,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::KubernetesContractInvalid,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::PodUnschedulable,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::ResourceObservationInvalid,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::ResourceIdentityConflict,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::ResourceIdentityMissing,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::PlacementAttestationNotFound,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::WorkspaceCapacityExhausted,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::IdentityExchangeFailed,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::ResidentMaterializationFailed,
        LifecycleDisposition::TerminalSameGeneration,
    ),
    outcome(
        LifecycleReasonCode::MaestroWorkloadStaleGeneration,
        LifecycleDisposition::TerminalSameGeneration,
    ),
];

pub const SANDBOX_STATES: &[SandboxStateContract] = &[
    SandboxStateContract {
        state: "planning",
        disposition: SandboxStateDisposition::Pending,
    },
    SandboxStateContract {
        state: "provisioning",
        disposition: SandboxStateDisposition::Pending,
    },
    SandboxStateContract {
        state: "ready",
        disposition: SandboxStateDisposition::Active,
    },
    SandboxStateContract {
        state: "running",
        disposition: SandboxStateDisposition::Active,
    },
    SandboxStateContract {
        state: "idle",
        disposition: SandboxStateDisposition::Active,
    },
    SandboxStateContract {
        state: "archiving",
        disposition: SandboxStateDisposition::Terminal,
    },
    SandboxStateContract {
        state: "archived",
        disposition: SandboxStateDisposition::Terminal,
    },
    SandboxStateContract {
        state: "error",
        disposition: SandboxStateDisposition::Terminal,
    },
];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleContract {
    pub schema: &'static str,
    pub generation_advance: &'static str,
    pub unknown_outcome_disposition: LifecycleDisposition,
    pub sandbox_states: &'static [SandboxStateContract],
    pub outcomes: &'static [LifecycleOutcome],
}

pub const fn lifecycle_contract() -> LifecycleContract {
    LifecycleContract {
        schema: LIFECYCLE_CONTRACT_SCHEMA,
        generation_advance: "confirmed_absence_only",
        unknown_outcome_disposition: LifecycleDisposition::TerminalSameGeneration,
        sandbox_states: SANDBOX_STATES,
        outcomes: LIFECYCLE_OUTCOMES,
    }
}

pub fn lifecycle_contract_json() -> String {
    let mut json = serde_json::to_string_pretty(&lifecycle_contract())
        .expect("lifecycle contract is serializable");
    json.push('\n');
    json
}

#[derive(Debug, Error)]
#[error("{env}={configured} does not match compiled lifecycle contract {compiled}")]
pub struct LifecycleContractMismatch {
    env: &'static str,
    configured: String,
    compiled: &'static str,
}

pub fn verify_configured_lifecycle_contract() -> Result<(), LifecycleContractMismatch> {
    let Some(configured) = std::env::var(LIFECYCLE_CONTRACT_ENV)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    if configured == LIFECYCLE_CONTRACT_SHA256 {
        return Ok(());
    }
    Err(LifecycleContractMismatch {
        env: LIFECYCLE_CONTRACT_ENV,
        configured,
        compiled: LIFECYCLE_CONTRACT_SHA256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DbVariant, SandboxState};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;

    #[test]
    fn lifecycle_contract_has_unique_codes_and_states() {
        let codes = LIFECYCLE_OUTCOMES
            .iter()
            .map(|outcome| outcome.code)
            .collect::<BTreeSet<_>>();
        assert_eq!(codes.len(), LIFECYCLE_OUTCOMES.len());
        assert_eq!(
            codes,
            LIFECYCLE_REASON_CODES
                .iter()
                .map(|code| code.as_str())
                .collect::<BTreeSet<_>>(),
            "every typed lifecycle reason must be exported exactly once"
        );
        let states = SANDBOX_STATES
            .iter()
            .map(|state| state.state)
            .collect::<BTreeSet<_>>();
        assert_eq!(states.len(), SANDBOX_STATES.len());
        assert_eq!(
            states,
            SandboxState::VALUES
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            "the lifecycle artifact must classify every typed sandbox state"
        );
    }

    #[test]
    fn lifecycle_contract_artifact_is_current() {
        assert_eq!(
            lifecycle_contract_json(),
            include_str!("../../../contracts/lifecycle.v1.json")
        );
    }

    #[test]
    fn lifecycle_contract_digest_is_current() {
        assert_eq!(
            format!("{:x}", Sha256::digest(lifecycle_contract_json().as_bytes())),
            LIFECYCLE_CONTRACT_SHA256
        );
    }
}
