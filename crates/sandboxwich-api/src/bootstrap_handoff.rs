//! Shared ephemeral handoff for resident-process bootstrap bytes.
//!
//! The in-process [`crate::state::ResidentBootstrapStore`] remains the
//! authority on delivery state (Ready / InFlight / Delivered) for the
//! process that admitted a bootstrap. This module gives that store a shared
//! ephemeral tier so the bytes survive an API restart or a read that lands
//! on another replica: the publishing process seals them under an
//! operator-held key and writes the ciphertext to
//! `resident_bootstrap_handoffs`; any process holding the same key can
//! rehydrate them on demand.
//!
//! The fence is unchanged by rehydration. Whether a rehydrated bootstrap
//! comes back Ready or already Delivered is decided by the durable
//! `resident_processes.bootstrap_delivered_*` columns, which are the same
//! columns the one-read consume statement fences on, so a replica that never
//! saw the original delivery still refuses a different generation, lease, or
//! digest.
//!
//! Fail-closed properties:
//!
//! - No key configured means no shared tier at all; behavior is exactly the
//!   process-local behavior that preceded it.
//! - Plaintext bootstrap bytes are never written: the durable row carries
//!   ciphertext plus the digest and byte count `resident_processes` already
//!   records.
//! - Decryption is bound (as AEAD associated data) to the resident process,
//!   tenant, sandbox, generation, and digest, so a row cannot be replayed
//!   under a different identity, and the plaintext digest is re-verified
//!   after opening.
//! - A row sealed under a different key id, an expired row, a structurally
//!   malformed row, or a row that fails to open is treated as absent, which
//!   surfaces as the existing `resident_bootstrap_unavailable` response. Only
//!   a database failure is an error.

use crate::db::Database;
use crate::state::LiveResidentBootstrap;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Utc};
use sandboxwich_core::{ResidentProcessId, SandboxId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{AnyConnection, Row};
use std::time::Duration;

pub(crate) const BOOTSTRAP_HANDOFF_KEY_BYTES: usize = 32;
pub(crate) const DEFAULT_BOOTSTRAP_HANDOFF_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Serialize, Deserialize)]
struct SealedBootstrapPayload {
    content: Vec<u8>,
    sterile_activation: Option<sandboxwich_core::SterileResidentActivationV1>,
}

/// An operator-held sealing key plus the retention window for sealed rows.
pub(crate) struct SharedBootstrapHandoff {
    cipher: XChaCha20Poly1305,
    key_id: String,
    ttl: Duration,
}

impl SharedBootstrapHandoff {
    pub(crate) fn new(key: [u8; BOOTSTRAP_HANDOFF_KEY_BYTES], ttl: Duration) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(Key::from_slice(&key)),
            key_id: key_id(&key),
            ttl,
        }
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    fn open_payload(
        &self,
        nonce: &XNonce,
        ciphertext: &[u8],
        id: ResidentProcessId,
        sandbox_id: SandboxId,
        bootstrap: &LiveResidentBootstrap,
    ) -> Option<SealedBootstrapPayload> {
        if let Ok(plaintext) = self.cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: associated_data(id, sandbox_id, bootstrap).as_bytes(),
            },
        ) {
            return serde_json::from_slice(&plaintext).ok();
        }
        // Rolling-deploy compatibility: releases before sterile activation
        // sealed the raw bootstrap content under the v1 AAD. New writers use
        // the v2 envelope, but readers must drain existing v1 handoffs without
        // changing the feature-off resident path.
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: legacy_associated_data(id, sandbox_id, bootstrap).as_bytes(),
                },
            )
            .ok()
            .map(|content| SealedBootstrapPayload {
                content,
                sterile_activation: None,
            })
    }

    /// Seals `bootstrap` and writes it on the caller's connection, so the
    /// handoff row commits atomically with the `resident_processes` row it
    /// belongs to.
    pub(crate) async fn publish_on_connection(
        &self,
        db: &Database,
        connection: &mut AnyConnection,
        id: ResidentProcessId,
        sandbox_id: SandboxId,
        bootstrap: &LiveResidentBootstrap,
        now: DateTime<Utc>,
    ) -> Result<(), HandoffError> {
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let plaintext = serde_json::to_vec(&SealedBootstrapPayload {
            content: bootstrap.content.clone(),
            sterile_activation: bootstrap.sterile_activation.clone(),
        })
        .map_err(|_| HandoffError::Seal)?;
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
                    aad: associated_data(id, sandbox_id, bootstrap).as_bytes(),
                },
            )
            .map_err(|_| HandoffError::Seal)?;
        let sql = format!(
            "insert into resident_bootstrap_handoffs (
                resident_process_id, sandbox_id, tenant_id, generation, sha256,
                byte_count, target_file, mode, key_id, nonce, ciphertext,
                created_at, expires_at
             ) values ({})",
            db.placeholders(13)
        );
        sqlx::query(&sql)
            .bind(id.to_string())
            .bind(sandbox_id.to_string())
            .bind(&bootstrap.tenant_id)
            .bind(bootstrap.generation as i64)
            .bind(&bootstrap.sha256)
            .bind(bootstrap.content.len() as i64)
            .bind(&bootstrap.target_file)
            .bind(i64::from(bootstrap.mode))
            .bind(&self.key_id)
            .bind(BASE64.encode(nonce_bytes))
            .bind(BASE64.encode(&ciphertext))
            .bind(now.to_rfc3339())
            .bind((now + self.ttl).to_rfc3339())
            .execute(connection)
            .await?;
        Ok(())
    }

    /// Opens the sealed row for `id`, if one is present, unexpired, sealed
    /// under this key, and internally consistent. Every other outcome is
    /// `Ok(None)`: an unreadable handoff is an absent handoff.
    pub(crate) async fn load(
        &self,
        db: &Database,
        id: ResidentProcessId,
        sandbox_id: SandboxId,
        now: DateTime<Utc>,
    ) -> Result<Option<LiveResidentBootstrap>, HandoffError> {
        let sql = format!(
            "select sandbox_id, tenant_id, generation, sha256, byte_count, target_file,
                    mode, key_id, nonce, ciphertext, expires_at
             from resident_bootstrap_handoffs where resident_process_id = {}",
            db.placeholder(1)
        );
        let Some(row) = sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&db.pool)
            .await?
        else {
            return Ok(None);
        };
        let row_sandbox_id: String = row.try_get("sandbox_id")?;
        let key_id: String = row.try_get("key_id")?;
        let expires_at: String = row.try_get("expires_at")?;
        let Ok(expires_at) = DateTime::parse_from_rfc3339(&expires_at) else {
            return Ok(unreadable("expires_at is not an RFC 3339 timestamp"));
        };
        if row_sandbox_id != sandbox_id.to_string()
            || key_id != self.key_id
            || expires_at.with_timezone(&Utc) <= now
        {
            return Ok(None);
        }
        let generation: i64 = row.try_get("generation")?;
        let byte_count: i64 = row.try_get("byte_count")?;
        let mode: i64 = row.try_get("mode")?;
        let (Ok(mode), Ok(generation)) = (u32::try_from(mode), u64::try_from(generation)) else {
            return Ok(unreadable("mode or generation is out of range"));
        };
        let bootstrap_shell = LiveResidentBootstrap {
            tenant_id: row.try_get("tenant_id")?,
            content: Vec::new(),
            sha256: row.try_get("sha256")?,
            target_file: row.try_get("target_file")?,
            mode,
            generation,
            sterile_activation: None,
        };
        let Ok(nonce_bytes) = BASE64.decode(row.try_get::<String, _>("nonce")?) else {
            return Ok(unreadable("nonce is not base64"));
        };
        if nonce_bytes.len() != 24 {
            return Ok(unreadable("nonce is not 24 bytes"));
        }
        let Ok(ciphertext) = BASE64.decode(row.try_get::<String, _>("ciphertext")?) else {
            return Ok(unreadable("ciphertext is not base64"));
        };
        let Some(payload) = self.open_payload(
            XNonce::from_slice(&nonce_bytes),
            &ciphertext,
            id,
            sandbox_id,
            &bootstrap_shell,
        ) else {
            return Ok(None);
        };
        let content = payload.content;
        if content.len() as i64 != byte_count || content_digest(&content) != bootstrap_shell.sha256
        {
            return Ok(None);
        }
        if !activation_matches_durable_fence(
            db,
            id,
            sandbox_id,
            payload.sterile_activation.as_ref(),
            Utc::now(),
        )
        .await?
        {
            return Ok(None);
        }
        Ok(Some(LiveResidentBootstrap {
            content,
            sterile_activation: payload.sterile_activation,
            ..bootstrap_shell
        }))
    }

    pub(crate) fn ttl(&self) -> Duration {
        self.ttl
    }
}

/// Deletes the sealed row for `id`. Called wherever the in-process store
/// drops its own copy (acknowledgment, reclamation, stop), so the shared
/// tier never outlives the process-local one.
pub(crate) async fn delete_handoff(
    db: &Database,
    id: ResidentProcessId,
) -> Result<(), HandoffError> {
    let sql = format!(
        "delete from resident_bootstrap_handoffs where resident_process_id = {}",
        db.placeholder(1)
    );
    sqlx::query(&sql)
        .bind(id.to_string())
        .execute(&db.pool)
        .await?;
    Ok(())
}

/// Retention sweep for sealed rows whose window has closed; runs on the
/// shared expiry sweeper alongside lease and snapshot expiry.
pub(crate) async fn expire_due_bootstrap_handoffs(db: &Database) -> Result<u64, HandoffError> {
    let sql = format!(
        "delete from resident_bootstrap_handoffs where expires_at <= {}",
        db.placeholder(1)
    );
    let deleted = sqlx::query(&sql)
        .bind(Utc::now().to_rfc3339())
        .execute(&db.pool)
        .await?;
    Ok(deleted.rows_affected())
}

/// A structurally broken row is an absent row, matching the treatment of a
/// row this process cannot open: the read surfaces as
/// `resident_bootstrap_unavailable` rather than an opaque server error.
fn unreadable(reason: &str) -> Option<LiveResidentBootstrap> {
    tracing::warn!(reason, "ignoring unreadable resident bootstrap handoff row");
    None
}

/// Binds a sealed row to exactly one resident identity: rekeying any of
/// these fields makes the ciphertext unopenable rather than replayable.
fn associated_data(
    id: ResidentProcessId,
    sandbox_id: SandboxId,
    bootstrap: &LiveResidentBootstrap,
) -> String {
    format!(
        "sandboxwich-resident-bootstrap-handoff/v2|{id}|{sandbox_id}|{}|{}|{}",
        bootstrap.tenant_id, bootstrap.generation, bootstrap.sha256
    )
}

fn legacy_associated_data(
    id: ResidentProcessId,
    sandbox_id: SandboxId,
    bootstrap: &LiveResidentBootstrap,
) -> String {
    format!(
        "sandboxwich-resident-bootstrap-handoff/v1|{id}|{sandbox_id}|{}|{}|{}",
        bootstrap.tenant_id, bootstrap.generation, bootstrap.sha256
    )
}

async fn activation_matches_durable_fence(
    db: &Database,
    id: ResidentProcessId,
    sandbox_id: SandboxId,
    activation: Option<&sandboxwich_core::SterileResidentActivationV1>,
    now: DateTime<Utc>,
) -> Result<bool, HandoffError> {
    let Some(activation) = activation else {
        let sql = format!(
            "select 1 from resident_processes where id = {} and sterile_lease_id is null",
            db.placeholder(1)
        );
        return Ok(sqlx::query(&sql)
            .bind(id.to_string())
            .fetch_optional(&db.pool)
            .await?
            .is_some());
    };
    let attestation_sha256 = content_digest(activation.lease_attestation.as_bytes());
    let sql = format!(
        "select 1
         from resident_processes rp
         join sterile_cells sc on sc.id = rp.sterile_cell_id
         where rp.id = {} and rp.sandbox_id = {} and rp.sterile_cell_id = {}
           and rp.sterile_lease_id = {} and rp.sterile_lease_generation = {}
           and sc.state = 'leased' and sc.lease_id = rp.sterile_lease_id
           and sc.generation = rp.sterile_lease_generation
           and sc.organization_id = {} and sc.workspace_id = {}
           and sc.thread_id = {} and sc.runner_session_id = {}
           and sc.lease_attestation_sha256 = {} and sc.lease_expires_at > {}",
        db.placeholder(1),
        db.placeholder(2),
        db.placeholder(3),
        db.placeholder(4),
        db.placeholder(5),
        db.placeholder(6),
        db.placeholder(7),
        db.placeholder(8),
        db.placeholder(9),
        db.placeholder(10),
        db.placeholder(11),
    );
    Ok(sqlx::query(&sql)
        .bind(id.to_string())
        .bind(sandbox_id.to_string())
        .bind(sandbox_id.to_string())
        .bind(activation.lease_id.to_string())
        .bind(activation.generation as i64)
        .bind(&activation.organization_id)
        .bind(&activation.workspace_id)
        .bind(&activation.thread_id)
        .bind(&activation.runner_session_id)
        .bind(attestation_sha256)
        .bind(now.to_rfc3339())
        .fetch_optional(&db.pool)
        .await?
        .is_some())
}

fn content_digest(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

/// A non-secret, stable label for the configured key, so a rotated key's
/// rows are ignored instead of failing to open one row at a time.
fn key_id(key: &[u8; BOOTSTRAP_HANDOFF_KEY_BYTES]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sandboxwich-resident-bootstrap-handoff-key-id/v1");
    hasher.update(key);
    format!("{:x}", hasher.finalize())[..16].to_string()
}

#[derive(Debug)]
pub(crate) enum HandoffError {
    Database(sqlx::Error),
    Seal,
}

impl std::fmt::Display for HandoffError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "bootstrap handoff database error: {error}"),
            Self::Seal => write!(formatter, "bootstrap handoff could not be sealed"),
        }
    }
}

impl std::error::Error for HandoffError {}

impl From<sqlx::Error> for HandoffError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// Parses `SANDBOXWICH_BOOTSTRAP_HANDOFF_KEY`: base64 of exactly 32 bytes.
pub(crate) fn parse_bootstrap_handoff_key(
    value: &str,
) -> anyhow::Result<[u8; BOOTSTRAP_HANDOFF_KEY_BYTES]> {
    let decoded = BASE64.decode(value.trim()).map_err(|_| {
        anyhow::anyhow!(
            "invalid SANDBOXWICH_BOOTSTRAP_HANDOFF_KEY: expected standard base64 of {BOOTSTRAP_HANDOFF_KEY_BYTES} bytes"
        )
    })?;
    <[u8; BOOTSTRAP_HANDOFF_KEY_BYTES]>::try_from(decoded.as_slice()).map_err(|_| {
        anyhow::anyhow!(
            "invalid SANDBOXWICH_BOOTSTRAP_HANDOFF_KEY: expected exactly {BOOTSTRAP_HANDOFF_KEY_BYTES} decoded bytes"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bootstrap(content: &[u8]) -> LiveResidentBootstrap {
        LiveResidentBootstrap {
            tenant_id: "tenant-a".into(),
            content: content.to_vec(),
            sha256: content_digest(content),
            target_file: "/run/orb/bootstrap".into(),
            mode: 0o600,
            generation: 3,
            sterile_activation: None,
        }
    }

    #[test]
    fn bootstrap_handoff_key_requires_thirty_two_decoded_bytes() {
        assert!(parse_bootstrap_handoff_key("not base64!").is_err());
        assert!(parse_bootstrap_handoff_key(&BASE64.encode([7u8; 16])).is_err());
        assert_eq!(
            parse_bootstrap_handoff_key(&BASE64.encode([7u8; 32])).unwrap(),
            [7u8; 32]
        );
    }

    #[test]
    fn key_id_is_stable_per_key_and_carries_no_key_material() {
        let first = key_id(&[1u8; 32]);
        assert_eq!(first, key_id(&[1u8; 32]));
        assert_ne!(first, key_id(&[2u8; 32]));
        assert_eq!(first.len(), 16);
        assert!(!BASE64.encode([1u8; 32]).contains(&first));
    }

    /// The sealed bytes only open for the exact resident identity they were
    /// sealed for; this is what stops one sandbox's sealed row from being
    /// replayed as another's.
    #[test]
    fn sealed_bootstrap_opens_only_under_its_own_associated_data() {
        let handoff = SharedBootstrapHandoff::new([9u8; 32], DEFAULT_BOOTSTRAP_HANDOFF_TTL);
        let id = ResidentProcessId::new();
        let sandbox_id = SandboxId::new();
        let bootstrap = bootstrap(b"resident-credential");
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let sealed = handoff
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &bootstrap.content,
                    aad: associated_data(id, sandbox_id, &bootstrap).as_bytes(),
                },
            )
            .unwrap();
        assert_ne!(sealed, bootstrap.content);

        assert_eq!(
            handoff
                .cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &sealed,
                        aad: associated_data(id, sandbox_id, &bootstrap).as_bytes(),
                    },
                )
                .unwrap(),
            bootstrap.content
        );
        assert!(
            handoff
                .cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &sealed,
                        aad: associated_data(ResidentProcessId::new(), sandbox_id, &bootstrap)
                            .as_bytes(),
                    },
                )
                .is_err()
        );
        let rotated = SharedBootstrapHandoff::new([10u8; 32], DEFAULT_BOOTSTRAP_HANDOFF_TTL);
        assert_ne!(rotated.key_id(), handoff.key_id());
        assert!(
            rotated
                .cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &sealed,
                        aad: associated_data(id, sandbox_id, &bootstrap).as_bytes(),
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn v2_reader_opens_a_legacy_v1_raw_handoff() {
        let handoff = SharedBootstrapHandoff::new([4u8; 32], DEFAULT_BOOTSTRAP_HANDOFF_TTL);
        let id = ResidentProcessId::new();
        let sandbox_id = SandboxId::new();
        let bootstrap = bootstrap(b"legacy-resident-credential");
        let nonce = XNonce::from_slice(&[7u8; 24]);
        let ciphertext = handoff
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &bootstrap.content,
                    aad: legacy_associated_data(id, sandbox_id, &bootstrap).as_bytes(),
                },
            )
            .unwrap();

        let opened = handoff
            .open_payload(nonce, &ciphertext, id, sandbox_id, &bootstrap)
            .expect("legacy v1 handoff remains readable during rollout");
        assert_eq!(opened.content, bootstrap.content);
        assert!(opened.sterile_activation.is_none());
    }
}
