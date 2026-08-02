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
use sha2::{Digest, Sha256};
use sqlx::{AnyConnection, Row};
use std::time::Duration;

pub(crate) const BOOTSTRAP_HANDOFF_KEY_BYTES: usize = 32;
pub(crate) const DEFAULT_BOOTSTRAP_HANDOFF_TTL: Duration = Duration::from_secs(60 * 60);

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
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &bootstrap.content,
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
        let Ok(content) = self.cipher.decrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad: associated_data(id, sandbox_id, &bootstrap_shell).as_bytes(),
            },
        ) else {
            return Ok(None);
        };
        if content.len() as i64 != byte_count || content_digest(&content) != bootstrap_shell.sha256
        {
            return Ok(None);
        }
        Ok(Some(LiveResidentBootstrap {
            content,
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
        "sandboxwich-resident-bootstrap-handoff/v1|{id}|{sandbox_id}|{}|{}|{}",
        bootstrap.tenant_id, bootstrap.generation, bootstrap.sha256
    )
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
}
