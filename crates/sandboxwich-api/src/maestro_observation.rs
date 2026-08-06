use crate::db::Database;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::mpsc;
#[cfg(test)]
use tokio::sync::oneshot;
use tracing::warn;

const DEFAULT_QUEUE_CAPACITY: usize = 1_024;
const MAX_BATCH_SIZE: usize = 64;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ObservationKey {
    tenant_id: String,
    outcome: String,
    reason: String,
}

#[derive(Clone, Debug)]
struct Observation {
    key: ObservationKey,
    elapsed_ms: u128,
}

#[derive(Default)]
struct Aggregate {
    sample_count: i64,
    sum_ms: i64,
    buckets: [i64; 8],
}

impl Aggregate {
    fn add(&mut self, elapsed_ms: u128) {
        let elapsed_ms = i64::try_from(elapsed_ms).unwrap_or(i64::MAX);
        self.sample_count = self.sample_count.saturating_add(1);
        self.sum_ms = self.sum_ms.saturating_add(elapsed_ms);
        for (bucket, limit) in self.buckets.iter_mut().zip([
            1_000_u128, 5_000, 15_000, 30_000, 60_000, 120_000, 300_000, 900_000,
        ]) {
            if u128::try_from(elapsed_ms).unwrap_or(u128::MAX) <= limit {
                *bucket = bucket.saturating_add(1);
            }
        }
    }
}

enum Message {
    Observation(Observation),
    #[cfg(test)]
    Flush(oneshot::Sender<()>),
}

#[derive(Default)]
struct Losses {
    queue_full: AtomicU64,
    channel_closed: AtomicU64,
    write_failed: AtomicU64,
}

/// Bounded, best-effort persistence for the identity-validation histogram.
///
/// Exact activation validation remains on the request path. The aggregate
/// observation is deliberately lower priority: a bounded queue and a single
/// batched writer keep a busy identity listener from serializing every
/// successful connection on the database writer. Losses are counted and
/// exported so this optimization cannot silently erase measurement quality.
#[derive(Clone)]
pub(crate) struct ActivationObservationSink {
    sender: mpsc::Sender<Message>,
    losses: Arc<Losses>,
}

impl ActivationObservationSink {
    pub(crate) fn new(db: Database) -> Self {
        Self::with_capacity(db, DEFAULT_QUEUE_CAPACITY)
    }

    fn with_capacity(db: Database, capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let losses = Arc::new(Losses::default());
        tokio::spawn(run_writer(db, receiver, Arc::clone(&losses)));
        Self { sender, losses }
    }

    pub(crate) fn try_enqueue(
        &self,
        tenant_id: &str,
        outcome: &str,
        reason: &str,
        elapsed_ms: u128,
    ) {
        let message = Message::Observation(Observation {
            key: ObservationKey {
                tenant_id: tenant_id.to_owned(),
                outcome: outcome.to_owned(),
                reason: reason.to_owned(),
            },
            elapsed_ms,
        });
        match self.sender.try_send(message) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.losses.queue_full.fetch_add(1, Ordering::Relaxed);
                warn!(
                    event = "maestro_identity_metric_dropped",
                    reason = "queue_full",
                    outcome,
                    "identity validation observation queue is full"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.losses.channel_closed.fetch_add(1, Ordering::Relaxed);
                warn!(
                    event = "maestro_identity_metric_dropped",
                    reason = "channel_closed",
                    outcome,
                    "identity validation observation writer is stopped"
                );
            }
        }
    }

    pub(crate) fn loss_counts(&self) -> Vec<(String, i64)> {
        [
            ("queue_full", self.losses.queue_full.load(Ordering::Relaxed)),
            (
                "channel_closed",
                self.losses.channel_closed.load(Ordering::Relaxed),
            ),
            (
                "write_failed",
                self.losses.write_failed.load(Ordering::Relaxed),
            ),
        ]
        .into_iter()
        .map(|(reason, count)| (reason.to_string(), i64::try_from(count).unwrap_or(i64::MAX)))
        .collect()
    }

    #[cfg(test)]
    pub(crate) async fn flush(&self) {
        let (sender, receiver) = oneshot::channel();
        if self.sender.send(Message::Flush(sender)).await.is_ok() {
            let _ = receiver.await;
        }
    }
}

async fn run_writer(db: Database, mut receiver: mpsc::Receiver<Message>, losses: Arc<Losses>) {
    while let Some(message) = receiver.recv().await {
        let mut batch = Vec::with_capacity(MAX_BATCH_SIZE);
        #[cfg(test)]
        let mut flush_ack: Option<oneshot::Sender<()>> = None;
        match message {
            Message::Observation(observation) => batch.push(observation),
            #[cfg(test)]
            Message::Flush(sender) => {
                let _ = sender.send(());
                continue;
            }
        }

        while batch.len() < MAX_BATCH_SIZE {
            match receiver.try_recv() {
                Ok(Message::Observation(observation)) => batch.push(observation),
                #[cfg(test)]
                Ok(Message::Flush(sender)) => {
                    flush_ack = Some(sender);
                    break;
                }
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                    break;
                }
            }
        }

        flush_batch(&db, &batch, &losses).await;
        #[cfg(test)]
        if let Some(sender) = flush_ack {
            let _ = sender.send(());
        }
    }
}

async fn flush_batch(db: &Database, observations: &[Observation], losses: &Losses) {
    let mut aggregates = BTreeMap::<ObservationKey, Aggregate>::new();
    for observation in observations {
        aggregates
            .entry(observation.key.clone())
            .or_default()
            .add(observation.elapsed_ms);
    }

    for (key, aggregate) in aggregates {
        if let Err(error) = write_aggregate(db, &key, &aggregate).await {
            losses.write_failed.fetch_add(
                u64::try_from(aggregate.sample_count.max(0)).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            warn!(
                event = "maestro_identity_metric_write_failed",
                outcome = key.outcome,
                reason = key.reason,
                samples = aggregate.sample_count,
                error = ?error,
                "identity validation observation batch was not persisted"
            );
        }
    }
}

async fn write_aggregate(
    db: &Database,
    key: &ObservationKey,
    aggregate: &Aggregate,
) -> Result<(), sqlx::Error> {
    let sql = format!(
        "insert into maestro_activation_validation_metrics
         (tenant_id, outcome, reason, sample_count, sum_ms, b0, b1, b2, b3, b4, b5, b6, b7)
         values ({})
         on conflict (tenant_id, outcome, reason) do update set
           sample_count = maestro_activation_validation_metrics.sample_count + excluded.sample_count,
           sum_ms = maestro_activation_validation_metrics.sum_ms + excluded.sum_ms,
           b0 = maestro_activation_validation_metrics.b0 + excluded.b0,
           b1 = maestro_activation_validation_metrics.b1 + excluded.b1,
           b2 = maestro_activation_validation_metrics.b2 + excluded.b2,
           b3 = maestro_activation_validation_metrics.b3 + excluded.b3,
           b4 = maestro_activation_validation_metrics.b4 + excluded.b4,
           b5 = maestro_activation_validation_metrics.b5 + excluded.b5,
           b6 = maestro_activation_validation_metrics.b6 + excluded.b6,
           b7 = maestro_activation_validation_metrics.b7 + excluded.b7",
        db.placeholders(13)
    );
    sqlx::query(&sql)
        .bind(&key.tenant_id)
        .bind(&key.outcome)
        .bind(&key.reason)
        .bind(aggregate.sample_count)
        .bind(aggregate.sum_ms)
        .bind(aggregate.buckets[0])
        .bind(aggregate.buckets[1])
        .bind(aggregate.buckets[2])
        .bind(aggregate.buckets[3])
        .bind(aggregate.buckets[4])
        .bind(aggregate.buckets[5])
        .bind(aggregate.buckets[6])
        .bind(aggregate.buckets[7])
        .execute(&db.pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ActivationObservationSink;
    use crate::db::{connect_database, migrate_database};

    #[tokio::test]
    async fn burst_observations_are_batched_and_eventually_persisted() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = directory.path().join("sandboxwich.db");
        let db = connect_database(&format!("sqlite://{}", database_path.display()), 1)
            .await
            .unwrap();
        migrate_database(&db).await.unwrap();

        let sink = ActivationObservationSink::with_capacity(db.clone(), 8);
        sink.try_enqueue("identity-service", "accepted", "validated", 12);
        sink.try_enqueue("identity-service", "accepted", "validated", 42);
        sink.flush().await;

        let row: (i64, i64) = sqlx::query_as(
            "select sample_count, sum_ms
             from maestro_activation_validation_metrics
             where tenant_id = ? and outcome = ? and reason = ?",
        )
        .bind("identity-service")
        .bind("accepted")
        .bind("validated")
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(row, (2, 54));
    }
}
