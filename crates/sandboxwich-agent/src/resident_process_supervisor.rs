use std::{collections::HashMap, future::Future};

use anyhow::Context as _;
use sandboxwich_core::{
    JobId, JobLease, LeaseId, LeaseResponse, ORB_EXECUTOR_RESIDENT_PROCESS_NAME, ResidentProcessId,
};
use tokio::task::{Id, JoinError, JoinSet};

/// Stable identity for a resident task. Keeping this outside the task future
/// means a panic can still be attributed to the exact control-plane objects
/// whose execution was interrupted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResidentProcessTaskMetadata {
    pub(crate) lease_id: LeaseId,
    pub(crate) job_id: JobId,
    pub(crate) process_id: ResidentProcessId,
    pub(crate) name: String,
    pub(crate) generation: u64,
}

impl ResidentProcessTaskMetadata {
    pub(crate) fn from_lease(lease: &JobLease) -> anyhow::Result<Self> {
        let process_id = serde_json::from_value(
            lease
                .job
                .payload
                .get("residentProcessId")
                .cloned()
                .context("residentProcessId is missing")?,
        )
        .context("residentProcessId is invalid")?;
        let generation = lease
            .job
            .payload
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            .context("resident generation is missing")?;
        let name = lease
            .job
            .payload
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(ORB_EXECUTOR_RESIDENT_PROCESS_NAME)
            .to_string();
        Ok(Self {
            lease_id: lease.id,
            job_id: lease.job_id,
            process_id,
            name,
            generation,
        })
    }
}

#[derive(Debug)]
pub(crate) enum ResidentProcessTaskCompletion {
    Finished {
        metadata: ResidentProcessTaskMetadata,
        result: anyhow::Result<()>,
    },
    Panicked {
        metadata: ResidentProcessTaskMetadata,
        error: JoinError,
    },
    Cancelled {
        metadata: ResidentProcessTaskMetadata,
    },
}

impl ResidentProcessTaskCompletion {
    pub(crate) fn into_failure(self) -> Option<(ResidentProcessTaskMetadata, String, bool)> {
        match self {
            Self::Finished { result: Ok(_), .. } => None,
            Self::Finished {
                metadata,
                result: Err(error),
            } => Some((metadata, error.to_string(), false)),
            Self::Panicked { metadata, error } => Some((
                metadata,
                format!("resident-process task panicked: {error}"),
                false,
            )),
            Self::Cancelled { metadata } => Some((
                metadata,
                "resident-process task was cancelled during daemon shutdown".to_string(),
                true,
            )),
        }
    }
}

/// Bounded owner for every long-lived resident task in one agent daemon.
///
/// `JoinSet` alone cannot identify which lease panicked. This supervisor keeps
/// metadata keyed by Tokio task id, caps concurrency, and drains every task on
/// shutdown so child processes with `kill_on_drop(true)` are actually reaped.
pub(crate) struct ResidentProcessSupervisor {
    tasks: JoinSet<anyhow::Result<()>>,
    metadata: HashMap<Id, ResidentProcessTaskMetadata>,
    max_active: usize,
}

impl ResidentProcessSupervisor {
    pub(crate) fn new(max_active: usize) -> Self {
        Self {
            tasks: JoinSet::new(),
            metadata: HashMap::new(),
            max_active: max_active.max(1),
        }
    }

    pub(crate) fn active_len(&self) -> usize {
        self.metadata.len()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.active_len() >= self.max_active
    }

    pub(crate) fn spawn<F>(
        &mut self,
        metadata: ResidentProcessTaskMetadata,
        task: F,
    ) -> anyhow::Result<()>
    where
        F: Future<Output = anyhow::Result<LeaseResponse>> + Send + 'static,
    {
        anyhow::ensure!(
            !self.is_full(),
            "resident-process supervisor is at its {} task limit",
            self.max_active
        );
        let task_id = self.tasks.spawn(async move { task.await.map(|_| ()) }).id();
        let previous = self.metadata.insert(task_id, metadata);
        debug_assert!(previous.is_none());
        Ok(())
    }

    pub(crate) fn try_reap(&mut self) -> Option<ResidentProcessTaskCompletion> {
        let result = self.tasks.try_join_next_with_id()?;
        Some(self.completion(result))
    }

    pub(crate) async fn shutdown(&mut self) -> Vec<ResidentProcessTaskCompletion> {
        self.tasks.abort_all();
        let mut completions = Vec::with_capacity(self.active_len());
        while let Some(result) = self.tasks.join_next_with_id().await {
            completions.push(self.completion(result));
        }
        debug_assert!(self.metadata.is_empty());
        completions
    }

    fn completion(
        &mut self,
        result: Result<(Id, anyhow::Result<()>), JoinError>,
    ) -> ResidentProcessTaskCompletion {
        match result {
            Ok((task_id, result)) => {
                let metadata = self.remove_metadata(task_id);
                ResidentProcessTaskCompletion::Finished { metadata, result }
            }
            Err(error) => {
                let metadata = self.remove_metadata(error.id());
                if error.is_cancelled() {
                    ResidentProcessTaskCompletion::Cancelled { metadata }
                } else {
                    ResidentProcessTaskCompletion::Panicked { metadata, error }
                }
            }
        }
    }

    fn remove_metadata(&mut self, task_id: Id) -> ResidentProcessTaskMetadata {
        self.metadata
            .remove(&task_id)
            .expect("every supervised task id must retain its metadata until reaped")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sandboxwich_core::{JobId, LeaseId, ResidentProcessId};
    use uuid::Uuid;

    use super::*;

    fn metadata(generation: u64) -> ResidentProcessTaskMetadata {
        ResidentProcessTaskMetadata {
            lease_id: LeaseId::new(),
            job_id: JobId::new(),
            process_id: ResidentProcessId(Uuid::now_v7()),
            name: "orb-executor".to_string(),
            generation,
        }
    }

    async fn reap(supervisor: &mut ResidentProcessSupervisor) -> ResidentProcessTaskCompletion {
        loop {
            if let Some(completion) = supervisor.try_reap() {
                return completion;
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn runner_error_retains_exact_metadata() {
        let expected = metadata(11);
        let mut supervisor = ResidentProcessSupervisor::new(1);
        supervisor
            .spawn(expected.clone(), async { anyhow::bail!("runner failed") })
            .unwrap();

        let (actual, error, cancelled) = reap(&mut supervisor).await.into_failure().unwrap();

        assert_eq!(actual, expected);
        assert!(error.contains("runner failed"));
        assert!(!cancelled);
        assert_eq!(supervisor.active_len(), 0);
    }

    #[tokio::test]
    async fn runner_panic_retains_exact_metadata() {
        let expected = metadata(12);
        let mut supervisor = ResidentProcessSupervisor::new(1);
        supervisor
            .spawn(expected.clone(), async {
                panic!("injected resident panic")
            })
            .unwrap();

        let (actual, error, cancelled) = reap(&mut supervisor).await.into_failure().unwrap();

        assert_eq!(actual, expected);
        assert!(error.contains("panicked"));
        assert!(!cancelled);
        assert_eq!(supervisor.active_len(), 0);
    }

    #[tokio::test]
    async fn capacity_is_bounded_and_shutdown_drains_cancellation() {
        let first = metadata(1);
        let second = metadata(2);
        let mut supervisor = ResidentProcessSupervisor::new(1);
        supervisor
            .spawn(first.clone(), async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                anyhow::bail!("should be cancelled")
            })
            .unwrap();

        let error = supervisor
            .spawn(second, async { anyhow::bail!("must not spawn") })
            .expect_err("the second task exceeds the configured bound");
        assert!(error.to_string().contains("task limit"));

        let completions = supervisor.shutdown().await;
        assert_eq!(completions.len(), 1);
        let (actual, error, cancelled) = completions
            .into_iter()
            .next()
            .unwrap()
            .into_failure()
            .unwrap();
        assert_eq!(actual, first);
        assert!(error.contains("daemon shutdown"));
        assert!(cancelled);
        assert_eq!(supervisor.active_len(), 0);
    }
}
