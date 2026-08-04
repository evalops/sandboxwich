-- Speed the heartbeat-history throttle lookback
-- (`insert_worker_heartbeat` checks for a recent sample per worker).
create index if not exists idx_worker_heartbeats_worker_created
    on worker_heartbeats(worker_id, created_at desc);
