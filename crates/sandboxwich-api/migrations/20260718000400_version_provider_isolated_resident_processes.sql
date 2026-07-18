-- A sidecar row created before provider isolation was enforced must not be
-- mistaken for a provider-isolated sidecar after an API upgrade. Existing
-- rows deliberately remain version 0; only newly admitted sidecars are
-- written with the current provider-isolation version.
alter table resident_processes
    add column provider_isolation_version integer not null default 0
    check (provider_isolation_version >= 0);

-- Compatibility cleanup for databases exercised by pre-release builds of
-- the sidecar feature. Provider isolation is advertised through a versioned
-- worker label now, while the closed v1 capability enum remains unchanged.
update workers
set capabilities = replace(
    replace(
        replace(capabilities, '"provider_isolated_resident_process_v1",', ''),
        ',"provider_isolated_resident_process_v1"',
        ''
    ),
    '"provider_isolated_resident_process_v1"',
    ''
)
where capabilities like '%"provider_isolated_resident_process_v1"%';

update jobs
set required_capability = 'run_command'
where required_capability = 'provider_isolated_resident_process_v1';

-- The pre-release event names were also closed wire-enum additions. Rewrite
-- any already-persisted rows to the existing lifecycle event kind and carry
-- the feature-specific discriminator in extensible event data instead.
update sandbox_events
set kind = 'lifecycle_changed',
    data = case
        when data = '{}' then '{"eventType":"sidecar_bootstrap_blocked"}'
        when data like '{%}' then
            substr(data, 1, length(data) - 1)
                || ',"eventType":"sidecar_bootstrap_blocked"}'
        else '{"eventType":"sidecar_bootstrap_blocked"}'
    end
where kind = 'sidecar_bootstrap_blocked';

update sandbox_events
set kind = 'lifecycle_changed',
    data = case
        when data = '{}' then '{"eventType":"resident_process_terminal_failure"}'
        when data like '{%}' then
            substr(data, 1, length(data) - 1)
                || ',"eventType":"resident_process_terminal_failure"}'
        else '{"eventType":"resident_process_terminal_failure"}'
    end
where kind = 'resident_process_terminal_failure';
