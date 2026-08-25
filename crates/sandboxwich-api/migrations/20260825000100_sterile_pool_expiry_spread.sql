-- Cohort expiry spread for purpose-created pool members.
--
-- A pool that fills in one replenishment cycle admits every member within a
-- few seconds of the others, and each member's ready TTL then starts at the
-- same instant. Every cell therefore expires as one cohort, the whole pool
-- goes to 'stopping' together, and claims fail until replacements finish
-- provisioning. This column records the slot width, in seconds, used to push
-- each new member's expiry one slot past the latest live ready peer in its
-- own cohort, so expiries land one slot apart instead of together.
--
-- The default of zero reproduces the previous synchronous behaviour, which is
-- what rows created before this migration were given.
alter table sterile_pool_memberships
    add column expiry_spread_seconds integer not null default 0;
