-- Deploy only after draining writers that do not enforce the retention floor.
create table authorization_retention_state
(
    singleton          boolean primary key default true check (singleton),
    initial_not_before timestamptz not null
);
insert into authorization_retention_state(singleton, initial_not_before)
values (true, clock_timestamp() - interval '1 minute');
alter table authorization_lifecycle
    add column grant_expires_at timestamptz;
-- Conservative backfill: old grants remain eligible only within their existing family deadline.
update authorization_lifecycle
set grant_expires_at=expires_at;
alter table authorization_lifecycle
    alter column grant_expires_at set not null;
create index lifecycle_grant_expiry on authorization_lifecycle (grant_expires_at, id);
alter table identity_sessions
    add column created_at timestamptz not null default clock_timestamp();
alter table identity_sessions
    add column expires_at timestamptz not null default (clock_timestamp() + interval '8 hours');
create index identity_sessions_expiry on identity_sessions (expires_at, id);
create index refresh_history_created on refresh_history (created_at, token_hash);
