-- Drain old writers first: they do not check or maintain the durable idle deadline.
alter table identity_sessions
    add column idle_timeout_seconds integer not null default 1200
        check (idle_timeout_seconds between 1 and 86400);
alter table identity_sessions
    add column idle_expires_at timestamptz;
-- Old Redis activity cannot be reconstructed. End legacy sessions conservatively;
-- the expiry worker preserves their participants and enqueues logout before GC.
update identity_sessions
set idle_expires_at=least(expires_at, clock_timestamp());
alter table identity_sessions
    alter column idle_expires_at set not null;
alter table identity_sessions
    alter column idle_expires_at set default (clock_timestamp() + interval '20 minutes');
create index identity_sessions_due on identity_sessions (least(expires_at,idle_expires_at), id) where revoked_at is null;
