-- Public management identifiers are unrelated to browser cookies and OIDC sid.
alter table identity_sessions
    add column management_id uuid not null default gen_random_uuid();
create unique index identity_sessions_management_id on identity_sessions (management_id);
alter table identity_sessions
    add column last_seen_at timestamptz;
update identity_sessions
set last_seen_at=created_at;
alter table identity_sessions
    alter column last_seen_at set not null;
alter table identity_sessions
    alter column last_seen_at set default clock_timestamp();
create index identity_sessions_owner_page on identity_sessions (principal_name, management_id);
-- This user-level fence survives session/history GC. Drain pre-V8 writers before rollout.
alter table users
    add column sessions_not_before timestamptz not null default '-infinity';
alter table security_audit_events
    add column actor_id varchar(200);
alter table security_audit_events
    add column target_session_id uuid;
