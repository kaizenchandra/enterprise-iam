-- Old writers must be drained: Redis markers do not establish durable MFA assurance.
alter table identity_sessions
    add column mfa_verified_at timestamptz;
alter table identity_sessions
    add column mfa_method varchar(16) check (mfa_method in ('otp', 'recovery'));
alter table users
    add column mfa_failed_attempts integer not null default 0 check (mfa_failed_attempts >= 0);
alter table users
    add column mfa_locked_until timestamptz;
-- Legacy Redis assurance cannot be attested. End enrolled users' sessions and grants
-- while preserving replay state and recording durable logout before grant deletion.
insert into logout_deliveries(id, rp_session_id)
select gen_random_uuid()::text,r.id
from oidc_rp_sessions r
         join identity_sessions s on s.id = r.session_id
         join mfa_credentials m on m.user_id = s.principal_name and m.enabled
where s.revoked_at is null on conflict(rp_session_id) do nothing;
update identity_sessions s
set revoked_at=coalesce(s.revoked_at, clock_timestamp())
where exists(select 1 from mfa_credentials m where m.user_id = s.principal_name and m.enabled);
update authorization_lifecycle a
set revoked_at=coalesce(a.revoked_at, clock_timestamp()),
    revision=revision + 1
where exists(select 1 from mfa_credentials m where m.user_id = a.principal_name and m.enabled);
delete
from oauth2_authorization a
where exists(select 1 from mfa_credentials m where m.user_id = a.principal_name and m.enabled);
update users u
set sessions_not_before=greatest(u.sessions_not_before, clock_timestamp())
where exists(select 1 from mfa_credentials m where m.user_id = u.id and m.enabled);
insert into security_audit_events(id, event_type, subject_id, actor_id)
select gen_random_uuid()::text,'MFA_ASSURANCE_UPGRADE', m.user_id, 'migration:V9'
from mfa_credentials m
where m.enabled;
