alter table mfa_credentials
    add column enrollment_expires_at timestamptz;
alter table mfa_credentials
    add column enrollment_session varchar(64);
-- Unconfirmed legacy enrollments must be restarted.
update mfa_credentials
set enrollment_expires_at=clock_timestamp()
where not enabled;
