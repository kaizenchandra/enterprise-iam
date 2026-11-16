-- Existing authorizations cannot safely be assigned an OP session or absolute lifetime.
-- Fail closed on upgrade: users/clients must obtain fresh grants. Preserve digest history.
delete
from oauth2_authorization;
create table identity_sessions
(
    id             varchar(36) primary key,
    principal_name varchar(200) not null,
    revoked_at     timestamptz
);
create index identity_sessions_principal on identity_sessions (principal_name);
create table authorization_lifecycle
(
    id             varchar(100) primary key,
    principal_name varchar(200) not null,
    client_id      varchar(100) not null,
    session_id     varchar(36) references identity_sessions (id),
    created_at     timestamptz  not null,
    expires_at     timestamptz  not null,
    revision       bigint       not null,
    revoked_at     timestamptz,
    check (expires_at > created_at)
);
create index lifecycle_principal on authorization_lifecycle (principal_name);
create index lifecycle_session on authorization_lifecycle (session_id);
create index lifecycle_expiry on authorization_lifecycle (expires_at);
