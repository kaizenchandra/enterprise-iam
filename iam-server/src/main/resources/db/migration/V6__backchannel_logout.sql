create table oidc_rp_sessions
(
    id                   varchar(36) primary key,
    session_id           varchar(36)   not null references identity_sessions (id),
    registered_client_id varchar(100)  not null,
    client_id            varchar(100)  not null,
    subject              varchar(200)  not null,
    sid                  varchar(256)  not null,
    endpoint             varchar(2048) not null,
    unique (session_id, registered_client_id, sid)
);
create index rp_session_parent on oidc_rp_sessions (session_id);
create table logout_deliveries
(
    id              varchar(36) primary key,
    rp_session_id   varchar(36) not null unique references oidc_rp_sessions (id),
    status          varchar(16) not null default 'PENDING' check (status in ('PENDING', 'INFLIGHT', 'SUCCEEDED', 'DEAD')),
    attempts        integer     not null default 0,
    next_attempt_at timestamptz not null default clock_timestamp(),
    deadline        timestamptz not null default (clock_timestamp() + interval '24 hours'),
    lease_id        varchar(36),
    lease_until     timestamptz,
    claimed_at      timestamptz,
    completed_at    timestamptz,
    last_outcome    varchar(40)
);
create index logout_due on logout_deliveries (status, next_attempt_at, lease_until);
create index logout_terminal on logout_deliveries (completed_at) where completed_at is not null;
