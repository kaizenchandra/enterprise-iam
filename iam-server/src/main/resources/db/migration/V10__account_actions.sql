alter table users
    add column email varchar(254);
alter table users
    add column email_verified boolean not null default false;
create unique index users_email_unique on users (email) where email is not null;
create table account_requests
(
    id              uuid primary key,
    kind            varchar(8)  not null check (kind in ('VERIFY', 'RESET')),
    envelope        text,
    next_attempt_at timestamptz not null default clock_timestamp(),
    created_at      timestamptz not null default clock_timestamp(),
    expires_at      timestamptz not null default (clock_timestamp() + interval '15 minutes'),
    completed_at    timestamptz
);
create index account_requests_pending on account_requests (created_at) where completed_at is null;
create table account_request_limits
(
    address_hash char(64) primary key,
    requested_at timestamptz not null default clock_timestamp()
);
create table account_action_tokens
(
    token_hash   char(64) primary key,
    user_id      varchar(36) not null references users (id),
    kind         varchar(8)  not null check (kind in ('VERIFY', 'RESET')),
    user_version bigint      not null,
    created_at   timestamptz not null default clock_timestamp(),
    expires_at   timestamptz not null,
    consumed_at  timestamptz
);
create index account_action_user on account_action_tokens (user_id);
create index account_action_expiry on account_action_tokens (expires_at);
create table account_mail
(
    id              uuid primary key,
    token_hash      char(64) references account_action_tokens (token_hash),
    envelope        text,
    status          varchar(12) not null default 'PENDING' check (status in ('PENDING', 'INFLIGHT', 'SUCCEEDED', 'DEAD')),
    attempts        integer     not null default 0,
    next_attempt_at timestamptz not null default clock_timestamp(),
    deadline        timestamptz not null,
    lease_id        uuid,
    lease_until     timestamptz,
    completed_at    timestamptz
);
create index account_mail_due on account_mail (next_attempt_at) where status in ('PENDING','INFLIGHT');

create index account_requests_retention on account_requests (completed_at);
create index account_mail_retention on account_mail (completed_at);
create index account_request_limits_retention on account_request_limits (requested_at);
