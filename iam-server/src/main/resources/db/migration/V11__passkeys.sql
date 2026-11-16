create table passkey_credentials
(
    id              uuid primary key,
    user_id         varchar(36) not null references users (id),
    credential_id   text        not null unique,
    public_key_cose text        not null,
    signature_count bigint      not null check (signature_count >= 0),
    backup_eligible boolean     not null,
    backed_up       boolean     not null,
    created_at      timestamptz not null default clock_timestamp(),
    last_used_at    timestamptz
);
create index passkey_owner on passkey_credentials (user_id);
create table passkey_challenges
(
    id            uuid primary key,
    binding       char(64)    not null,
    kind          varchar(8)  not null check (kind in ('REGISTER', 'AUTH')),
    user_id       varchar(36) references users (id),
    user_version  bigint,
    op_session    varchar(36),
    options       text        not null,
    configuration char(64)    not null,
    created_at    timestamptz not null default clock_timestamp(),
    expires_at    timestamptz not null default (clock_timestamp() + interval '2 minutes'),
    consumed_at   timestamptz
);
create index passkey_challenge_binding on passkey_challenges (binding, kind);
create index passkey_challenge_expiry on passkey_challenges (expires_at);
alter table users
    add column passkey_reauth_failures integer not null default 0 check (passkey_reauth_failures >= 0);
alter table users
    add column passkey_reauth_locked_until timestamptz;
