-- Public verification material only. Retain revision tombstones when authentication is disabled.
create table client_assertion_keys
(
    client_id  varchar(100) primary key references oauth2_registered_client (id) on delete cascade,
    revision   bigint      not null check (revision > 0),
    enabled    boolean     not null,
    jwks       text        not null,
    updated_at timestamptz not null default clock_timestamp()
);
-- Hash identifiers, never persist a reusable assertion. Independent commits survive issuance rollback.
create table client_assertion_replays
(
    -- Use the external issuer/client ID, with no cascading deletion: recreation must not erase live replay evidence.
    client_id  varchar(100) not null,
    jti_hash   char(64)     not null,
    expires_at timestamptz  not null,
    primary key (client_id, jti_hash)
);
create index client_assertion_replays_expiry on client_assertion_replays (expires_at);
