create table rp_bindings
(
    session_id varchar(100) primary key,
    issuer     varchar(512) not null,
    client_id  varchar(100) not null,
    subject    varchar(200) not null,
    sid        varchar(256) not null,
    created_at timestamptz  not null default clock_timestamp(),
    expires_at timestamptz  not null default (clock_timestamp() + interval '8 hours')
);
create index rp_binding_sid on rp_bindings (issuer, client_id, sid);
create table rp_logout_receipts
(
    issuer      varchar(512),
    client_id   varchar(100),
    jti         varchar(100),
    fingerprint char(64)    not null,
    expires_at  timestamptz not null,
    primary key (issuer, client_id, jti)
);
create table rp_revoked_sids
(
    issuer     varchar(512),
    client_id  varchar(100),
    sid        varchar(256),
    revoked_at timestamptz not null default clock_timestamp(),
    primary key (issuer, client_id, sid)
);
create table rp_creation_floor
(
    issuer     varchar(512),
    client_id  varchar(100),
    not_before timestamptz not null default '1970-01-01T00:00:00Z',
    primary key (issuer, client_id)
);
