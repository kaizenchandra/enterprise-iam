create table passkey_metadata_state
(
    id              integer primary key check (id = 1),
    serial          integer     not null,
    digest          char(64)    not null,
    configuration   char(64)    not null,
    policy_revision bigint      not null check (policy_revision > 0),
    required        boolean     not null,
    blob            text        not null,
    accepted_at     timestamptz not null,
    expires_at      timestamptz not null
);
create table passkey_model_eligibility
(
    aaguid   uuid primary key,
    eligible boolean not null
);
create table passkey_revoked_models
(
    aaguid       uuid primary key,
    first_serial integer     not null,
    revoked_at   timestamptz not null default clock_timestamp()
);
alter table passkey_credentials
    add column attestation_aaguid uuid;
alter table passkey_credentials
    add column attestation_chain text;
alter table passkey_credentials
    add column attestation_revoked_at timestamptz;
alter table passkey_credentials
    add constraint attestation_pair check ((attestation_aaguid is null) = (attestation_chain is null));
create index passkey_attested_model on passkey_credentials (attestation_aaguid) where attestation_aaguid is not null;
