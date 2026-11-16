alter table passkey_metadata_state
    add column source varchar(16) not null default 'OFFLINE' check (source in ('OFFLINE', 'LIVE'));
alter table passkey_metadata_state
    add column retrieval_cache text not null default '{}';
alter table passkey_metadata_state
    add column evidence_digest char(64) not null default repeat('0', 64);
create table passkey_mds_fetch_state
(
    id            integer primary key check (id = 1),
    lease_id      uuid,
    lease_until   timestamptz,
    next_fetch_at timestamptz not null default clock_timestamp()
);
insert into passkey_mds_fetch_state(id)
values (1);
