create table mfa_credentials
(
    user_id          varchar(36) primary key references users (id),
    secret_encrypted text    not null,
    enabled          boolean not null default false,
    last_step        bigint  not null default -1
);
create table recovery_codes
(
    user_id   varchar(36) references users (id),
    code_hash char(64),
    primary key (user_id, code_hash)
);
