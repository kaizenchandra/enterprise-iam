create table users
(
    id            varchar(36) primary key,
    username      varchar(128) not null unique,
    password_hash varchar(100) not null,
    state         varchar(32)  not null check (state in
                                               ('PENDING_VERIFICATION', 'ACTIVE', 'LOCKED', 'SUSPENDED', 'DISABLED',
                                                'DELETED')),
    version       bigint       not null default 0,
    created_at    timestamptz  not null default current_timestamp
);
create table organizations
(
    id   varchar(36) primary key,
    name varchar(128) not null
);
create table organization_memberships
(
    user_id         varchar(36) references users (id),
    organization_id varchar(36) references organizations (id),
    primary key (user_id, organization_id)
);
create table roles
(
    id   varchar(36) primary key,
    name varchar(128) unique not null
);
create table role_permissions
(
    role_id    varchar(36) references roles (id),
    permission varchar(128),
    primary key (role_id, permission)
);
create table protected_resources
(
    id              varchar(128) primary key,
    organization_id varchar(36) not null references organizations (id)
);
create table user_role_assignments
(
    id              varchar(36) primary key,
    user_id         varchar(36) not null,
    organization_id varchar(36) not null,
    role_id         varchar(36) not null references roles (id),
    resource_id     varchar(128) references protected_resources (id),
    foreign key (user_id, organization_id) references organization_memberships (user_id, organization_id)
);
create index assignments_lookup on user_role_assignments (user_id, organization_id);
create table refresh_history
(
    token_hash       char(64) primary key,
    authorization_id varchar(100) not null,
    client_id        varchar(100) not null,
    created_at       timestamptz  not null default current_timestamp
);
create index refresh_history_family on refresh_history (authorization_id);
create table security_audit_events
(
    id         varchar(36) primary key,
    event_type varchar(64) not null,
    subject_id varchar(128),
    created_at timestamptz not null default current_timestamp
);
create index audit_time on security_audit_events (created_at);
