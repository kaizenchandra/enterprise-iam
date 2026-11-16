-- Platform administration is independent of organization-scoped roles.
-- No existing identity is automatically promoted.
create table platform_administrators
(
    user_id    varchar(36) primary key references users (id),
    granted_at timestamptz not null default clock_timestamp()
);
