create table if not exists groups
(
    id text not null primary key,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    name text not null,
    icon text not null,
    user_id text not null,
    constraint fk_links
        foreign key (user_id)
            references users (id)
);

CREATE UNIQUE INDEX idx_groups_users_id on users (id);