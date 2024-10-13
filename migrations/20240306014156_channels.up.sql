create table if not exists channels
(
    id text not null primary key,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    group_id text not null references groups (id),
    name text not null,
    thumbnail text not null,
    new_content boolean,
    user_id text not null REFERENCES users (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_channels_id on groups (id);