-- Add up migration script here
create table if not exists crunchyroll_channels
(
    id text not null primary key,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    name text not null,
    thumbnail text not null
);
