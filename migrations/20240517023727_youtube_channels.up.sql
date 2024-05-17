create table if not exists youtube_channels
(
    id text not null primary key,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    name text not null,
    thumbnail text not null,
    new_content boolean,
    channel_id text not null,
    user_id text not null REFERENCES users (id)
);

ALTER TABLE youtube_channels
ADD CONSTRAINT unique_channel_user
UNIQUE (channel_id, user_id);