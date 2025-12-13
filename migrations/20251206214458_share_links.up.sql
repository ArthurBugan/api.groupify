CREATE TABLE share_links (
    id text not null primary key,
    group_id TEXT NOT NULL REFERENCES groups(id),
    link_code VARCHAR(255) NOT NULL UNIQUE,
    link_type VARCHAR(50) NOT NULL,
    permission VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
