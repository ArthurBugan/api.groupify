create table if not exists link_statistics
(
    id serial primary key,
    link_id text not null,
    referer text,
    user_agent text,
    constraint fk_links
        foreign key (link_id)
            references links (id)
);

CREATE INDEX IF NOT EXISTS idx_link_statistics_link_id on link_statistics (link_id);