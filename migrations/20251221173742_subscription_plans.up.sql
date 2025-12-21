-- Add up migration script here
CREATE TABLE subscription_plans (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    max_channels INTEGER NOT NULL DEFAULT 0,
    max_groups INTEGER NOT NULL DEFAULT 0,
    can_create_subgroups BOOLEAN NOT NULL DEFAULT FALSE,
    price_monthly NUMERIC(10,2) NOT NULL DEFAULT 0,
    price_yearly NUMERIC(10,2) NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO subscription_plans (name, max_channels, max_groups, can_create_subgroups, price_monthly, price_yearly) VALUES
('free', 5, 3, FALSE, 0, 0),
('basic', 1000, 10, TRUE, 3.99, 39.9),
('pro', 999999, 99999, TRUE, 9.99, 99.9)
ON CONFLICT (name) DO NOTHING;