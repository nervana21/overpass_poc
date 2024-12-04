-- Add migration script here    

CREATE TABLE IF NOT EXISTS channels (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner VARCHAR(255) NOT NULL,
    balance BIGINT NOT NULL,
    nonce BIGINT NOT NULL,
    state BYTEA NOT NULL,
    merkle_root BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS htlcs (
    id SERIAL PRIMARY KEY,
    channel_id INTEGER NOT NULL,
    hash_lock BYTEA NOT NULL,
    time_lock BIGINT NOT NULL,
    amount BIGINT NOT NULL,
    sender BYTEA NOT NULL,
    recipient BYTEA NOT NULL,
    state VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS payments (
    id SERIAL PRIMARY KEY,
    channel_id INTEGER NOT NULL,
    participant_1 BYTEA NOT NULL,
    participant_2 BYTEA NOT NULL,
    balance_1 BIGINT NOT NULL,
    balance_2 BIGINT NOT NULL,
    nonce BIGINT NOT NULL,
    state BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS wallets (
    id SERIAL PRIMARY KEY,
    channel_id INTEGER NOT NULL,
    owner BYTEA NOT NULL,
    balance BIGINT NOT NULL,
    nonce BIGINT NOT NULL,
    state BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    channel_id INTEGER NOT NULL,
    sender BYTEA NOT NULL,
    recipient BYTEA NOT NULL,
    amount BIGINT NOT NULL,
    nonce BIGINT NOT NULL,
    state BYTEA NOT NULL
);