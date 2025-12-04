-- ============================================================
-- SentinelScore Schema 
-- LinkedIn: www.linkedin.com/in/alex-chicaiza-a61631196/
-- GitHub: @Cvndela
-- ============================================================

CREATE SCHEMA IF NOT EXISTS sentinelscore;
SET search_path TO sentinelscore;

-- ============================================================
--  					  USERS
-- ============================================================
CREATE TABLE users (
    user_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at         TIMESTAMP NOT NULL,
    kyc_risk_tier      TEXT CHECK (kyc_risk_tier IN ('low', 'medium', 'high')),
    country            TEXT,
    region             TEXT,
    age_bucket         TEXT,
    income_bucket      TEXT,
    account_status     TEXT CHECK (account_status IN ('active', 'locked', 'closed')) DEFAULT 'active'
);

-- ============================================================
-- 					    DEVICES
-- ============================================================
CREATE TABLE devices (
    device_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_fingerprint TEXT NOT NULL,
    device_type        TEXT,
    os                 TEXT,
    first_seen_at      TIMESTAMP,
    last_seen_at       TIMESTAMP
);

-- ============================================================
-- 				    	USER DEVICES 
-- ============================================================
CREATE TABLE user_devices (
    user_id        UUID REFERENCES users(user_id) ON DELETE CASCADE,
    device_id      UUID REFERENCES devices(device_id) ON DELETE CASCADE,
    first_seen_at  TIMESTAMP NOT NULL,
    last_seen_at   TIMESTAMP NOT NULL,
    is_primary_device BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (user_id, device_id)
);

CREATE INDEX idx_user_devices_user ON user_devices(user_id);
CREATE INDEX idx_user_devices_device ON user_devices(device_id);

-- ============================================================
-- 				   DEVICE ENRICHMENTS
-- ============================================================
CREATE TABLE device_enrichments (
    enrichment_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id          UUID REFERENCES devices(device_id) ON DELETE CASCADE,
    ip_address         TEXT,
    geo_country        TEXT,
    geo_region         TEXT,
    ip_risk_score      NUMERIC(5,3),
    proxy_vpn_tor_flag BOOLEAN DEFAULT FALSE,
    velocity_flag      BOOLEAN DEFAULT FALSE,
    device_risk_score  NUMERIC(5,3),
    snapshot_at        TIMESTAMP NOT NULL
);

CREATE INDEX idx_device_enrich_device ON device_enrichments(device_id);

-- ============================================================
-- 					  AUTH SESSIONS
-- ============================================================
CREATE TABLE auth_sessions (
    session_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID REFERENCES users(user_id) ON DELETE CASCADE,
    device_id             UUID REFERENCES devices(device_id),
    ip_address            TEXT,
    geo_country           TEXT,
    geo_region            TEXT,
    login_at              TIMESTAMP NOT NULL,
    logout_at             TIMESTAMP,
    was_new_device_login  BOOLEAN DEFAULT FALSE,
    was_geo_change        BOOLEAN DEFAULT FALSE,
    was_mfa_bypassed      BOOLEAN DEFAULT FALSE,
    password_reset_during_session BOOLEAN DEFAULT FALSE,
    device_risk_snapshot  NUMERIC(5,3),
    ip_risk_snapshot      NUMERIC(5,3),
    session_risk_level    NUMERIC(5,3)
);

CREATE INDEX idx_sessions_user ON auth_sessions(user_id, login_at);
CREATE INDEX idx_sessions_device ON auth_sessions(device_id);

-- ============================================================
-- 					   AUTH FAILURES
-- ============================================================
CREATE TABLE auth_failures (
    failure_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID REFERENCES users(user_id) ON DELETE CASCADE,
    device_id     UUID REFERENCES devices(device_id),
    ip_address    TEXT,
    failure_reason TEXT,
    failed_at     TIMESTAMP NOT NULL
);

CREATE INDEX idx_auth_fail_user ON auth_failures(user_id);

-- ============================================================
-- 					    MERCHANTS
-- ============================================================
CREATE TABLE merchants (
    merchant_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_name    TEXT,
    merchant_category TEXT,
    risk_segment     TEXT CHECK (risk_segment IN ('low', 'medium', 'high')),
    is_crypto        BOOLEAN DEFAULT FALSE,
    is_p2p_like      BOOLEAN DEFAULT FALSE,
    is_exchange      BOOLEAN DEFAULT FALSE,
    created_at       TIMESTAMP NOT NULL
);

-- ============================================================
-- 				      P2P RECIPIENTS
-- ============================================================
CREATE TABLE p2p_recipients (
    sender_user_id     UUID REFERENCES users(user_id) ON DELETE CASCADE,
    recipient_user_id  UUID REFERENCES users(user_id) ON DELETE CASCADE,
    first_interaction_at TIMESTAMP NOT NULL,
    last_interaction_at  TIMESTAMP NOT NULL,
    txn_count          INT DEFAULT 0,
    PRIMARY KEY (sender_user_id, recipient_user_id)
);

CREATE INDEX idx_p2p_sender ON p2p_recipients(sender_user_id, recipient_user_id);

-- ============================================================
-- 			           FRAUD EVENTS
-- ============================================================
CREATE TABLE fraud_events (
    scenario_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    primary_user_id       UUID REFERENCES users(user_id) ON DELETE CASCADE,
    fraud_type            TEXT,
    scenario_version      TEXT,
    risk_entry_point      TEXT,
    behavior_change_notes TEXT,
    pattern_complexity_score NUMERIC(5,3),
    injected_at           TIMESTAMP NOT NULL,
    started_at            TIMESTAMP,
    ended_at              TIMESTAMP
);

CREATE INDEX idx_fraud_events_user ON fraud_events(primary_user_id);

-- ============================================================
-- 					  TRANSACTIONS
-- ============================================================
CREATE TABLE transactions (
    txn_id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  UUID REFERENCES users(user_id) ON DELETE CASCADE,
    device_id                UUID REFERENCES devices(device_id),
    merchant_id              UUID REFERENCES merchants(merchant_id),
    recipient_user_id        UUID REFERENCES users(user_id),
    session_id               UUID REFERENCES auth_sessions(session_id),
    device_enrichment_id     UUID REFERENCES device_enrichments(enrichment_id),
    created_at               TIMESTAMP NOT NULL,
    amount                   NUMERIC(12,2) NOT NULL,
    currency                 TEXT,
    txn_type                 TEXT,
    channel                  TEXT,
    status                   TEXT,
    label_is_fraud           BOOLEAN DEFAULT FALSE,
    scenario_id              UUID REFERENCES fraud_events(scenario_id),
    is_new_device_for_user        BOOLEAN,
    is_first_time_recipient       BOOLEAN,
    amount_vs_user_avg_multiplier NUMERIC(10,4),
    velocity_1h                   INT,
    minutes_since_session_start   INT,

    -- XOR constraint for merchants
    CONSTRAINT merchant_xor_recipient CHECK (
        (merchant_id IS NOT NULL AND recipient_user_id IS NULL)
        OR
        (merchant_id IS NULL AND recipient_user_id IS NOT NULL)
    )
);

CREATE INDEX idx_txn_user ON transactions(user_id, created_at);
CREATE INDEX idx_txn_device ON transactions(device_id, created_at);
CREATE INDEX idx_txn_merchant ON transactions(merchant_id);
CREATE INDEX idx_txn_recipient ON transactions(recipient_user_id);
CREATE INDEX idx_txn_scenario ON transactions(scenario_id);

-- ============================================================
-- 						RULE_HITS
-- ============================================================
CREATE TABLE rule_hits (
    rule_hit_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    txn_id         UUID REFERENCES transactions(txn_id) ON DELETE CASCADE,
    user_id        UUID REFERENCES users(user_id),
    rule_name      TEXT NOT NULL,
    severity       TEXT CHECK (severity IN ('low', 'medium', 'high')),
    signal_values  JSONB,
    created_at     TIMESTAMP NOT NULL
);

CREATE INDEX idx_rule_hits_txn ON rule_hits(txn_id);

-- ============================================================
-- 						 DECISIONS
-- ============================================================
CREATE TABLE decisions (
    decision_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    txn_id        UUID REFERENCES transactions(txn_id) ON DELETE CASCADE,
    user_id       UUID REFERENCES users(user_id),
    decision      TEXT CHECK (decision IN ('approve', 'review', 'decline', 'critical')),
    risk_score    NUMERIC(8,2),
    reason_codes  JSONB,
    created_at    TIMESTAMP NOT NULL
);

CREATE INDEX idx_decisions_txn ON decisions(txn_id);

-- ============================================================
-- 						USER BASELINES
-- ============================================================
CREATE TABLE IF NOT EXISTS user_baselines (
    user_id                     UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    avg_amount_30d              NUMERIC(12,2),
    median_amount_30d           NUMERIC(12,2),
    stddev_amount_30d           NUMERIC(12,2),
    avg_velocity_1h_30d         NUMERIC(10,4),
    avg_txns_per_day_30d        NUMERIC(10,4),
    primary_device_id           UUID REFERENCES devices(device_id),
    device_count                INT,
    trusted_recipients          JSONB,     
    top_recipients              JSONB,     
    typical_txn_hours           INT[],    
    typical_txn_days            INT[],     
    expected_session_duration_avg NUMERIC(10,4),
    baseline_generated_at       TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_baselines_user
    ON user_baselines (user_id);
