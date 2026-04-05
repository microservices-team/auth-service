-- ── V3: API Keys, OAuth providers, Account lockout, Remember Me ──

-- Account lockout columns on users
ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS failed_attempts  INT       DEFAULT 0,
    ADD COLUMN IF NOT EXISTS locked_until     TIMESTAMP,
    ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP DEFAULT NOW();

-- API Keys table
CREATE TABLE IF NOT EXISTS auth.api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash    VARCHAR(255) UNIQUE NOT NULL,
    key_prefix  VARCHAR(8),
    name        VARCHAR(100) NOT NULL,
    user_id     UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    active      BOOLEAN DEFAULT true,
    expires_at  TIMESTAMP,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON auth.api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id  ON auth.api_keys(user_id);

-- OAuth providers table
CREATE TABLE IF NOT EXISTS auth.oauth_providers (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    provider         VARCHAR(30) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email   VARCHAR(255),
    created_at       TIMESTAMP DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_provider ON auth.oauth_providers(provider, provider_user_id);

-- Remember Me tokens (Spring Security persistent token)
CREATE TABLE IF NOT EXISTS auth.persistent_logins (
    username  VARCHAR(64)  NOT NULL,
    series    VARCHAR(64)  PRIMARY KEY,
    token     VARCHAR(64)  NOT NULL,
    last_used TIMESTAMP    NOT NULL
);
