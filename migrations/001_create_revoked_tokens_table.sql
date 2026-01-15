-- Migration: Create revoked_tokens table
-- Purpose: Support JWT token revocation for security
-- Date: 2026-01-15
-- Author: Jaafar Benabderrazak

-- Drop table if exists (for clean redeployment)
DROP TABLE IF EXISTS revoked_tokens CASCADE;

-- Create revoked_tokens table
CREATE TABLE revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,                    -- JWT ID (unique token identifier)
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- When the token was revoked
    revoked_by VARCHAR(100) NOT NULL,                -- Admin who revoked it
    reason TEXT,                                      -- Reason for revocation (e.g., "Security breach")
    expires_at TIMESTAMP NOT NULL                    -- When token would have expired (for cleanup)
);

-- Create indexes for efficient queries
CREATE INDEX idx_revoked_expires ON revoked_tokens(expires_at);
CREATE INDEX idx_revoked_by ON revoked_tokens(revoked_by);
CREATE INDEX idx_revoked_at ON revoked_tokens(revoked_at);

-- Add comments for documentation
COMMENT ON TABLE revoked_tokens IS 'Stores revoked JWT tokens to prevent their reuse';
COMMENT ON COLUMN revoked_tokens.jti IS 'JWT ID claim - unique identifier for the token';
COMMENT ON COLUMN revoked_tokens.revoked_at IS 'Timestamp when the token was revoked';
COMMENT ON COLUMN revoked_tokens.revoked_by IS 'Username or ID of the admin who revoked the token';
COMMENT ON COLUMN revoked_tokens.reason IS 'Human-readable reason for revocation';
COMMENT ON COLUMN revoked_tokens.expires_at IS 'Original expiration time of the token for automatic cleanup';

-- Sample cleanup query (to be run as a scheduled job)
-- DELETE FROM revoked_tokens WHERE expires_at < NOW() - INTERVAL '7 days';

