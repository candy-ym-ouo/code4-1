-- Sliding sessions with an absolute deadline, plus a per-user revocation watermark.
-- expires_at            : sliding (idle) deadline, extended by authenticated activity
-- absolute_expires_at   : hard deadline fixed at session creation, never extended
ALTER TABLE sessions
  ADD COLUMN absolute_expires_at timestamptz;

-- Existing rows keep their original fixed expiry: idle and absolute deadlines coincide.
UPDATE sessions SET absolute_expires_at = expires_at WHERE absolute_expires_at IS NULL;

ALTER TABLE sessions
  ALTER COLUMN absolute_expires_at SET NOT NULL;

-- Watermark bumped on password change; every session created before it is invalid even
-- without a matching revoked_at row (defence in depth against token resurrection).
ALTER TABLE users
  ADD COLUMN sessions_revoked_at timestamptz NOT NULL DEFAULT 'epoch'::timestamptz;

CREATE INDEX sessions_user_revoked_idx ON sessions(user_id, revoked_at);
