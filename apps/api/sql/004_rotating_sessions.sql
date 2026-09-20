-- Sliding sessions with an absolute deadline and rotating refresh tokens.
-- One session_families row per login; session_tokens holds the rotation chain
-- (the current token plus the immediately previous one, used for reuse detection).

CREATE TABLE session_families (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_refreshed_at timestamptz NOT NULL DEFAULT now(),
  absolute_expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX session_families_user_idx ON session_families(user_id);
CREATE INDEX session_families_absolute_expiry_idx ON session_families(absolute_expires_at);

CREATE TABLE session_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  family_id uuid NOT NULL REFERENCES session_families(id) ON DELETE CASCADE,
  token_hash char(64) NOT NULL UNIQUE,
  previous_token_hash char(64) UNIQUE,
  previous_rotated_at timestamptz,
  idle_expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX session_tokens_family_idx ON session_tokens(family_id);
CREATE INDEX session_tokens_idle_expiry_idx ON session_tokens(idle_expires_at);

-- Preserve any currently valid login from the single-table sessions model:
-- one family per live session, mapped explicitly so multiple sessions of the
-- same user do not cross-link, seeded with the existing token as its current token.
CREATE TEMP TABLE migrated_sessions ON COMMIT DROP AS
SELECT id AS old_session_id, user_id, token_hash, expires_at, created_at
  FROM sessions
 WHERE revoked_at IS NULL
   AND expires_at > now();

CREATE TEMP TABLE session_family_map ON COMMIT DROP AS
SELECT old_session_id, user_id, created_at, gen_random_uuid() AS family_id
  FROM migrated_sessions;

INSERT INTO session_families (id, user_id, created_at, last_refreshed_at, absolute_expires_at)
SELECT m.family_id,
       m.user_id,
       m.created_at,
       now(),
       m.created_at + interval '30 days'
  FROM session_family_map m;

INSERT INTO session_tokens (family_id, token_hash, idle_expires_at, created_at)
SELECT m.family_id, s.token_hash, s.expires_at, s.created_at
  FROM migrated_sessions s
  JOIN session_family_map m ON m.old_session_id = s.old_session_id;

DROP TABLE sessions;
