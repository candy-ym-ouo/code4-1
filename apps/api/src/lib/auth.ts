import { createHmac, randomBytes } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import { hash, verify, Algorithm } from "@node-rs/argon2";
import { pool, type DbClient } from "./db.js";
import { AppError } from "./errors.js";
import { config } from "../config.js";

const DAY_MS = 24 * 60 * 60 * 1000;
// A session only slides once at least half of its idle lifetime has been consumed.
const SLIDING_THRESHOLD_RATIO = 0.5;

export type AuthUser = {
  id: string;
  displayName: string;
};

export type AuthenticatedRequest = FastifyRequest & { authUser: AuthUser };

export function hashSessionToken(token: string): string {
  return createHmac("sha256", config.SESSION_SECRET).update(token).digest("hex");
}

export async function hashPassword(password: string): Promise<string> {
  return hash(password, { algorithm: Algorithm.Argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
}

export async function verifyPassword(passwordHash: string, password: string): Promise<boolean> {
  try {
    return await verify(passwordHash, password);
  } catch {
    return false;
  }
}

type QueryExecutor = Pick<DbClient, "query">;

export async function createSession(
  userId: string,
  executor: QueryExecutor = pool
): Promise<{ token: string; expiresAt: Date; absoluteExpiresAt: Date }> {
  const token = randomBytes(32).toString("base64url");
  const now = Date.now();
  const expiresAt = new Date(now + config.SESSION_IDLE_DAYS * DAY_MS);
  // Fixed at creation and never extended: activity can slide the idle deadline,
  // but no session may live longer than SESSION_ABSOLUTE_DAYS.
  const absoluteExpiresAt = new Date(now + config.SESSION_ABSOLUTE_DAYS * DAY_MS);
  await executor.query(
    `INSERT INTO sessions(user_id, token_hash, expires_at, absolute_expires_at)
     VALUES ($1, $2, $3, $4)`,
    [userId, hashSessionToken(token), expiresAt, absoluteExpiresAt]
  );
  return { token, expiresAt, absoluteExpiresAt };
}

export function setSessionCookie(reply: FastifyReply, token: string, expiresAt: Date, secure: boolean): void {
  reply.setCookie("handcraft_session", token, {
    path: "/",
    httpOnly: true,
    sameSite: "lax",
    secure,
    expires: expiresAt
  });
}

export async function authenticate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const token = request.cookies.handcraft_session;
  if (!token) {
    throw new AppError(401, "UNAUTHENTICATED", "请先登录");
  }

  const now = Date.now();
  const slidingThreshold = new Date(now + config.SESSION_IDLE_DAYS * DAY_MS * SLIDING_THRESHOLD_RATIO);
  const idleDeadline = new Date(now + config.SESSION_IDLE_DAYS * DAY_MS);

  // Validation and sliding happen in one statement. The row is taken FOR UPDATE,
  // so a concurrent logout / password-change revoke is serialized against this
  // refresh: a revoked row never satisfies the WHERE clause and can never be
  // extended, even when requests race. Revocation is also double-checked via the
  // users.sessions_revoked_at watermark (sessions must be newer than it).
  const result = await pool.query<{
    user_id: string;
    display_name: string;
    expires_at: Date;
    renewed: boolean;
  }>(
    `WITH locked AS (
        SELECT s.id, s.expires_at, s.absolute_expires_at, u.id AS user_id, u.display_name
          FROM sessions s
          JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1
           AND s.revoked_at IS NULL
           AND s.expires_at > now()
           AND s.absolute_expires_at > now()
           AND s.created_at >= u.sessions_revoked_at
         FOR UPDATE OF s
      ),
      slid AS (
        UPDATE sessions
           SET expires_at = LEAST($3, locked.absolute_expires_at)
          FROM locked
         WHERE sessions.id = locked.id
           AND locked.expires_at <= $2
         RETURNING sessions.id, sessions.expires_at
      )
     SELECT locked.user_id, locked.display_name,
            COALESCE(slid.expires_at, locked.expires_at) AS expires_at,
            (slid.id IS NOT NULL) AS renewed
       FROM locked
       LEFT JOIN slid ON slid.id = locked.id`,
    [hashSessionToken(token), slidingThreshold, idleDeadline]
  );

  const session = result.rows[0];
  if (!session) {
    throw new AppError(401, "SESSION_EXPIRED", "登录已失效，请重新登录");
  }

  (request as AuthenticatedRequest).authUser = {
    id: session.user_id,
    displayName: session.display_name
  };

  // Only re-issue the cookie when the idle deadline actually moved.
  if (session.renewed) {
    setSessionCookie(reply, token, session.expires_at, config.COOKIE_SECURE);
  }
}

export async function revokeSession(request: FastifyRequest): Promise<void> {
  const token = request.cookies.handcraft_session;
  if (token) {
    await pool.query("UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL", [hashSessionToken(token)]);
  }
}
