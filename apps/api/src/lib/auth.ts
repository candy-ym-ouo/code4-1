import { createHmac, randomBytes } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import { hash, verify, Algorithm } from "@node-rs/argon2";
import { pool, withTransaction, type DbClient } from "./db.js";
import { AppError } from "./errors.js";
import { config } from "../config.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const SESSION_IDLE_MS = config.SESSION_IDLE_DAYS * DAY_MS;
const SESSION_ABSOLUTE_MS = config.SESSION_ABSOLUTE_DAYS * DAY_MS;

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

type SessionRow = {
  familyId: string;
  userId: string;
  displayName: string;
  revokedAt: Date | null;
  absoluteExpiresAt: Date;
  lastRefreshedAt: Date;
  currentTokenHash: string;
  previousTokenHash: string | null;
  previousRotatedAt: Date | null;
  idleExpiresAt: Date;
};

const SESSION_SELECT_COLUMNS = `
  f.id AS "familyId",
  f.user_id AS "userId",
  u.display_name AS "displayName",
  f.revoked_at AS "revokedAt",
  f.absolute_expires_at AS "absoluteExpiresAt",
  f.last_refreshed_at AS "lastRefreshedAt",
  t.token_hash AS "currentTokenHash",
  t.previous_token_hash AS "previousTokenHash",
  t.previous_rotated_at AS "previousRotatedAt",
  t.idle_expires_at AS "idleExpiresAt"`;

async function findSessionRow(
  tokenHash: string,
  executor: QueryExecutor,
  lockForWrite = false
): Promise<SessionRow | null> {
  // The row lock must cover the row being mutated (session_tokens): locking
  // only the family serializes nothing between two refreshes, since each would
  // read and overwrite the same token row under its own MVCC snapshot. Locking
  // both rows, in the same fixed order everywhere, also prevents logout/password
  // revocation from interleaving with a refresh.
  const result = await executor.query<SessionRow>(
    `SELECT ${SESSION_SELECT_COLUMNS}
       FROM session_tokens t
       JOIN session_families f ON f.id = t.family_id
       JOIN users u ON u.id = f.user_id
      WHERE t.token_hash = $1 OR t.previous_token_hash = $1
      ${lockForWrite ? "FOR UPDATE OF t, f" : ""}`,
    [tokenHash]
  );
  // token_hash and previous_token_hash are each globally unique; at most one row matches.
  return result.rows[0] ?? null;
}

export async function createSession(
  userId: string,
  executor: QueryExecutor = pool
): Promise<{ token: string; idleExpiresAt: Date; absoluteExpiresAt: Date }> {
  const token = randomBytes(32).toString("base64url");
  const now = Date.now();
  const idleExpiresAt = new Date(now + SESSION_IDLE_MS);
  const absoluteExpiresAt = new Date(now + SESSION_ABSOLUTE_MS);
  const family = await executor.query<{ id: string }>(
    `INSERT INTO session_families(user_id, absolute_expires_at)
     VALUES ($1, $2)
     RETURNING id`,
    [userId, absoluteExpiresAt]
  );
  const familyId = family.rows[0]?.id;
  if (!familyId) {
    throw new Error("session family creation returned no id");
  }
  await executor.query(
    `INSERT INTO session_tokens(family_id, token_hash, idle_expires_at)
     VALUES ($1, $2, $3)`,
    [familyId, hashSessionToken(token), idleExpiresAt]
  );
  return { token, idleExpiresAt, absoluteExpiresAt };
}

export function setSessionCookie(reply: FastifyReply, token: string, idleExpiresAt: Date, secure: boolean): void {
  reply.setCookie("handcraft_session", token, {
    path: "/",
    httpOnly: true,
    sameSite: "lax",
    secure,
    expires: idleExpiresAt
  });
}

export function clearSessionCookie(reply: FastifyReply): void {
  reply.clearCookie("handcraft_session", { path: "/" });
}

function assertFamilyLive(row: SessionRow): void {
  if (row.revokedAt) {
    throw new AppError(401, "SESSION_REVOKED", "会话已退出，请重新登录");
  }
  if (row.absoluteExpiresAt.getTime() <= Date.now()) {
    throw new AppError(401, "SESSION_ABSOLUTE_EXPIRED", "登录已达到最长有效时间，请重新登录");
  }
}

function isWithinRotationGrace(row: SessionRow): boolean {
  const rotatedAt = row.previousRotatedAt?.getTime() ?? 0;
  return rotatedAt + config.SESSION_ROTATION_GRACE_SECONDS * 1000 > Date.now();
}

// A rotated token replayed outside the short grace window is evidence of a
// stolen credential: revoke the entire family, including the current token.
async function revokeFamily(familyId: string, executor: QueryExecutor = pool): Promise<void> {
  await executor.query(
    "UPDATE session_families SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    [familyId]
  );
}

// Sliding the idle deadline does not rotate the token, so concurrent requests
// are harmless: every request simply pushes the same deadline forward, capped
// by the family's absolute deadline.
async function slideIdleDeadline(row: SessionRow): Promise<void> {
  await pool.query(
    `UPDATE session_tokens
        SET idle_expires_at = LEAST($2::timestamptz, $3::timestamptz)
      WHERE token_hash = $1
        AND idle_expires_at < $2::timestamptz
        AND $3::timestamptz > now()`,
    [row.currentTokenHash, new Date(Date.now() + SESSION_IDLE_MS), row.absoluteExpiresAt]
  );
}

export async function authenticate(request: FastifyRequest): Promise<void> {
  const token = request.cookies.handcraft_session;
  if (!token) {
    throw new AppError(401, "UNAUTHENTICATED", "请先登录");
  }

  const tokenHash = hashSessionToken(token);
  const row = await findSessionRow(tokenHash, pool);
  if (!row) {
    throw new AppError(401, "SESSION_EXPIRED", "登录已失效，请重新登录");
  }

  assertFamilyLive(row);

  if (row.currentTokenHash !== tokenHash) {
    // The presented token was already rotated. Inside the grace window this is
    // just concurrent traffic at rotation time: report a plain idle expiry so
    // the client retries transparently with the cookie it now holds. Outside
    // the window the credential was replayed, so burn the whole family.
    if (!isWithinRotationGrace(row)) {
      await revokeFamily(row.familyId);
      throw new AppError(401, "SESSION_REUSE_DETECTED", "登录凭证已失效，请重新登录");
    }
    throw new AppError(401, "SESSION_EXPIRED", "登录已失效，请重新登录");
  }

  if (row.idleExpiresAt.getTime() <= Date.now()) {
    throw new AppError(401, "SESSION_EXPIRED", "登录已失效，请重新登录");
  }

  (request as AuthenticatedRequest).authUser = {
    id: row.userId,
    displayName: row.displayName
  };

  // Slide the idle deadline once the current token has consumed at least half
  // of its idle lifetime, so active users are never cut off mid-work.
  const tokenAge = Date.now() - row.lastRefreshedAt.getTime();
  if (tokenAge >= SESSION_IDLE_MS / 2) {
    await slideIdleDeadline(row);
  }
}

// Rotates the presented token. The whole rotation is serialized per family by
// row-locking both the token row and the family row (FOR UPDATE OF t, f), in the
// same fixed order used by logout. A logout or password change that revokes the
// family therefore cannot interleave with a refresh: a refresh starting after
// the revocation sees the revoked family and fails, and one that started first
// commits its new token before the revocation lands. A logged-out session can
// never be brought back by an in-flight refresh.
export async function refreshSession(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const token = request.cookies.handcraft_session;
  if (!token) {
    throw new AppError(401, "UNAUTHENTICATED", "请先登录");
  }

  const tokenHash = hashSessionToken(token);

  const result = await withTransaction(async (client) => {
    const row = await findSessionRow(tokenHash, client, true);
    if (!row) {
      throw new AppError(401, "SESSION_EXPIRED", "登录已失效，请重新登录");
    }

    assertFamilyLive(row);

    const presentedCurrent = row.currentTokenHash === tokenHash;
    if (!presentedCurrent) {
      if (isWithinRotationGrace(row)) {
        // Another concurrent refresh already rotated this token. Do not rotate
        // again and do not treat it as reuse; the winner already set a fresh
        // cookie (the browser shares one cookie jar across tabs).
        return { concurrent: true as const };
      }
      // An old token presented long after it was rotated was replayed (stolen
      // credential): revoke the whole family, including the newer token.
      await revokeFamily(row.familyId, client);
      throw new AppError(401, "SESSION_REUSE_DETECTED", "登录凭证已失效，请重新登录");
    }

    // Refresh is the one operation allowed even after the idle window lapsed:
    // it issues a fresh token, restarting the sliding window. The only hard
    // stop here is the absolute deadline (checked above) or revocation.
    const nextToken = randomBytes(32).toString("base64url");
    const now = new Date();
    const nextIdleExpiresAt = new Date(Math.min(Date.now() + SESSION_IDLE_MS, row.absoluteExpiresAt.getTime()));

    await client.query(
      `UPDATE session_tokens
          SET previous_token_hash = token_hash,
              previous_rotated_at = $2,
              token_hash = $3,
              idle_expires_at = $4
        WHERE token_hash = $1`,
      [tokenHash, now, hashSessionToken(nextToken), nextIdleExpiresAt]
    );
    await client.query(
      "UPDATE session_families SET last_refreshed_at = $2 WHERE id = $1",
      [row.familyId, now]
    );

    return { concurrent: false as const, nextToken, nextIdleExpiresAt };
  });

  if (result.concurrent) {
    // The winner already rotated the token and set the fresh cookie; signal
    // the caller that a concurrent rotation happened rather than succeeding
    // silently (which would make duplicate concurrent rotations indistinguishable).
    return reply.status(409).send({
      error: { code: "SESSION_CONCURRENT_REFRESH", message: "会话已在其他请求中刷新", fieldErrors: {} }
    });
  }
  setSessionCookie(reply, result.nextToken, result.nextIdleExpiresAt, config.COOKIE_SECURE);
  return reply.status(204).send();
}

export async function revokeSession(request: FastifyRequest): Promise<void> {
  const token = request.cookies.handcraft_session;
  if (!token) return;

  const tokenHash = hashSessionToken(token);
  await withTransaction(async (client) => {
    // Lock the token and family rows in the same order as refreshSession, so a
    // logout and a concurrent refresh cannot deadlock or interleave.
    const row = await findSessionRow(tokenHash, client, true);
    if (!row) return;
    await client.query(
      "UPDATE session_families SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
      [row.familyId]
    );
  });
}
