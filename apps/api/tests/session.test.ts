import { beforeEach, describe, expect, it, vi } from "vitest";

const queryMock = vi.fn();

vi.mock("pg", () => {
  class FakePool {
    public max: number;
    constructor(options?: { max?: number }) {
      this.max = options?.max ?? 10;
    }
    query = queryMock;
    on(): void {}
  }
  return { default: { Pool: FakePool } };
});

const { authenticate } = await import("../src/lib/auth.js");
const { config } = await import("../src/config.js");

function requestWith(token: string | undefined) {
  return { cookies: token ? { handcraft_session: token } : {} } as never;
}

function replyMock() {
  const headers: Record<string, string> = {};
  return {
    headers,
    setCookie(name: string, value: string, options: { expires?: Date }) {
      headers["set-cookie"] = `${name}=${value}; Expires=${options.expires?.toUTCString()}`;
    }
  } as never;
}

const DAY_MS = 24 * 60 * 60 * 1000;

describe("authenticate sliding sessions", () => {
  beforeEach(() => {
    queryMock.mockReset();
  });

  it("rejects requests without a session cookie without touching the database", async () => {
    await expect(authenticate(requestWith(undefined), replyMock())).rejects.toMatchObject({
      statusCode: 401,
      code: "UNAUTHENTICATED"
    });
    expect(queryMock).not.toHaveBeenCalled();
  });

  it("rejects when the atomic session lookup finds no live row", async () => {
    queryMock.mockResolvedValueOnce({ rows: [] });
    await expect(authenticate(requestWith("token"), replyMock())).rejects.toMatchObject({
      statusCode: 401,
      code: "SESSION_EXPIRED"
    });
  });

  it("bounds sliding by half the idle lifetime and never past the absolute deadline", async () => {
    queryMock.mockResolvedValueOnce({
      rows: [
        {
          user_id: "u1",
          display_name: "操作员",
          expires_at: new Date(),
          renewed: false
        }
      ]
    });

    const reply = replyMock();
    await authenticate(requestWith("token"), reply);

    const [, params] = queryMock.mock.calls[0];
    const threshold = params[1].getTime();
    const idleDeadline = params[2].getTime();
    const now = Date.now();

    // $2: only slide when current expires_at is within half the idle window.
    expect(threshold).toBeGreaterThan(now + config.SESSION_IDLE_DAYS * DAY_MS * 0.49);
    expect(threshold).toBeLessThan(now + config.SESSION_IDLE_DAYS * DAY_MS * 0.51);
    // $3: candidate sliding deadline is one full idle window out; the SQL caps it
    // at LEAST($3, sessions.absolute_expires_at).
    expect(idleDeadline).toBeGreaterThan(now + config.SESSION_IDLE_DAYS * DAY_MS - 5000);
  });

  it("re-issues the cookie only when the row was actually renewed", async () => {
    queryMock.mockResolvedValueOnce({
      rows: [
        {
          user_id: "u1",
          display_name: "操作员",
          expires_at: new Date(Date.now() + 6 * DAY_MS),
          renewed: true
        }
      ]
    });
    const renewedReply = replyMock();
    await authenticate(requestWith("token"), renewedReply);
    expect((renewedReply as { headers: Record<string, string> }).headers["set-cookie"]).toContain("handcraft_session=token");

    queryMock.mockResolvedValueOnce({
      rows: [
        {
          user_id: "u1",
          display_name: "操作员",
          expires_at: new Date(Date.now() + 6 * DAY_MS),
          renewed: false
        }
      ]
    });
    const idleReply = replyMock();
    await authenticate(requestWith("token"), idleReply);
    expect((idleReply as { headers: Record<string, string> }).headers["set-cookie"]).toBeUndefined();
  });

  it("performs validation and sliding in a single row-locking statement", async () => {
    queryMock.mockResolvedValueOnce({ rows: [] });
    await authenticate(requestWith("token"), replyMock()).catch(() => undefined);

    const [sql] = queryMock.mock.calls[0];
    expect(sql).toContain("FOR UPDATE OF s");
    expect(sql).toContain("s.revoked_at IS NULL");
    expect(sql).toContain("s.absolute_expires_at > now()");
    expect(sql).toContain("s.created_at >= u.sessions_revoked_at");
    expect(sql).toContain("LEAST($3, locked.absolute_expires_at)");
    // Revocation must be part of the same statement that performs the refresh.
    const statementCount = (sql.match(/UPDATE sessions/g) ?? []).length;
    expect(statementCount).toBe(1);
  });
});
