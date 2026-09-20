import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { refreshSession, recoverAfterUnauthorized } from "../src/lib/session";

function jsonResponse(status: number, body: unknown = {}) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: status === 204 ? {} : { "content-type": "application/json" }
  });
}

describe("session refresh", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));
  afterEach(() => vi.unstubAllGlobals());

  it("resolves true on a successful rotation", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(204));
    await expect(refreshSession()).resolves.toBe(true);
  });

  it("treats a concurrent 409 as success and never retries", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(409, { error: { code: "SESSION_CONCURRENT_REFRESH" } }));
    await expect(refreshSession()).resolves.toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("coalesces concurrent calls into a single rotation request", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(204));
    const [a, b, c] = await Promise.all([refreshSession(), refreshSession(), refreshSession()]);
    expect(a).toBe(true);
    expect(b).toBe(true);
    expect(c).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("returns false on hard 401s so callers force re-login", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(401, { error: { code: "SESSION_REVOKED" } }));
    await expect(refreshSession()).resolves.toBe(false);
  });

  it("does not attempt recovery for the refresh/login/setup endpoints", async () => {
    await expect(recoverAfterUnauthorized("/auth/refresh")).resolves.toBe(false);
    await expect(recoverAfterUnauthorized("/auth/login")).resolves.toBe(false);
    await expect(recoverAfterUnauthorized("/setup")).resolves.toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });
});
