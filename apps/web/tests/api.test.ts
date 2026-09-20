import { afterEach, describe, expect, it, vi } from "vitest";
import { request } from "../src/lib/api";

describe("api client", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("returns the API envelope", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ data: { id: "1" } }), { status: 200, headers: { "content-type": "application/json" } })));
    const result = await request<{ data: { id: string } }>("/test");
    expect(result.data.id).toBe("1");
  });

  it("maps structured API errors", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: { code: "INSUFFICIENT_STOCK", message: "库存不足", fieldErrors: {} } }), { status: 409, headers: { "content-type": "application/json" } })));
    await expect(request("/consumptions", { method: "POST", body: {} })).rejects.toMatchObject({
      status: 409,
      code: "INSUFFICIENT_STOCK",
      message: "库存不足"
    });
  });

  it("retries once after a sliding refresh when the session idled out", async () => {
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        calls.push(url);
        if (url.endsWith("/auth/refresh")) {
          return new Response(null, { status: 204 });
        }
        if (calls.filter((entry) => entry.endsWith("/materials")).length === 1) {
          return new Response(JSON.stringify({ error: { code: "SESSION_EXPIRED", message: "登录已失效" } }), {
            status: 401,
            headers: { "content-type": "application/json" }
          });
        }
        return new Response(JSON.stringify({ data: { id: "2" } }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      })
    );
    const result = await request<{ data: { id: string } }>("/materials");
    expect(result.data.id).toBe("2");
    expect(calls.filter((entry) => entry.endsWith("/auth/refresh"))).toHaveLength(1);
  });

  it("does not retry a hard revocation and surfaces the error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: { code: "SESSION_REVOKED", message: "会话已退出" } }), {
        status: 401,
        headers: { "content-type": "application/json" }
      }))
    );
    await expect(request("/materials")).rejects.toMatchObject({ status: 401, code: "SESSION_REVOKED" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
