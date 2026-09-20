const baseUrl = process.env.SMOKE_BASE_URL ?? "http://127.0.0.1:8080";
const configuredPassword = process.env.SMOKE_PASSWORD;
if (!configuredPassword) {
  throw new Error("SMOKE_PASSWORD is required");
}
let cookie = "";

async function callWithStatus(path, options = {}) {
  const headers = new Headers(options.headers);
  if (cookie) headers.set("cookie", cookie);
  if (options.body !== undefined && !(options.body instanceof FormData)) headers.set("content-type", "application/json");
  const response = await fetch(`${baseUrl}/api/v1${path}`, {
    ...options,
    headers,
    body: options.body instanceof FormData ? options.body : options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  const setCookie = response.headers.get("set-cookie");
  if (setCookie) cookie = setCookie.split(";")[0];
  const payload = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    throw new Error(`${options.method ?? "GET"} ${path} -> ${response.status} ${JSON.stringify(payload)}`);
  }
  return { status: response.status, data: payload };
}

async function call(path, options = {}) {
  return (await callWithStatus(path, options)).data;
}

// Like callWithStatus but sends an explicit Cookie header, so tests can replay
// old tokens after the global cookie has already been rotated.
async function callWithCookie(path, explicitCookie, options = {}) {
  const headers = new Headers(options.headers);
  if (explicitCookie) headers.set("cookie", explicitCookie);
  if (options.body !== undefined) headers.set("content-type", "application/json");
  const response = await fetch(`${baseUrl}/api/v1${path}`, {
    ...options,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  const setCookie = response.headers.get("set-cookie");
  const payload = response.status === 204 ? null : await response.json().catch(() => null);
  return { status: response.status, setCookie: setCookie ? setCookie.split(";")[0] : null, data: payload };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const status = await call("/setup/status");
if (!status.data.initialized) {
  await call("/setup", { method: "POST", body: { displayName: "Smoke Test Operator", password: configuredPassword } });
  console.log("Initialized a new empty workspace.");
} else {
  await call("/auth/login", { method: "POST", body: { password: configuredPassword } });
}

// --- Session lifecycle: sliding refresh, rotation, logout, password change ---
const { execFileSync } = await import("node:child_process");
const { fileURLToPath } = await import("node:url");
const { dirname, resolve } = await import("node:path");
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const execSql = (sql) =>
  execFileSync(process.execPath, [resolve(repoRoot, "apps/api/scripts/exec-sql.mjs"), sql], {
    stdio: ["ignore", "ignore", "pipe"],
    env: { ...process.env }
  });

const originalCookie = cookie;
assert(originalCookie, "login did not set a session cookie");

// Sliding refresh rotates the token and issues a new cookie.
const firstRefresh = await callWithStatus("/auth/refresh", { method: "POST" });
assert(firstRefresh.status === 204, "session refresh did not return 204");
assert(cookie !== originalCookie, "sliding refresh did not rotate the session token");
const rotatedCookie = cookie;

// The immediately previous token is rejected for authentication; rotation is
// one-way and old tokens are never valid credentials again.
const meWithOld = await callWithCookie("/auth/me", originalCookie);
assert(meWithOld.status === 401, "previous token still authenticated after rotation");

// Concurrent refreshes racing with the same cookie: at most one rotates and
// wins (204); the other loses the row lock race and is told a concurrent
// rotation happened (409) — it must NOT rotate again or kill the family.
const [concurrentA, concurrentB] = await Promise.all([
  callWithCookie("/auth/refresh", rotatedCookie, { method: "POST" }),
  callWithCookie("/auth/refresh", rotatedCookie, { method: "POST" })
]);
const concurrentStatuses = [concurrentA.status, concurrentB.status].sort();
assert(concurrentStatuses[0] === 204 && concurrentStatuses[1] === 409,
  `concurrent refresh expected 204+409, got ${concurrentStatuses.join(",")}`);
const winningCookie = concurrentA.status === 204 ? concurrentA.setCookie : concurrentB.setCookie;
assert(winningCookie && winningCookie !== rotatedCookie, "winning concurrent refresh did not issue a new token");
{
  const meWinner = await callWithCookie("/auth/me", winningCookie);
  assert(meWinner.status === 200, "session did not survive concurrent refresh");
}

// After logout, neither the token used to log out nor a concurrent refresh
// winner can resurrect the session.
const [logoutResult, racedLogoutRefresh] = await Promise.all([
  callWithCookie("/auth/logout", winningCookie, { method: "POST" }),
  callWithCookie("/auth/refresh", winningCookie, { method: "POST" })
]);
assert(logoutResult.status === 204, "logout did not return 204");
assert(racedLogoutRefresh.status === 401, "concurrent refresh resurrected a logged-out session");
{
  const meAfterLogout = await callWithCookie("/auth/me", winningCookie);
  assert(meAfterLogout.status === 401, "old token still authenticated after logout");
}

// Idle expiry: once the sliding window lapses the token is rejected, but a
// successful refresh rotates it back into a valid session.
await call("/auth/login", { method: "POST", body: { password: configuredPassword } });
const idleCookie = cookie;
execSql(`UPDATE session_tokens
            SET idle_expires_at = now() - interval '1 minute'
          WHERE token_hash IS NOT NULL
            AND family_id = (SELECT id FROM session_families
                              WHERE user_id = (SELECT id FROM users LIMIT 1)
                                AND revoked_at IS NULL
                              ORDER BY created_at DESC LIMIT 1)`);
{
  const meIdle = await callWithCookie("/auth/me", idleCookie);
  assert(meIdle.status === 401, "idle-expired token was still accepted");
  const refreshIdle = await callWithCookie("/auth/refresh", idleCookie, { method: "POST" });
  assert(refreshIdle.status === 204, "refresh failed while absolute deadline was still in the future");
  const renewedCookie = refreshIdle.setCookie;
  assert(renewedCookie, "idle recovery refresh did not set a cookie");
  const meRenewed = await callWithCookie("/auth/me", renewedCookie);
  assert(meRenewed.status === 200, "sliding refresh did not restore the session");
  cookie = renewedCookie;
}

// Absolute deadline: even a fresh-looking idle token cannot be refreshed past
// the family's absolute expiry; re-login is mandatory.
// expire the family that owns the most recently created token (the one above)
execSql(`UPDATE session_families
            SET absolute_expires_at = now() - interval '1 minute'
          WHERE id = (SELECT family_id FROM session_tokens ORDER BY created_at DESC LIMIT 1)`);
{
  const refreshAbsolute = await callWithCookie("/auth/refresh", cookie, { method: "POST" });
  assert(refreshAbsolute.status === 401, "refresh succeeded past the absolute deadline");
  const meAbsolute = await callWithCookie("/auth/me", cookie);
  assert(meAbsolute.status === 401, "old token still authenticated past the absolute deadline");
}

// Password change revokes every existing token immediately, including tokens
// captured before the change; the changed password is required to log in again.
const alternatePassword = "smoke-rotated-password-9";
await call("/auth/login", { method: "POST", body: { password: configuredPassword } });
const beforePasswordCookie = cookie;
await call("/auth/password", {
  method: "POST",
  body: { currentPassword: configuredPassword, newPassword: alternatePassword }
});
{
  const meOldPasswordSession = await callWithCookie("/auth/me", beforePasswordCookie);
  assert(meOldPasswordSession.status === 401, "old token survived the password change");
  const refreshAfterPassword = await callWithCookie("/auth/refresh", beforePasswordCookie, { method: "POST" });
  assert(refreshAfterPassword.status === 401, "refresh revived a session revoked by password change");
}
// Restore the configured password so repeat runs keep working.
await call("/auth/login", { method: "POST", body: { password: alternatePassword } });
await call("/auth/password", {
  method: "POST",
  body: { currentPassword: alternatePassword, newPassword: configuredPassword }
});
await call("/auth/login", { method: "POST", body: { password: configuredPassword } });
console.log("Session lifecycle checks passed.");

const suffix = Date.now().toString(36);
const source = await call("/sources", { method: "POST", body: { name: `Smoke Source ${suffix}`, type: "PURCHASED" } });
const material = await call("/materials", {
  method: "POST",
  body: {
    code: `SMOKE-${suffix}`,
    name: `Smoke Material ${suffix}`,
    craftTypes: ["GENERAL"],
    stockUnit: "g",
    lowStockThreshold: "100",
    defaultColorName: "Original",
    defaultColorHex: "#8B5A2B",
    tags: ["smoke"]
  }
});
const batchPayload = {
  materialId: material.data.id,
  batchCode: `B-${suffix}`,
  sourceId: source.data.id,
  receivedAt: new Date().toISOString().slice(0, 10),
  initialQuantity: "1",
  entryUnit: "kg"
};
const [batchResult, repeatedBatchResult] = await Promise.all([
  callWithStatus("/batches", {
    method: "POST",
    headers: { "idempotency-key": `smoke-batch-${suffix}` },
    body: batchPayload
  }),
  callWithStatus("/batches", {
    method: "POST",
    headers: { "idempotency-key": `smoke-batch-${suffix}` },
    body: batchPayload
  })
]);
assert([200, 201].includes(batchResult.status) && [200, 201].includes(repeatedBatchResult.status), "Concurrent batch idempotency returned an unexpected status");
const batch = batchResult.status === 201 ? batchResult.data.data : repeatedBatchResult.data.data;
const repeatedBatch = batchResult.status === 201 ? repeatedBatchResult.data.data : batchResult.data.data;
assert(repeatedBatch.id === batch.id, "Batch idempotency returned a different batch");
const project = await call("/projects", {
  method: "POST",
  body: { name: `Smoke Project ${suffix}`, craftType: "GENERAL", status: "PLANNED" }
});
const requirement = await call(`/projects/${project.data.id}/requirements`, {
  method: "POST",
  body: { materialId: material.data.id, requiredQuantity: "500", unit: "g", purpose: "Smoke verification" }
});
const consumptionPayload = {
  projectId: project.data.id,
  projectRequirementId: requirement.data.id,
  batchId: batch.id,
  usedQuantity: "450",
  wasteQuantity: "50",
  unit: "g",
  purpose: "Smoke verification"
};
const [consumptionResult, repeatedConsumptionResult] = await Promise.all([
  callWithStatus("/consumptions", {
    method: "POST",
    headers: { "idempotency-key": `smoke-consumption-${suffix}` },
    body: consumptionPayload
  }),
  callWithStatus("/consumptions", {
    method: "POST",
    headers: { "idempotency-key": `smoke-consumption-${suffix}` },
    body: consumptionPayload
  })
]);
assert([200, 201].includes(consumptionResult.status) && [200, 201].includes(repeatedConsumptionResult.status), "Concurrent consumption idempotency returned an unexpected status");
const consumption = consumptionResult.status === 201 ? consumptionResult.data.data : repeatedConsumptionResult.data.data;
const repeatedConsumption = consumptionResult.status === 201 ? repeatedConsumptionResult.data.data : consumptionResult.data.data;
assert(repeatedConsumption.id === consumption.id, "Consumption idempotency returned a different row");
assert(consumption.totalQuantity === "500.000000", "Consumption total is incorrect");

const latestOccurredAt = new Date();
await call("/color-changes", {
  method: "POST",
  body: {
    batchId: batch.id,
    projectId: project.data.id,
    changeType: "OTHER",
    afterColorName: "Smoke Brown",
    afterColorHex: "#6B2F1F",
    affectedQuantity: "450",
    unit: "g",
    occurredAt: latestOccurredAt.toISOString()
  }
});
const backdatedColor = await call("/color-changes", {
  method: "POST",
  body: {
    batchId: batch.id,
    projectId: project.data.id,
    changeType: "OTHER",
    afterColorName: "Backdated Blue",
    afterColorHex: "#0000FF",
    occurredAt: new Date(latestOccurredAt.getTime() - 60_000).toISOString()
  }
});
assert(backdatedColor.data.isCurrent === false, "Backdated color was treated as current");

const afterConsumption = await call(`/batches/${batch.id}`);
assert(afterConsumption.data.remainingQuantity === "500.000000", "Batch balance after consumption is incorrect");
assert(afterConsumption.data.currentColorName === "Smoke Brown", "Current color was not updated");
const projectAfterConsumption = await call(`/projects/${project.data.id}`);
assert(projectAfterConsumption.data.requirements[0].actualQuantity === "500.000000", "Project actual quantity is incorrect");
assert(projectAfterConsumption.data.status === "IN_PROGRESS", "First consumption did not start the planned project");

await call(`/consumptions/${consumption.id}/reverse`, { method: "POST", body: { reason: "Automated smoke test reversal" } });
const afterReversal = await call(`/batches/${batch.id}`);
assert(afterReversal.data.remainingQuantity === "1000.000000", "Batch balance after reversal is incorrect");
assert(afterReversal.data.movements[0].type === "REVERSAL", "Reversal movement was not created");

const search = await call(`/materials?${new URLSearchParams({ q: `Smoke Material ${suffix}`, craftType: "GENERAL", color: "Smoke Brown", stockState: "in_stock" })}`);
assert(search.meta.total >= 1, "Material search did not find the smoke-test material");

console.log(JSON.stringify({
  result: "PASS",
  sourceId: source.data.id,
  materialId: material.data.id,
  batchId: batch.id,
  projectId: project.data.id,
  consumptionId: consumption.id
}, null, 2));
