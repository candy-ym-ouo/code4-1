import { ApiError } from "@/lib/api";

// Keeps the server-side sliding session alive and serializes refreshes so that
// concurrent API calls (or multiple tabs) trigger at most one token rotation.
let inFlight: Promise<boolean> | null = null;
let timer: ReturnType<typeof setInterval> | null = null;

export async function refreshSession(): Promise<boolean> {
  if (!inFlight) {
    inFlight = (async () => {
      try {
        const response = await fetch("/api/v1/auth/refresh", { method: "POST", credentials: "include" });
        // 204: this call rotated the token. 409: a concurrent refresh (another
        // tab or in-flight request) already rotated it — the shared cookie jar
        // already holds the new token, so the sliding refresh succeeded.
        if (response.status === 204 || response.status === 409) return true;
        const payload = await response.json().catch(() => ({}));
        throw new ApiError(response.status, payload.error?.code ?? "SESSION_EXPIRED", payload.error?.message ?? "登录已失效");
      } finally {
        inFlight = null;
      }
    })();
  }
  try {
    return await inFlight;
  } catch {
    return false;
  }
}

function emitUnauthorized(): void {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("handcraft:unauthorized"));
  }
}

// Called by the API layer when a request comes back 401. One transparent retry
// is attempted after a sliding refresh; hard failures (absolute deadline,
// revocation after logout/password change, token reuse) surface immediately.
export async function recoverAfterUnauthorized(path: string): Promise<boolean> {
  if (path === "/auth/refresh" || path === "/auth/login" || path === "/setup") return false;
  const renewed = await refreshSession();
  if (!renewed) {
    emitUnauthorized();
    return false;
  }
  return true;
}

const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000;

export function startSessionKeepalive(): void {
  if (timer !== null || typeof window === "undefined") return;
  timer = setInterval(() => {
    void refreshSession().then((ok) => {
      if (!ok) emitUnauthorized();
    });
  }, REFRESH_INTERVAL_MS);
  window.addEventListener("online", refreshWhenVisible);
  document.addEventListener("visibilitychange", refreshWhenVisible);
}

export function stopSessionKeepalive(): void {
  if (timer !== null) {
    clearInterval(timer);
    timer = null;
  }
  if (typeof window !== "undefined") {
    window.removeEventListener("online", refreshWhenVisible);
    document.removeEventListener("visibilitychange", refreshWhenVisible);
  }
}

function refreshWhenVisible(): void {
  if (document.visibilityState === "visible") {
    void refreshSession().then((ok) => {
      if (!ok) emitUnauthorized();
    });
  }
}
