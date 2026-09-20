import { recoverAfterUnauthorized } from "@/lib/session";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly fieldErrors: Record<string, string[]> = {}
  ) {
    super(message);
  }
}

type ApiOptions = Omit<RequestInit, "body"> & { body?: unknown };

const HARD_UNAUTHORIZED_CODES = new Set([
  "UNAUTHENTICATED",
  "SESSION_REVOKED",
  "SESSION_ABSOLUTE_EXPIRED",
  "SESSION_REUSE_DETECTED"
]);

function emitUnauthorized(): void {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("handcraft:unauthorized"));
  }
}

async function rawRequest(path: string, options: ApiOptions): Promise<Response> {
  const { body, ...requestOptions } = options;
  const headers = new Headers(options.headers);
  const init: RequestInit = {
    ...requestOptions,
    credentials: "include",
    headers
  };
  if (body !== undefined && !(body instanceof FormData)) {
    headers.set("content-type", "application/json");
    init.body = JSON.stringify(body);
  } else if (body instanceof FormData) {
    init.body = body;
  }
  return fetch(`/api/v1${path}`, init);
}

async function parseError(response: Response): Promise<ApiError> {
  const payload = await response.json().catch(() => ({}));
  const error = payload.error ?? {};
  return new ApiError(response.status, error.code ?? "REQUEST_FAILED", error.message ?? "请求失败", error.fieldErrors ?? {});
}

export async function request<T>(path: string, options: ApiOptions = {}): Promise<T> {
  let response = await rawRequest(path, options);

  if (response.status === 401) {
    const probe = await parseError(response);
    // SESSION_EXPIRED means the idle window lapsed: one transparent sliding
    // refresh + retry keeps an active user working. Everything else is a hard
    // stop (logged out, password changed, absolute deadline, token reuse).
    if (probe.code === "SESSION_EXPIRED" && (await recoverAfterUnauthorized(path))) {
      response = await rawRequest(path, options);
    } else {
      if (HARD_UNAUTHORIZED_CODES.has(probe.code) || probe.code === "SESSION_EXPIRED") emitUnauthorized();
      throw probe;
    }
  }

  if (response.status === 204) return undefined as T;
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = payload.error ?? {};
    const code = error.code ?? "REQUEST_FAILED";
    if (response.status === 401 && HARD_UNAUTHORIZED_CODES.has(code)) emitUnauthorized();
    throw new ApiError(response.status, code, error.message ?? "请求失败", error.fieldErrors ?? {});
  }
  return payload as T;
}

export async function download(path: string): Promise<void> {
  let response = await fetch(`/api/v1${path}`, { credentials: "include" });

  if (response.status === 401) {
    const payload = await response.json().catch(() => ({}));
    const code = payload.error?.code ?? "SESSION_EXPIRED";
    if (code === "SESSION_EXPIRED" && (await recoverAfterUnauthorized(path))) {
      response = await fetch(`/api/v1${path}`, { credentials: "include" });
    } else {
      emitUnauthorized();
      throw new ApiError(response.status, code, payload.error?.message ?? "导出失败", payload.error?.fieldErrors ?? {});
    }
  }

  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const error = payload.error ?? {};
    const code = error.code ?? "DOWNLOAD_FAILED";
    if (response.status === 401 && HARD_UNAUTHORIZED_CODES.has(code)) emitUnauthorized();
    throw new ApiError(response.status, code, error.message ?? "导出失败", error.fieldErrors ?? {});
  }

  const disposition = response.headers.get("content-disposition") ?? "";
  const filenameMatch = /filename="?([^";]+)"?/i.exec(disposition);
  const filename = filenameMatch?.[1] ?? "handcraft-export";
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
