/**
 * Transport layer (WO-U4): the shared HTTP plumbing behind the domain
 * modules. The `api` facade in client.ts spreads the domain objects, so
 * callers keep importing from client.ts — only the plumbing moved.
 */

export const BASE = "/portal/api";

/**
 * Phase 4e: explicit case identity for every request.
 *
 * The cockpit always tells the server which case it means — the active-case
 * pointer is only a fallback for CLI/MCP/legacy consumers. CaseContext owns
 * this value; pages never set it directly.
 */
let requestCaseId = "";

/** Set (or clear) the case id attached to every API request. */
export function setRequestCaseId(caseId: string): void {
  requestCaseId = caseId || "";
}

export function caseHeaders(): Record<string, string> {
  return requestCaseId ? { "X-Nexus-Case": requestCaseId } : {};
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public detail?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...caseHeaders(), ...options.headers },
    ...options,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError(
      res.status,
      (body as { error?: string }).error || res.statusText,
      body,
    );
  }
  return body as T;
}

export function get<T>(path: string, options: RequestInit = {}): Promise<T> {
  return request<T>(path, { ...options, method: "GET" });
}

export function post<T>(path: string, data?: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    body: data ? JSON.stringify(data) : undefined,
  });
}

export async function downloadBlob(
  path: string,
  fallbackFilename: string,
): Promise<void> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { ...caseHeaders() },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      res.status,
      (body as { error?: string }).error || res.statusText,
      body,
    );
  }
  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition");
  let filename = fallbackFilename;
  if (disposition) {
    const match = disposition.match(/filename="?([^"]+)"?/);
    if (match && match[1]) {
      filename = match[1];
    }
  }
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  window.setTimeout(() => URL.revokeObjectURL(url), 200);
}
