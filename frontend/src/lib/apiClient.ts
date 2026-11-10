const API_BASE_URL =
  ((import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() || "").replace(/\/+$/, "");

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

type TokenGetter = () => string | null;
let getAuthToken: TokenGetter = () => null;

export function setAuthTokenGetter(fn: TokenGetter) {
  getAuthToken = fn;
}

export async function apiRequest<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = getAuthToken();
  const headers = new Headers(options.headers);
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const url = `${API_BASE_URL}${path}`;
  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const payload = (await response.json()) as { detail?: string };
      if (payload?.detail) {
        message = payload.detail;
      }
    } catch {
      // Ignore non-JSON error body
    }
    throw new ApiError(message, response.status);
  }

  return (await response.json()) as T;
}

