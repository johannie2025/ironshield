import type { AlertsResponse } from "./types";

const API_BASE = "https://wiseshield.alwaysdata.net/api";
const TOKEN_KEY = "ironshield_machine_token";

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function storeToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token.trim());
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

async function authedFetch(path: string): Promise<Response> {
  const token = getStoredToken();
  if (!token) {
    throw new Error("no_token");
  }
  return fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

export async function fetchAlerts(unacknowledgedOnly = false): Promise<AlertsResponse> {
  const qs = unacknowledgedOnly ? "?unacknowledged=1&limit=100" : "?limit=100";
  const res = await authedFetch(`/alerts${qs}`);
  if (res.status === 401) {
    clearToken();
    throw new Error("unauthorized");
  }
  if (!res.ok) {
    throw new Error(`http_${res.status}`);
  }
  return res.json();
}
