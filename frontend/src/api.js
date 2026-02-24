const API_BASE =
  "https://safelink-by-strikepoint-security-production.up.railway.app";

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Request failed (${res.status})`);
  }
  return res.json();
}

export function scanUrl(url) {
  return request("/api/scan", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

export function getScan(scanId) {
  return request(`/api/scan/${scanId}`);
}

export function getHistory() {
  return request("/api/history");
}

export function healthCheck() {
  return request("/api/health");
}
