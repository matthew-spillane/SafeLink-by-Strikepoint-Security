const API_BASE = "";

function getSessionId() {
  const key = "safelink-session-id";
  let id = localStorage.getItem(key);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(key, id);
  }
  return id;
}

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
    body: JSON.stringify({ url, session_id: getSessionId() }),
  });
}

export function getScan(scanId) {
  return request(`/api/scan/${scanId}`);
}

export function getHistory() {
  const sid = getSessionId();
  return request(`/api/history?session_id=${encodeURIComponent(sid)}`);
}

export function getUrlscanResult(scanId) {
  return request(`/api/scan/${scanId}/urlscan`);
}

export function healthCheck() {
  return request("/api/health");
}
