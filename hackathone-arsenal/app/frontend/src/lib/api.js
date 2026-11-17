import axios from "axios";

const BACKEND = process.env.REACT_APP_BACKEND_URL || "http://localhost:8000";
export const API = `${BACKEND}/api`;
export const WS_URL = (BACKEND.startsWith("https") ? "wss" : "ws") + BACKEND.replace(/^https?/, "") + "/api/ws";

const client = axios.create({ baseURL: API, withCredentials: true });

// Attach Authorization header if stored in localStorage
client.interceptors.request.use((config) => {
  const token = localStorage.getItem("threatlens_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const api = {
  me: () => client.get("/auth/me").then(r => r.data),
  login: (email, password) => client.post("/auth/login", { email, password }).then(r => {
    if (r.data?.token) {
      localStorage.setItem("threatlens_token", r.data.token);
    }
    return r.data;
  }),
  logout: () => client.post("/auth/logout").then(r => {
    localStorage.removeItem("threatlens_token");
    return r.data;
  }).catch(() => {
    localStorage.removeItem("threatlens_token");
  }),
  config: () => client.get("/config").then(r => r.data),
  summary: () => client.get("/dashboard/summary").then(r => r.data),
  eventStream: () => client.get("/dashboard/event-stream").then(r => r.data),
  leaderboard: () => client.get("/dashboard/leaderboard").then(r => r.data),
  origins: () => client.get("/dashboard/origins").then(r => r.data),
  alerts: (severity) => client.get("/alerts", { params: severity && severity !== "all" ? { severity } : {} }).then(r => r.data),
  alert: (id) => client.get(`/alerts/${id}`).then(r => r.data),
  saveNote: (id, note) => client.patch(`/alerts/${id}/note`, { note }).then(r => r.data),
  setStatus: (id, status) => client.patch(`/alerts/${id}/status`, { status }).then(r => r.data),
  setContainment: (id, contained) => client.patch(`/alerts/${id}/containment`, { contained }).then(r => r.data),
  startSim: (scenario, intensity = "normal") => client.post("/simulation/start", { scenario, intensity }).then(r => r.data),
  resetSim: () => client.post("/simulation/reset").then(r => r.data),
  attackerCmd: (line) => client.post("/simulation/attacker-command", { line }).then(r => r.data),
  exportCsv: () => {
    const token = localStorage.getItem("threatlens_token");
    return token ? `${API}/export/alerts.csv?token=${encodeURIComponent(token)}` : `${API}/export/alerts.csv`;
  },
  exportReport: () => {
    const token = localStorage.getItem("threatlens_token");
    return token ? `${API}/export/incident-report.md?token=${encodeURIComponent(token)}` : `${API}/export/incident-report.md`;
  },
};

export function formatDetail(d) {
  if (d == null) return "Something went wrong.";
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map(e => e?.msg || JSON.stringify(e)).join(" ");
  if (d.msg) return d.msg;
  return String(d);
}