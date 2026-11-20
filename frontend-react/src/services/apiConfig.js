// =========================================================================
// Dynamic API Configuration for Local Dev, Docker, and Cloud Deployments
// =========================================================================

export const getApiBaseUrl = () => {
  // 1. Explicit Vite environment variable (set at build or via .env)
  if (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL) {
    const raw = import.meta.env.VITE_API_URL.replace(/\/$/, '');
    return raw.endsWith('/api') ? raw : `${raw}/api`;
  }

  // 2. Window runtime configuration (e.g. injected at container start)
  if (typeof window !== 'undefined' && window.__AEGIS_API_URL__) {
    const raw = String(window.__AEGIS_API_URL__).replace(/\/$/, '');
    return raw.endsWith('/api') ? raw : `${raw}/api`;
  }

  // 3. Browser environment heuristics:
  if (typeof window !== 'undefined') {
    // If running on local Vite dev server on port 3000, hit backend on 8000
    if (window.location.hostname === 'localhost' && window.location.port === '3000') {
      return 'http://localhost:8000/api';
    }
    // In Docker (Nginx on port 80/3000) or any deployed host (Render, Vercel, VPS),
    // use relative '/api' so Nginx or reverse proxy routes requests without CORS or mixed content issues
    return '/api';
  }

  return 'http://localhost:8000/api';
};

export const API_BASE = getApiBaseUrl();
export default API_BASE;
