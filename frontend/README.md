# Cloud Guardian Dashboard

React + Vite frontend wired to the Cloud Guardian FastAPI backend.

## Tech stack
- React 18
- Recharts (charts/sparklines)
- Vite (dev server + build)
- No UI framework — pure inline styles matching the dark security theme

## Quick start (local dev)

### Prerequisites
- Node 18+
- Backend running on port 8000 (`uvicorn api.app:app --port 8000`)

### Run
```bash
cd frontend
npm install
npm run dev
# Open http://localhost:3000
```

Vite proxies `/api/*` to `http://localhost:8000` — no CORS issues in dev.

### Build for production
```bash
npm run build
# Outputs to frontend/dist/
# Serve dist/ with nginx, Vercel, Netlify, etc.
```

## Changing the API URL

In `src/main.jsx`, uncomment and set:
```js
window.CG_API_URL = "https://api.yourproductiondomain.com";
```

Or set `VITE_API_URL` in your deployment environment and read it in `App.jsx`:
```js
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
```

## Pages

| Nav item | Status | Data source |
|----------|--------|-------------|
| Overview | ✅ Full | `/alerts`, `/coverage`, `/health`, `/accounts` |
| Incidents | ✅ Full table | `/alerts?limit=500` |
| Remediation | ✅ Approve/dismiss | `/remediation/pending`, `/remediation/{id}/approve` |
| Alerts | ✅ Full feed | `/alerts?limit=500` |
| Settings | ✅ Health + accounts | `/health`, `/accounts` |
| Others | 🚧 Coming soon | — |

## Auth
- Login/register via `/auth/login` and `/auth/register`
- JWT stored in memory (not localStorage — no XSS risk)
- Token attached as `Authorization: Bearer <token>` on every request
- API keys also supported via `X-API-Key` header

## Auto-refresh
All data refreshes every 30 seconds automatically.
"Scan Now" button triggers `POST /scan` and refreshes after 3s.
