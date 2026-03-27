# NEXUS v12 ELITE — AI Business Data Analyst

> World-class AI data analyst for Indian SMEs. Upload CSV/Excel, get McKinsey-level insights in 30 seconds.

## Live URLs

- **Website:** https://nexus-data-analyst-web.pages.dev
- **Backend API:** https://nexus-data-analyst-api.onliraxter.workers.dev

## Project Structure

```
nexus-project/
├── frontend/
│   └── index.html          ← Main app (v12 Elite — deploy this to Cloudflare Pages)
├── backend/
│   ├── worker.js           ← Cloudflare Worker backend (v12)
│   ├── wrangler.toml       ← Worker config
│   └── .env.example        ← Environment variables reference
└── README.md
```

## What's New in v12 Elite

- **Fuzzy column matching** — works on any real-world file, not just perfectly named columns
- **Verified chart generator** — charts built from JavaScript data, zero AI hallucination
- **AI response validator** — cross-checks AI numbers against verified data
- **Schema enforcer** — detects type mismatches, discount format errors
- **Timestamp validator** — catches invalid dates, mixed formats
- **Geo normalizer** — standardizes city/state names
- **Drag & drop file support** — drop files directly on dashboard
- **Smart paste** — paste CSV anywhere, auto-detects and auto-analyzes
- **100x module prompts** — all 13 modules completely rewritten with expert frameworks
- **Open access mode** — no login required for testing phase

## Deploy — Step by Step

### Step 1: Deploy Backend (Worker)

**Option A — Cloudflare Dashboard (recommended):**
1. Go to dash.cloudflare.com → Workers & Pages
2. Click `nexus-data-analyst-api` → Edit Code
3. Select all → Delete → Paste contents of `backend/worker.js`
4. Click **Deploy**

**Option B — Wrangler CLI:**
```bash
cd backend
npx wrangler deploy
```

### Step 2: Set Worker Secrets

In Cloudflare Dashboard → Workers → `nexus-data-analyst-api` → Settings → Variables and Secrets:

| Secret Name | Where to get it |
|---|---|
| `GROQ_API_KEY` | console.groq.com → API Keys |
| `GEMINI_API_KEY` | aistudio.google.com → Get API Key (optional, fallback) |
| `JWT_SECRET` | Any random 32+ char string |
| `ADMIN_SECRET` | Your private admin password |

⚠️ Add all as **Secrets** (encrypted), NOT as plain Variables.

### Step 3: Deploy Frontend

**GitHub → Cloudflare Pages (auto-deploy):**
1. Go to github.com/onliraxter-rgb/nexus-project
2. Navigate to `frontend/index.html`
3. Click the pencil (Edit) icon
4. Select all → Delete → Paste contents of `frontend/index.html`
5. Commit message: `deploy: NEXUS v12 Elite`
6. Commit — Cloudflare Pages auto-deploys in ~60 seconds

**Verify deploy worked:**
- Open https://nexus-data-analyst-web.pages.dev in **incognito tab**
- Dashboard badge should show `v12 · ELITE` (not v11)

## Backend Secrets Reference

| Variable | Type | Required |
|---|---|---|
| `GROQ_API_KEY` | Secret | ✅ Yes |
| `GEMINI_API_KEY` | Secret | Optional (fallback AI) |
| `JWT_SECRET` | Secret | ✅ Yes |
| `ADMIN_SECRET` | Secret | ✅ Yes |
| `GOOGLE_CLIENT_ID` | Var (plain) | ✅ Already in wrangler.toml |
| `FREE_CREDITS` | Var (plain) | ✅ Already in wrangler.toml |

## KV Namespace

- **Name:** NEXUS_KV
- **ID:** 6c1a280596a8453fa4893dd7de5f7700
- **Binding:** NEXUS_KV (already in wrangler.toml)

## API Routes

| Method | Route | Auth Required |
|---|---|---|
| GET | /health | No |
| POST | /api/auth/google | No |
| POST | /api/analyze | No (guest access during testing) |
| GET | /api/user/me | JWT token |
| POST | /api/user/deduct-credit | JWT token |
| POST | /api/user/refund-credit | JWT token |
| POST | /api/payment-request | No |
| POST | /api/notify | No |
| GET | /api/admin/users | Admin secret |
| POST | /api/admin/activate | Admin secret |
| GET | /api/admin/logs | Admin secret |
| GET | /api/admin/check-secrets | Admin secret |

## Architecture

```
User Browser
    ↓
Cloudflare Pages (frontend/index.html)
    ↓ API calls
Cloudflare Worker (backend/worker.js)
    ↓                    ↓
Groq API           Gemini API (fallback)
(llama-3.3-70b)    (gemini-1.5-flash)
    ↓
Cloudflare KV (user data, credits, sessions)
```

## Testing Checklist After Deploy

- [ ] Dashboard shows `v12 · ELITE` badge
- [ ] Paste a CSV → auto-processes and sends analysis
- [ ] Drag & drop a file → loads correctly
- [ ] Upload a CSV → dataset card appears with row count
- [ ] Ask a question → streaming response appears
- [ ] Charts render after analysis
- [ ] PDF export works
- [ ] Google Sheets URL import works
