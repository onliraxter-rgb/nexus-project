# NEXUS v6 — AI Business Analyst

## Project Structure
```
nexus-project/
├── frontend/
│   ├── index.html          ← Main app (deploy to Cloudflare Pages)
│   └── nexus-control.html  ← Admin panel
├── backend/
│   ├── worker.js           ← Cloudflare Worker backend
│   ├── wrangler.toml       ← Worker config
│   └── .env.example        ← Environment variables reference
└── README.md
```

## Live URLs
- Frontend: https://nexus.onliraxter.workers.dev
- Backend:  https://nexus-backend-clean.onliraxter.workers.dev

## Backend Environment Variables (already set in Cloudflare)
| Variable         | Value                          |
|------------------|-------------------------------|
| GROQ_API_KEY     | gsk_fieUUf...                 |
| GOOGLE_CLIENT_ID | 152785926177-ani51o...         |
| JWT_SECRET       | nexus_secret_2026_x9k         |
| ADMIN_SECRET     | admin123nexus                 |
| FREE_CREDITS     | 10                            |

## KV Namespace
- Name: NEXUS_KV
- ID:   6c1a280596a8453fa4893dd7de5f7700
- Binding: NEXUS_KV

## API Routes
| Method | Route                    | Description           |
|--------|--------------------------|-----------------------|
| GET    | /health                  | Health check          |
| POST   | /api/auth/google         | Google login          |
| GET    | /api/user/me             | Get current user      |
| POST   | /api/user/deduct-credit  | Deduct 1 credit       |
| POST   | /api/user/refund-credit  | Refund 1 credit       |
| POST   | /api/analyze             | AI analysis via Groq  |
| POST   | /api/payment-request     | Submit UPI payment    |
| POST   | /api/notify              | Email notify signup   |
| GET    | /api/admin/users         | List all users        |
| POST   | /api/admin/activate      | Activate user plan    |

## How to Deploy with Antigravity / Wrangler
```bash
# Backend
cd backend
npx wrangler deploy

# Frontend — just upload index.html to Cloudflare Pages
# or push to GitHub (connected to Cloudflare Pages)
```

## Admin Panel
Open nexus-control.html in browser.
Use ADMIN_SECRET = admin123nexus to login.
