# NEXUS-DATA ANALYST v11 — AI Business Analyst [ULTRA STABLE]

## Project Structure
```
nexus-project/
├── index.html              ← Main app (v11.0 Ultra Stable)
├── nexus-admin-v11.html    ← Modern Admin panel
├── backend/
│   ├── worker.js           ← Cloudflare Worker backend
│   ├── wrangler.toml       ← Worker config
│   └── .env.example        ← Environment variables reference
└── README.md
```

## Live URLs
- **Main Website:** [https://nexus-data-analyst-web.pages.dev](https://nexus-data-analyst-web.pages.dev)
- **Backend API:** [https://nexus-data-analyst-api.onliraxter.workers.dev](https://nexus-data-analyst-api.onliraxter.workers.dev)

## Backend Environment Variables (configured as Secrets)
| Variable         | Value                          |
|------------------|-------------------------------|
| GROQ_API_KEY     | [Cloudflare Secret]            |
| GOOGLE_CLIENT_ID | [Cloudflare Secret]            |
| JWT_SECRET       | [Cloudflare Secret]            |
| ADMIN_SECRET     | [Cloudflare Secret]            |
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

## How to Deploy
### Backend
```bash
cd backend
npx wrangler deploy
```

### Frontend
- **GitHub**: Push to `main` (connected to Cloudflare Pages).
- **Manual**: Upload `index.html` to Cloudflare Pages dashboard.

## Admin Panel
- Access `nexus-admin-v11.html` locally or via live URL.
- Use `ADMIN_SECRET` to login (default: `admin123nexus`).
