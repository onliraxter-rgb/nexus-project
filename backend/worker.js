// ═══════════════════════════════════════════════════════
//  NEXUS-DATA ANALYST v6 — Cloudflare Worker Backend
//  KV: NEXUS_KV
//  Routes: /health /api/auth/google /api/user/me
//          /api/user/deduct-credit /api/user/refund-credit
//          /api/analyze /api/payment-request /api/admin/users
//          /api/admin/activate
// ═══════════════════════════════════════════════════════

const ORIGIN_WHITELIST = [
  "https://nexus.onliraxter.workers.dev",
  "https://nexus-data-analyst-web.pages.dev",
  "https://*.nexus-data-analyst-web.pages.dev", // Support branch previews
  "https://nexus-backend-clean.onliraxter.workers.dev",
  "http://localhost:*",
  "http://127.0.0.1:*",
  "null"
];

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "no-referrer",
  "X-NEXUS-Origin": "onliraxter"
};

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, x-nexus-token, x-admin-secret, authorization",
  "Access-Control-Expose-Headers": "X-NEXUS-Origin, Content-Type",
  "Access-Control-Max-Age": "86400",
};

function json(data, status = 200, origin = null) {
  const headers = { "Content-Type": "application/json", ...SECURITY_HEADERS };
  Object.entries(CORS).forEach(([k, v]) => headers[k] = v);
  if (origin) headers["Access-Control-Allow-Origin"] = origin;
  return new Response(JSON.stringify(data), { status, headers });
}

function err(msg, status = 400, origin = null) {
  return json({ error: msg }, status, origin);
}

// ── SECURITY HELPERS ─────────────────────────────────────
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/<[^>]*>/g, '').replace(/script/gi, '');
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function logActivity(env, ip, type, details = {}) {
  const ts = Date.now();
  const entry = { ts, ip, type, ...details };
  await env.NEXUS_KV.put(`log:${ts}:${ip}`, JSON.stringify(entry), { expirationTtl: 86400 * 7 });
  
  // Cleanup old logs (keep last 100) - simple rotation
  const list = await env.NEXUS_KV.list({ prefix: "log:" });
  if (list.keys.length > 100) {
    const sorted = list.keys.sort((a,b) => a.name.localeCompare(b.name));
    for (const k of sorted.slice(0, list.keys.length - 100)) {
      await env.NEXUS_KV.delete(k.name);
    }
  }
}

async function checkRateLimit(env, ip, type, max) {
  const key = `ratelimit:${type}:${ip}`;
  const count = parseInt(await env.NEXUS_KV.get(key) || "0") + 1;
  if (count > max) return false;
  await env.NEXUS_KV.put(key, count.toString(), { expirationTtl: 60 });
  return true;
}

async function isBlacklisted(env, ip) {
  const reason = await env.NEXUS_KV.get(`blacklist:${ip}`);
  if (reason) return true;
  
  // Auto-blacklist check
  const hourKey = `hourly:${ip}`;
  const count = parseInt(await env.NEXUS_KV.get(hourKey) || "0") + 1;
  await env.NEXUS_KV.put(hourKey, count.toString(), { expirationTtl: 3600 });
  if (count > 200) {
    await env.NEXUS_KV.put(`blacklist:${ip}`, "High frequency abuse", { expirationTtl: 86400 });
    await logActivity(env, ip, "AUTO_BLACKLIST", { count });
    return true;
  }
  return false;
}

// ── JWT (simple, no library needed) ──────────────────────
async function signJWT(payload, secret) {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + (24 * 60 * 60); // 24 hours
  const fullPayload = { ...payload, iat, exp };
  
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body   = btoa(unescape(encodeURIComponent(JSON.stringify(fullPayload))));
  const msg    = `${header}.${body}`;
  const key    = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  return `${msg}.${b64}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split(".");
    const msg = `${header}.${body}`;
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    const sigBuf = Uint8Array.from(atob(sig.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    const valid  = await crypto.subtle.verify("HMAC", key, sigBuf, new TextEncoder().encode(msg));
    if (!valid) return null;
    
    const payload = JSON.parse(decodeURIComponent(escape(atob(body))));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && now > payload.exp) return { expired: true };
    return payload;
  } catch {
    return null;
  }
}

// ── Google token verify ───────────────────────────────────
async function verifyGoogleToken(credential, clientId) {
  const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`);
  if (!res.ok) return null;
  const data = await res.json();
  if (data.aud !== clientId) return null;
  return { email: data.email, name: data.name, picture: data.picture, sub: data.sub };
}

// ── Auth middleware ───────────────────────────────────────
async function getUser(request, env) {
  const token = request.headers.get("x-nexus-token");
  if (!token) return null;
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return null;
  if (payload.expired) return { expired: true };
  const raw = await env.NEXUS_KV.get(`user:${payload.email}`);
  if (!raw) return null;
  return JSON.parse(raw);
}

// ── KV user helpers ───────────────────────────────────────
async function saveUser(env, user) {
  await env.NEXUS_KV.put(`user:${user.email}`, JSON.stringify(user));
}

async function getAllUsers(env) {
  const list = await env.NEXUS_KV.list({ prefix: "user:" });
  const users = [];
  for (const key of list.keys) {
    const raw = await env.NEXUS_KV.get(key.name);
    if (raw) users.push(JSON.parse(raw));
  }
  return users;
}

// ═══════════════════════════════════════════════════════
//  MAIN HANDLER
// ═══════════════════════════════════════════════════════
export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const normalizedOrigin = origin ? origin.replace(/\/$/, "") : null;
    
    try {
      const url    = new URL(request.url);
      const path   = url.pathname;
      const method = request.method;
      const ip     = request.headers.get("cf-connecting-ip") || "0.0.0.0";
    const isWhitelisted = !normalizedOrigin || ORIGIN_WHITELIST.some(o => {
      const wo = o.replace(/\/$/, "");
      if (wo === normalizedOrigin) return true;
      if (o.includes("*")) {
        const parts = o.replace(/\/$/, "").split("*");
        return normalizedOrigin.startsWith(parts[0]) && normalizedOrigin.endsWith(parts[1]);
      }
      return false;
    });

    // CORS preflight - handle immediately
    if (method === "OPTIONS") {
      const h = { ...CORS };
      if (normalizedOrigin) h["Access-Control-Allow-Origin"] = normalizedOrigin;
      return new Response(null, { status: 204, headers: h });
    }

    // ── ORIGIN WHITELIST (Except /health) ────────────────
    if (path !== "/health" && origin && !isWhitelisted) {
      await logActivity(env, ip, "FORBIDDEN_ORIGIN", { origin });
      return err(`Forbidden origin: ${origin}`, 403, normalizedOrigin);
    }

    // ── IP BLACKLIST ─────────────────────────────────────
    if (await isBlacklisted(env, ip)) return err("Access denied.", 403, normalizedOrigin);

    // ── REQUEST SIZE LIMIT (10MB) ────────────────────────
    const cl = parseInt(request.headers.get("content-length") || "0");
    if (cl > 10 * 1024 * 1024) return err("Request body too large", 413, normalizedOrigin);

    // ── /health ───────────────────────────────────────────
    if (path === "/health") {
      return json({ status: "ok", platform: "cloudflare-workers" }, 200, normalizedOrigin);
    }

    // ── ROUTE RATE LIMITING ──────────────────────────────
    let limit = 100;
    if (path === "/api/auth/google") limit = 5;
    else if (path === "/api/analyze") limit = 20;

    if (!(await checkRateLimit(env, ip, path, limit))) {
      await logActivity(env, ip, "RATE_LIMIT_HIT", { path });
      return err("Rate limit exceeded. Try again in 60 seconds.", 429, normalizedOrigin);
    }

    // ── AUTH REQUIREMENT (Most routes) ───────────────────
    const publicPaths = ["/health", "/api/auth/google", "/api/payment-request", "/api/notify"];
    const needsAuth = !publicPaths.includes(path);
    let user = null;
    if (needsAuth) {
      user = await getUser(request, env);
      if (!user) {
        await logActivity(env, ip, "UNAUTHORIZED_ATTEMPT", { path });
        return err("Unauthorized", 401);
      }
      if (user.expired) {
        return err("Session expired. Please login again.", 401);
      }
    }

    // ── SAFE JSON PARSE HELPER ───────────────────────────
    const getJson = async () => {
      try { return await request.json(); }
      catch { return null; }
    };

    // ── /api/auth/google ──────────────────────────────────
    if (path === "/api/auth/google" && method === "POST") {
      const body = await getJson();
      if (!body) return err("Malformed JSON", 400);
      const credential = body.credential;
      if (!credential) return err("No credential");

      const profile = await verifyGoogleToken(credential, env.GOOGLE_CLIENT_ID);
      if (!profile) {
        await logActivity(env, ip, "FAILED_LOGIN", { email: "unknown" });
        return err("Invalid Google token", 401);
      }

      // Email Validation
      if (!validateEmail(profile.email)) return err("Invalid email format");

      // Load or create user
      let raw  = await env.NEXUS_KV.get(`user:${profile.email}`);
      let userData = raw ? JSON.parse(raw) : null;

      if (!userData) {
        userData = {
          email:     profile.email,
          name:      sanitize(profile.name),
          picture:   profile.picture,
          plan:      "free",
          credits:   parseInt(env.FREE_CREDITS || "10"),
          active:    true,
          createdAt: new Date().toISOString(),
        };
        await saveUser(env, userData);
      }

      const token = await signJWT({ email: userData.email }, env.JWT_SECRET);
      return json({ token, user: userData });
    }

    // ── /api/user/me ─────────────────────────────────────
    if (path === "/api/user/me" && method === "GET") {
      const user = await getUser(request, env);
      if (!user) return err("Unauthorized", 401);
      return json({ user });
    }

    // ── /api/user/deduct-credit ───────────────────────────
    if (path === "/api/user/deduct-credit" && method === "POST") {
      const user = await getUser(request, env);
      if (!user) return err("Unauthorized", 401);
      if (user.plan === "unlimited") return json({ credits: -1 });
      if (user.credits <= 0) return err("No credits left", 402);
      user.credits--;
      await saveUser(env, user);
      return json({ credits: user.credits });
    }

    // ── /api/user/refund-credit ───────────────────────────
    if (path === "/api/user/refund-credit" && method === "POST") {
      const user = await getUser(request, env);
      if (!user) return err("Unauthorized", 401);
      if (user.plan !== "unlimited") {
        user.credits++;
        await saveUser(env, user);
      }
      return json({ credits: user.credits });
    }

    // ── /api/analyze ──────────────────────────────────────
    if (path === "/api/analyze" && method === "POST") {
      const user = await getUser(request, env);
      if (!user) return err("Unauthorized", 401);

      const body = await getJson();
      if (!body) return err("Malformed JSON", 400);
      const { messages, fileData } = body;

      // Build Groq request
      const groqMessages = [];
      if (fileData) {
        groqMessages.push({
          role: "user",
          content: `[File attached: ${sanitize(fileData.name)}]\n${sanitize(fileData.text) || ""}`,
        });
      }
      (messages || []).forEach(m => {
        groqMessages.push({ role: m.role, content: sanitize(m.content) });
      });

      const groqRes = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${env.GROQ_API_KEY}`,
        },
        body: JSON.stringify({
          model: "llama-3.3-70b-versatile",
          messages: [
            {
              role: "system",
              content: `You are NEXUS-DATA ANALYST v6 — Universal AI Data Analyst. Combined: Senior Data Scientist + CFO + McKinsey Consultant + ML Engineer + Statistician + Risk Manager.
ANALYSIS LAYERS:
1. DATA PROFILING: Schema, quality, missing patterns, outliers (IQR/Z-score), cardinality.
2. DESCRIPTIVE: Mean, median, mode, variance, std dev, IQR, skewness, kurtosis, CAGR, YoY/MoM/QoQ.
3. INFERENTIAL: Hypothesis testing, t-tests, ANOVA, chi-square, correlation, regression, confidence intervals.
4. DIAGNOSTIC: Waterfall decomp, Pareto/ABC, 5-Why, volume/price/mix variance, HHI.
5. PREDICTIVE: Trend projection, time-series decomp, SMA/EMA, churn prediction, LTV projection.
6. PRESCRIPTIVE: ROI-ranked action plan, resource allocation, 90-day roadmap.
7. FINANCE: P&L decomp, DuPont ROE bridge, Altman Z-Score, Piotroski F, DCF sensitivity, WACC, CCC, 30+ ratios.
8. RISK: Monte Carlo ranges, scenario stress test, HHI, sensitivity tornado chart.
9. VISUALIZATIONS: Use [CHART:type|title|json] for bar/line/pie/area/radar charts. Use [KPI:label|value|delta|up/down/neutral] for KPI cards.
10. CODE: SQL (CTEs, window functions), Python/pandas, DAX, R.
ALWAYS: Detect anomalies, flag assumptions, end with ◆ NEXUS-DATA ANALYST VERDICT + PRIORITY ACTIONS.
Format: ══ sections, ▶ sub-sections, | tables, **bold** numbers.`,
            },
            ...groqMessages,
          ],
          max_tokens: 4096,
          temperature: 0.7,
        }),
      });

      if (!groqRes.ok) {
        const errData = await groqRes.text();
        return err(`AI error: ${errData}`, 502);
      }

      const groqData = await groqRes.json();
      const reply    = groqData.choices?.[0]?.message?.content || "No response";
      return json({ reply });
    }

    // ── /api/payment-request ─────────────────────────────
    if (path === "/api/payment-request" && method === "POST") {
      const body = await request.json();
      const { plan, utr, name, email, phone } = body;
      if (!utr || !name || !email) return err("Missing fields");

      const record = {
        plan, utr, name, email, phone,
        status:    "pending",
        createdAt: new Date().toISOString(),
      };
      await env.NEXUS_KV.put(`payment:${utr}`, JSON.stringify(record));

      // Notify admin via email (optional, needs Email routing)
      return json({ ok: true, message: "Payment request received" });
    }

    // ── /api/notify ───────────────────────────────────────
    if (path === "/api/notify" && method === "POST") {
      const body = await request.json();
      await env.NEXUS_KV.put(`notify:${body.email}`, JSON.stringify({ email: body.email, at: new Date().toISOString() }));
      return json({ ok: true });
    }

    // ── /api/admin/users ──────────────────────────────────
    if (path === "/api/admin/users" && method === "GET") {
      const secret = request.headers.get("x-admin-secret");
      if (secret !== env.ADMIN_SECRET) return err("Forbidden", 403);
      const users    = await getAllUsers(env);
      const payments = [];
      const pList    = await env.NEXUS_KV.list({ prefix: "payment:" });
      for (const k of pList.keys) {
        const raw = await env.NEXUS_KV.get(k.name);
        if (raw) payments.push(JSON.parse(raw));
      }
      return json({ users, payments });
    }

    // ── /api/admin/activate ───────────────────────────────
    if (path === "/api/admin/activate" && method === "POST") {
      const secret = request.headers.get("x-admin-secret");
      if (secret !== env.ADMIN_SECRET) return err("Forbidden", 403);

      const body = await request.json();
      const { email, plan, credits } = body;
      if (!email) return err("Missing email");

      const raw  = await env.NEXUS_KV.get(`user:${email}`);
      if (!raw) return err("User not found", 404);
      const user = JSON.parse(raw);

      user.plan    = plan || "pro";
      user.credits = plan === "unlimited" ? -1 : (credits || 100);
      user.active  = true;
      await saveUser(env, user);
      return json({ ok: true, user });
    }

    // ── /api/admin/logs ───────────────────────────────────
    if (path === "/api/admin/logs" && method === "GET") {
      const secret = request.headers.get("x-admin-secret");
      if (secret !== env.ADMIN_SECRET) return err("Forbidden", 403);
      
      const list = await env.NEXUS_KV.list({ prefix: "log:" });
      const logs = [];
      for (const k of list.keys) {
        const raw = await env.NEXUS_KV.get(k.name);
        if (raw) logs.push(JSON.parse(raw));
      }
      return json({ logs: logs.sort((a,b) => b.ts - a.ts) }, 200, normalizedOrigin);
    }

    return err("Not found", 404, normalizedOrigin);

    } catch (e) {
      console.error("Worker Error:", e);
      return err(`Internal Server Error: ${e.message}`, 500, normalizedOrigin);
    }
  },
};
