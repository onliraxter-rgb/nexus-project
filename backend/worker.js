// ═══════════════════════════════════════════════════════
//  NEXUS v6 — Cloudflare Worker Backend
//  KV: NEXUS_KV
//  Routes: /health /api/auth/google /api/user/me
//          /api/user/deduct-credit /api/user/refund-credit
//          /api/analyze /api/payment-request /api/admin/users
//          /api/admin/activate
// ═══════════════════════════════════════════════════════

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, x-nexus-token, x-admin-secret",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// ── JWT (simple, no library needed) ──────────────────────
async function signJWT(payload, secret) {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body   = btoa(JSON.stringify(payload));
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
    return JSON.parse(atob(body));
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
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    // ── /health ───────────────────────────────────────────
    if (path === "/health") {
      return json({ status: "ok", platform: "cloudflare-workers" });
    }

    // ── /api/auth/google ──────────────────────────────────
    if (path === "/api/auth/google" && method === "POST") {
      const body       = await request.json();
      const credential = body.credential;
      if (!credential) return err("No credential");

      const profile = await verifyGoogleToken(credential, env.GOOGLE_CLIENT_ID);
      if (!profile) return err("Invalid Google token", 401);

      // Load or create user
      let raw  = await env.NEXUS_KV.get(`user:${profile.email}`);
      let user = raw ? JSON.parse(raw) : null;

      if (!user) {
        user = {
          email:     profile.email,
          name:      profile.name,
          picture:   profile.picture,
          plan:      "free",
          credits:   parseInt(env.FREE_CREDITS || "10"),
          active:    true,
          createdAt: new Date().toISOString(),
        };
        await saveUser(env, user);
      }

      const token = await signJWT({ email: user.email }, env.JWT_SECRET);
      return json({ token, user });
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

      const body = await request.json();
      const { messages, fileData } = body;

      // Build Groq request
      const groqMessages = [];
      if (fileData) {
        groqMessages.push({
          role: "user",
          content: `[File attached: ${fileData.name}]\n${fileData.text || ""}`,
        });
      }
      groqMessages.push(...(messages || []));

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
              content: "You are NEXUS, an elite AI business analyst. Be sharp, structured, and data-driven.",
            },
            ...groqMessages,
          ],
          max_tokens: 2048,
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

    return err("Not found", 404);
  },
};
