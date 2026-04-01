// ═══════════════════════════════════════════════════════
//  NEXUS v15 — Analytical Intelligence Engine
//  Cloudflare Worker
//  Architecture: Judgment in code. Translation in LLM.
//  Every judgment is deterministic. Nothing is delegated.
// ═══════════════════════════════════════════════════════

'use strict';

// ── SECURITY: Origin whitelist ───────────────────────────
const ORIGIN_WHITELIST = [
  "https://nexus-data-analyst-web.pages.dev",
  "https://nexus-project.pages.dev",
  "https://nexus-backend-clean.onliraxter.workers.dev",
  "http://localhost",
  "http://127.0.0.1",
  "null"
];

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "no-referrer",
  "X-NEXUS-Version": "v15",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none';"
};

const CORS_HEADERS = {
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, x-nexus-token, x-admin-secret, authorization",
  "Access-Control-Expose-Headers": "X-NEXUS-Version, Content-Type",
  "Access-Control-Max-Age": "86400"
};

// ── RATE LIMIT CONSTANTS ─────────────────────────────────
const RATE_LIMITS = {
  auth: { max: 10, window: 60 },
  analyze: { max: 30, window: 60 },
  general: { max: 100, window: 60 }
};

// ── JUDGMENT THRESHOLDS (deterministic, not LLM) ────────
const THRESHOLDS = {
  MIN_ROWS_FOR_PATTERNS: 30,
  MIN_ROWS_FOR_TRENDS: 7,
  MIN_ROWS_FOR_SEASONAL: 12,
  MIN_ROWS_FOR_FORECAST: 24,
  MIN_ROWS_FOR_STANDARD: 100,
  MIN_ROWS_FOR_FULL: 500,
  MIN_CLEAN_RATE_FOR_ANALYSIS: 85,
  MIN_CLEAN_RATE_HARD_REFUSE: 70,
  MAX_ANOMALY_DENSITY_PCT: 15,
  OUTLIER_DISTORTION_THRESHOLD: 0.20,
  MIN_R2_FOR_LINEAR_FORECAST: 0.50,
  MIN_CATEGORY_INSTANCES: 3,
  SKEW_DISTORTION_THRESHOLD: 2.0,
  CONCENTRATION_DOMINANCE_PCT: 40
};

// ═══════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════

function buildCORSHeaders(origin) {
  const h = { ...SECURITY_HEADERS, ...CORS_HEADERS };
  // Validate origin against whitelist
  if (origin && isOriginAllowed(origin)) {
    h["Access-Control-Allow-Origin"] = origin;
  } else {
    h["Access-Control-Allow-Origin"] = "null";
  }
  return h;
}

function isOriginAllowed(origin) {
  if (!origin) return false;
  const clean = origin.replace(/\/$/, "");
  return ORIGIN_WHITELIST.some(allowed => {
    const cleanAllowed = allowed.replace(/\/$/, "");
    if (cleanAllowed.includes("*")) {
      const [prefix, suffix] = cleanAllowed.split("*");
      return clean.startsWith(prefix) && clean.endsWith(suffix || "");
    }
    return clean === cleanAllowed || clean.startsWith(cleanAllowed);
  });
}

function jsonResponse(data, status = 200, origin = null) {
  const headers = buildCORSHeaders(origin);
  headers["Content-Type"] = "application/json";
  return new Response(JSON.stringify(data), { status, headers });
}

function errorResponse(message, status = 400, origin = null) {
  return jsonResponse({ error: message, status }, status, origin);
}

function sanitizeString(s) {
  if (typeof s !== "string") return String(s || "");
  return s
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]*>/g, "")
    .replace(/javascript:/gi, "")
    .replace(/on\w+\s*=/gi, "")
    .trim();
}

function safeNumber(val, fallback = null) {
  if (val === null || val === undefined || val === "") return fallback;
  const s = String(val).replace(/[₹$€£¥,\s]/g, "").replace(/[()]/g, "");
  if (!s || s === "-" || /^(null|na|n\/a|nan|undefined|-)$/i.test(s)) return fallback;
  const n = parseFloat(s);
  return isNaN(n) || !isFinite(n) ? fallback : n;
}

function safeDate(val) {
  if (val === null || val === undefined) return null;
  try {
  const s = String(val).trim();
  if (!s || s.toLowerCase() === "null" || s.toLowerCase() === "na") return null;
  let d = new Date(s);
  if (!isNaN(d.getTime()) && d.getFullYear() > 1900 && d.getFullYear() < 2100) {
    // Reject dates in the future beyond 1 year — likely data entry errors
    if (d > new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)) return null;
    return d;
  }
  const parts = s.split(/[\/\-\.]/);
  if (parts.length === 3) {
    const [a, b, c] = parts;
    if (c && c.length === 4) {
      d = new Date(`${c}-${String(b).padStart(2, "0")}-${String(a).padStart(2, "0")}`);
      if (!isNaN(d.getTime()) && d.getFullYear() > 1900) return d;
    }
    if (a && a.length === 4) {
      d = new Date(`${a}-${String(b).padStart(2, "0")}-${String(c).padStart(2, "0")}`);
      if (!isNaN(d.getTime()) && d.getFullYear() > 1900) return d;
    }
  }
  return null;
  } catch { return null; }
}

function roundTo(v, decimals = 2) {
  if (!isFinite(v)) return 0;
  return Math.round(v * Math.pow(10, decimals)) / Math.pow(10, decimals);
}

function formatIndian(n) {
  if (n == null || !isFinite(n)) return "N/A";
  const abs = Math.abs(n);
  const sign = n < 0 ? "-" : "";
  if (abs >= 10000000) return `${sign}₹${roundTo(abs / 10000000, 2)}Cr`;
  if (abs >= 100000) return `${sign}₹${roundTo(abs / 100000, 2)}L`;
  if (abs >= 1000) return `${sign}₹${Number(abs).toLocaleString("en-IN", { maximumFractionDigits: 0 })}`;
  return `${sign}₹${roundTo(abs, 2)}`;
}

// ── Scrub non-finite values for JSON safety ──────────────
function scrubForJSON(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === "number") return isFinite(obj) ? obj : 0;
  if (Array.isArray(obj)) return obj.map(scrubForJSON);
  if (typeof obj === "object") {
    const out = {};
    for (const [k, v] of Object.entries(obj)) out[k] = scrubForJSON(v);
    return out;
  }
  return obj;
}

// ═══════════════════════════════════════════════════════
//  AUTH & KV UTILITIES
// ═══════════════════════════════════════════════════════

async function signJWT(payload, secret) {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 86400;
  const fullPayload = { ...payload, iat, exp };
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(unescape(encodeURIComponent(JSON.stringify(fullPayload))));
  const msg = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
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
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const msg = `${header}.${body}`;
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    const sigBuf = Uint8Array.from(
      atob(sig.replace(/-/g, "+").replace(/_/g, "/")),
      c => c.charCodeAt(0)
    );
    const valid = await crypto.subtle.verify("HMAC", key, sigBuf, new TextEncoder().encode(msg));
    if (!valid) return null;
    const pl = JSON.parse(decodeURIComponent(escape(atob(body))));
    if (pl.exp && Math.floor(Date.now() / 1000) > pl.exp) return { expired: true };
    return pl;
  } catch {
    return null;
  }
}

async function verifyGoogleToken(credential, clientId) {
  try {
    const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`);
    if (!res.ok) return null;
    const data = await res.json();
    if (data.aud !== clientId) return null;
    if (data.exp && parseInt(data.exp) < Math.floor(Date.now() / 1000)) return null;
    return { email: data.email, name: data.name, picture: data.picture, sub: data.sub };
  } catch {
    return null;
  }
}

async function getUser(request, env) {
  if (!env.NEXUS_KV) return null;
  const token = request.headers.get("x-nexus-token");
  if (!token || token === "guest_token") return null;
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload || payload.expired) return null;
  try {
    const raw = await env.NEXUS_KV.get(`user:${payload.email}`);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

async function saveUser(env, user) {
  if (!env.NEXUS_KV) return;
  try {
    await env.NEXUS_KV.put(`user:${user.email}`, JSON.stringify(user));
  } catch (e) {
    console.error("saveUser KV error:", e.message);
  }
}

async function checkRateLimit(env, ip, type) {
  if (!env.NEXUS_KV) return true;
  const limit = RATE_LIMITS[type] || RATE_LIMITS.general;
  const key = `rl:${type}:${ip}:${Math.floor(Date.now() / (limit.window * 1000))}`;
  try {
    const count = parseInt(await env.NEXUS_KV.get(key) || "0") + 1;
    if (count > limit.max) return false;
    await env.NEXUS_KV.put(key, count.toString(), { expirationTtl: limit.window * 2 });
    return true;
  } catch {
    return true; // Fail open on KV error — don't block legitimate traffic
  }
}

async function isBlacklisted(env, ip) {
  if (!env.NEXUS_KV) return false;
  try {
    const [blacklisted, hourRaw] = await Promise.all([
      env.NEXUS_KV.get(`blacklist:${ip}`).catch(() => null),
      env.NEXUS_KV.get(`hourly:${ip}:${Math.floor(Date.now() / 3600000)}`).catch(() => null)
    ]);
    if (blacklisted) return true;
    const count = parseInt(hourRaw || "0") + 1;
    const hourKey = `hourly:${ip}:${Math.floor(Date.now() / 3600000)}`;
    await env.NEXUS_KV.put(hourKey, count.toString(), { expirationTtl: 7200 }).catch(() => {});
    if (count > 500) {
      await env.NEXUS_KV.put(`blacklist:${ip}`, "auto", { expirationTtl: 86400 }).catch(() => {});
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

async function logActivity(env, ip, type, details = {}) {
  if (!env.NEXUS_KV) return;
  try {
    const ts = Date.now();
    await env.NEXUS_KV.put(
      `log:${ts}:${ip}`,
      JSON.stringify({ ts, ip, type, ...details }),
      { expirationTtl: 604800 }
    );
  } catch { /* Non-critical — don't throw */ }
}

// ═══════════════════════════════════════════════════════
//  CSV / DATA PARSING
// ═══════════════════════════════════════════════════════

function detectDelimiter(line) {
  const counts = { ",": 0, "\t": 0, "|": 0, ";": 0 };
  let inQuote = false;
  for (const ch of line) {
    if (ch === '"') { inQuote = !inQuote; continue; }
    if (!inQuote && counts[ch] !== undefined) counts[ch]++;
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
}

function parseCSVLine(line, delim) {
  const row = [];
  let inQuote = false;
  let cur = "";
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuote && line[i + 1] === '"') { cur += '"'; i++; }
      else inQuote = !inQuote;
    } else if (ch === delim && !inQuote) {
      row.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  row.push(cur.trim());
  return row;
}

function parseCSV(text) {
  if (!text || typeof text !== "string") return { headers: [], records: [] };
  // Strip BOM
  if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
  text = text.replace(/\\n/g, "\n").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = text.split("\n").filter(l => l.trim());
  if (lines.length < 2) return { headers: [], records: [] };

  const delim = detectDelimiter(lines[0]);
  const rawHeaders = parseCSVLine(lines[0], delim);
  const headers = rawHeaders
    .map(h => (h || "").replace(/^"|"$/g, "").trim())
    .filter(h => h);

  if (!headers.length) return { headers: [], records: [] };

  const records = [];
  const limit = Math.min(lines.length, 100001);
  for (let i = 1; i < limit; i++) {
    if (!lines[i].trim()) continue;
    const row = parseCSVLine(lines[i], delim);
    if (row.every(c => !c)) continue;
    const rec = {};
    headers.forEach((h, j) => { rec[h] = row[j] !== undefined ? row[j] : ""; });
    records.push(rec);
  }
  return { headers, records };
}

function parseJSONData(text) {
  try {
    const trimmed = text.trim();
    if (trimmed.startsWith("[")) {
      const arr = JSON.parse(trimmed);
      if (Array.isArray(arr) && arr.length > 0 && typeof arr[0] === "object") {
        const headers = Object.keys(arr[0]);
        const records = arr.slice(0, 100000).map(obj => {
          const rec = {};
          headers.forEach(h => { rec[h] = obj[h] != null ? String(obj[h]) : ""; });
          return rec;
        });
        return { headers, records };
      }
    }
  } catch { /* Fall through to CSV */ }
  return null;
}

function parseInput(text) {
  if (!text) return { headers: [], records: [] };
  const json = parseJSONData(text);
  if (json) return json;
  return parseCSV(text.slice(0, 10_000_000));
}

// ═══════════════════════════════════════════════════════
//  SCHEMA DETECTION
// ═══════════════════════════════════════════════════════

const COLUMN_ALIASES = {
  revenue: ["amount", "revenue", "sales", "price", "total", "final_amount", "sale_price",
    "total_amount", "grand_total", "net_amount", "value", "income", "earning", "payment",
    "invoice_amount", "order_value", "gmv", "transaction_amount", "subtotal", "unit_price",
    "mrr", "arr", "billing", "fee", "charge", "proceeds"],
  date: ["date", "timestamp", "created_at", "order_date", "transaction_date", "signup_date",
    "purchase_date", "time", "datetime", "created", "updated_at", "order_time", "sale_date",
    "invoice_date", "event_date", "date_time", "order_created", "period", "month", "year"],
  user_id: ["user_id", "customer_id", "cust_id", "client_id", "uid", "userid", "customerid",
    "buyer_id", "account_id", "member_id", "contact_id", "user", "customer", "sub_id"],
  email: ["email", "email_address", "user_email", "customer_email"],
  category: ["category", "type", "group", "department", "segment", "product_type", "item_type",
    "channel", "source", "product_category", "region", "country", "city", "brand",
    "vertical", "division", "subcategory", "industry", "market"],
  product: ["product", "product_name", "item", "item_name", "sku", "product_id", "description",
    "name", "title", "product_title", "item_description", "sku_id"],
  quantity: ["quantity", "qty", "units", "count", "volume", "items", "num_items", "pieces"],
  status: ["status", "state", "stage", "order_status", "payment_status", "txn_status"],
  cost: ["cost", "expenses", "cogs", "expenditure", "spending", "purchase_price", "buy_price"],
  profit: ["profit", "margin", "earnings", "net_income", "ebitda", "net_profit", "gross_profit"],
  channel: ["channel", "source", "medium", "campaign", "platform", "utm_source"],
  region: ["region", "country", "state", "city", "postcode", "zip", "location", "territory"]
};

function detectSchema(headers) {
  if (!headers || !headers.length) return {};
  const detected = {};
  const normalized = headers.map(h => h.toLowerCase().replace(/[^a-z0-9_]/g, "_"));
  for (const [role, aliases] of Object.entries(COLUMN_ALIASES)) {
    if (detected[role]) continue;
    for (let i = 0; i < normalized.length; i++) {
      const h = normalized[i];
      if (aliases.some(a =>
        h === a ||
        h.startsWith(a + "_") ||
        h.endsWith("_" + a) ||
        (a.length > 4 && h.includes(a))
      )) {
        detected[role] = headers[i];
        break;
      }
    }
  }
  return detected;
}

function inferDatasetType(detected, headers) {
  if (!headers || !headers.length) return "generic";
  const h = headers.join(" ").toLowerCase();
  if (h.includes("mrr") || h.includes("churn") || h.includes("arr") || h.includes("subscription")) return "saas";
  if (h.includes("salary") || h.includes("employee") || h.includes("attrition")) return "hr";
  if (h.includes("stock") || h.includes("ticker") || h.includes("dividend")) return "finance";
  if (h.includes("campaign") || h.includes("ctr") || h.includes("impression") || h.includes("roas")) return "marketing";
  if (h.includes("inventory") || h.includes("warehouse") || h.includes("shipment")) return "operations";
  if (detected.user_id && detected.revenue && detected.date) return "ecommerce";
  if (detected.revenue && detected.date) return "transactional";
  if (detected.revenue) return "revenue";
  return "generic";
}

// ═══════════════════════════════════════════════════════
//  DATA CLEANING
// ═══════════════════════════════════════════════════════

function cleanData(records, detected) {
  const issues = [];
  const rowsBefore = records.length;

  // Remove exact duplicates
  const seen = new Set();
  let cleaned = records.filter(row => {
    const fp = JSON.stringify(row);
    if (seen.has(fp)) return false;
    seen.add(fp);
    return true;
  });
  const dupsRemoved = rowsBefore - cleaned.length;
  if (dupsRemoved > 0) issues.push(`Removed ${dupsRemoved} exact duplicate rows`);

  // Parse revenue
  if (detected.revenue) {
    cleaned = cleaned.map(row => ({ ...row, _rev: safeNumber(row[detected.revenue]) }));
    const before = cleaned.length;
    cleaned = cleaned.filter(row => row._rev !== null);
    const dropped = before - cleaned.length;
    if (dropped > 0) issues.push(`Dropped ${dropped} rows with unparseable ${detected.revenue}`);
  } else {
    cleaned = cleaned.map(row => ({ ...row, _rev: null }));
  }

  // Parse dates — with future date detection
  if (detected.date) {
    cleaned = cleaned.map(row => ({ ...row, _date: safeDate(row[detected.date]) }));
    const before = cleaned.length;
    cleaned = cleaned.filter(row => row._date !== null);
    const dropped = before - cleaned.length;
    if (dropped > 0) issues.push(`Dropped ${dropped} rows with invalid or future dates`);
  } else {
    cleaned = cleaned.map(row => ({ ...row, _date: null }));
  }

  // Parse quantity
  if (detected.quantity) {
    cleaned = cleaned.map(row => ({ ...row, _qty: safeNumber(row[detected.quantity]) }));
  }

  // IQR outlier flagging
  if (detected.revenue) {
    const vals = cleaned.map(r => r._rev).filter(v => v !== null).sort((a, b) => a - b);
    if (vals.length >= 4) {
      const q1 = vals[Math.floor(vals.length * 0.25)];
      const q3 = vals[Math.floor(vals.length * 0.75)];
      const iqr = q3 - q1;
      const upper = q3 + 1.5 * iqr;
      const lower = q1 - 1.5 * iqr;
      const oCount = cleaned.filter(r => r._rev !== null && (r._rev < lower || r._rev > upper)).length;
      if (oCount > 0) issues.push(`Flagged ${oCount} IQR outliers (retained for analysis)`);
      cleaned = cleaned.map(row => ({
        ...row,
        _iqr_out: row._rev !== null && (row._rev < lower || row._rev > upper),
        _iqr_lower: lower,
        _iqr_upper: upper
      }));
    } else {
      cleaned = cleaned.map(row => ({ ...row, _iqr_out: false }));
    }
  }

  // Detect suspicious constant values (template paste detection)
  if (detected.revenue && cleaned.length >= 5) {
    const revVals = cleaned.map(r => r._rev).filter(v => v !== null);
    const uniqueVals = new Set(revVals);
    if (uniqueVals.size === 1) {
      issues.push(`WARNING: All ${revVals.length} revenue values are identical (${revVals[0]}) — possible template or test data`);
    } else if (uniqueVals.size < revVals.length * 0.05) {
      issues.push(`WARNING: Revenue has only ${uniqueVals.size} unique values across ${revVals.length} rows — data may be aggregated or artificial`);
    }
  }

  return {
    cleaned,
    dataQuality: {
      rows_before: rowsBefore,
      rows_after: cleaned.length,
      clean_rate: rowsBefore > 0 ? roundTo((cleaned.length / rowsBefore) * 100) : 100,
      issues,
      detected_cols: detected
    }
  };
}

// ═══════════════════════════════════════════════════════
//  STATISTICS ENGINE
// ═══════════════════════════════════════════════════════

function computeStats(arr) {
  if (!arr || !arr.length) return null;
  const filtered = arr.filter(v => v !== null && v !== undefined && isFinite(v));
  if (!filtered.length) return null;
  const s = [...filtered].sort((a, b) => a - b);
  const n = s.length;
  if (!n) return null;
  const sum = s.reduce((a, v) => a + v, 0);
  const mean = sum / n;
  const variance = s.reduce((a, v) => a + (v - mean) ** 2, 0) / n;
  const std = Math.sqrt(variance);
  const pct = p => {
    const idx = (p / 100) * (n - 1);
    const lo = Math.floor(idx);
    const hi = Math.ceil(idx);
    return s[lo] + (s[hi] - s[lo]) * (idx - lo);
  };
  let skew = 0;
  if (std > 0) {
    const m3 = s.reduce((a, v) => a + (v - mean) ** 3, 0) / n;
    skew = m3 / std ** 3;
  }
  return {
    n, sum: roundTo(sum), mean: roundTo(mean), median: roundTo(pct(50)),
    std: roundTo(std), variance: roundTo(variance), min: roundTo(s[0]),
    max: roundTo(s[n - 1]), skew: roundTo(skew, 3),
    p5: roundTo(pct(5)), p10: roundTo(pct(10)), p25: roundTo(pct(25)),
    p75: roundTo(pct(75)), p90: roundTo(pct(90)), p95: roundTo(pct(95)),
    p99: roundTo(pct(99))
  };
}

function computeLinearRegression(pts) {
  const n = pts.length;
  if (n < 2) return { slope: 0, intercept: 0, r2: 0, usable: false };
  let sx = 0, sy = 0, sxy = 0, sx2 = 0, sy2 = 0;
  pts.forEach((p, i) => { sx += i; sy += p; sxy += i * p; sx2 += i * i; sy2 += p * p; });
  const denom = n * sx2 - sx * sx;
  if (denom === 0) return { slope: 0, intercept: sy / n, r2: 0, usable: false };
  const slope = (n * sxy - sx * sy) / denom;
  const intercept = (sy - slope * sx) / n;
  const r2denom = (n * sy2 - sy * sy);
  const r2 = r2denom === 0 ? 0 : Math.pow((n * sxy - sx * sy), 2) / ((n * sx2 - sx * sx) * r2denom);
  return {
    slope: isFinite(slope) ? roundTo(slope) : 0,
    intercept: isFinite(intercept) ? roundTo(intercept) : 0,
    r2: isFinite(r2) ? roundTo(r2, 4) : 0,
    usable: isFinite(r2) && r2 >= THRESHOLDS.MIN_R2_FOR_LINEAR_FORECAST
  };
}

function computeCorrelation(arr1, arr2) {
  if (!arr1 || !arr2) return 0;
  const n = arr1.length;
  if (n < 2 || n !== arr2.length) return 0;
  // Filter out non-finite values
  const pairs = arr1.map((v, i) => [v, arr2[i]]).filter(([a, b]) => isFinite(a) && isFinite(b));
  if (pairs.length < 2) return 0;
  const a1 = pairs.map(p => p[0]), a2 = pairs.map(p => p[1]);
  arr1 = a1; arr2 = a2;
  const m1 = arr1.reduce((a, b) => a + b, 0) / n;
  const m2 = arr2.reduce((a, b) => a + b, 0) / n;
  let num = 0, d1 = 0, d2 = 0;
  for (let i = 0; i < n; i++) {
    const diff1 = arr1[i] - m1;
    const diff2 = arr2[i] - m2;
    num += diff1 * diff2;
    d1 += diff1 ** 2;
    d2 += diff2 ** 2;
  }
  return d1 * d2 === 0 ? 0 : roundTo(num / Math.sqrt(d1 * d2), 4);
}

// ═══════════════════════════════════════════════════════
//  JUDGMENT ENGINE — deterministic analysis of data quality
//  This is the core of the v15 architecture.
//  Nothing delegated to the LLM that can be decided here.
// ═══════════════════════════════════════════════════════

function runJudgmentEngine(cleaned, detected, dataQuality, n) {
  const judgment = {
    // What kind of analysis is permissible
    permissions: {
      canShowPatterns: n >= THRESHOLDS.MIN_ROWS_FOR_PATTERNS,
      canShowTrends: false, // Determined after temporal check
      canShowSeasonal: false,
      canForecast: false,
      canShowCategories: false,
      canShowUserAnalysis: false,
      canShowStatistical: n >= THRESHOLDS.MIN_ROWS_FOR_PATTERNS,
      canShowRecommendations: false, // Requires findings first
      fullAnalysis: n >= THRESHOLDS.MIN_ROWS_FOR_FULL
    },

    // Data quality verdict
    qualityVerdict: "CLEAN",
    qualityBlocksAnalysis: false,
    qualityWarnings: [],

    // Metric distortion flags
    distortions: [],

    // Contradiction flags
    contradictions: [],

    // Dominance flags (concentration risk)
    dominance: null,

    // Temporal quality
    temporalQuality: {
      dataPoints: 0,
      frequency: "unknown",
      hasSufficientForTrend: false,
      hasSufficientForSeasonal: false,
      hasSufficientForForecast: false,
      isLinearFit: false,
      r2: 0,
      trendConcentrated: false, // Trend driven by one outlier period
      trendConcentratedPeriod: null
    },

    // Skewness impact
    skewnessFlag: null,

    // Anomaly density
    anomalyDensityFlag: null,

    // Overall analysis tier
    analysisTier: "FACTS_ONLY", // FACTS_ONLY | DIRECTIONAL | STANDARD | FULL

    // What the LLM must say at the top (mandatory injections)
    mandatoryPreamble: [],

    // Findings ranked by materiality (deterministic)
    rankedFindings: []
  };

  // ── TIER DETERMINATION ───────────────────────────────
  if (n >= THRESHOLDS.MIN_ROWS_FOR_FULL) judgment.analysisTier = "FULL";
  else if (n >= THRESHOLDS.MIN_ROWS_FOR_STANDARD) judgment.analysisTier = "STANDARD";
  else if (n >= THRESHOLDS.MIN_ROWS_FOR_PATTERNS) judgment.analysisTier = "DIRECTIONAL";
  else judgment.analysisTier = "FACTS_ONLY";

  // ── DATA QUALITY CHECK ───────────────────────────────
  const cr = dataQuality.clean_rate;
  if (cr < THRESHOLDS.MIN_CLEAN_RATE_HARD_REFUSE) {
    judgment.qualityVerdict = "CRITICAL";
    judgment.qualityBlocksAnalysis = true;
    judgment.mandatoryPreamble.push(
      `DATA INTEGRITY CRITICAL: Only ${cr}% of rows passed quality checks ` +
      `(${dataQuality.rows_after} of ${dataQuality.rows_before} usable). ` +
      `Analysis is not reliable. A minimum of ${THRESHOLDS.MIN_CLEAN_RATE_FOR_ANALYSIS}% ` +
      `clean data is required for downstream conclusions. ` +
      `Issues: ${dataQuality.issues.join("; ")}`
    );
  } else if (cr < THRESHOLDS.MIN_CLEAN_RATE_FOR_ANALYSIS) {
    judgment.qualityVerdict = "DEGRADED";
    judgment.qualityWarnings.push(
      `${100 - cr}% of rows were excluded during cleaning. ` +
      `All metrics reflect only the ${cr}% that passed validation and may not represent the full dataset.`
    );
    judgment.mandatoryPreamble.push(
      `DATA QUALITY WARNING: ${dataQuality.rows_before - dataQuality.rows_after} of ` +
      `${dataQuality.rows_before} rows excluded. ` +
      `Metrics below reflect ${cr}% of original data.`
    );
  }

  // ── ANOMALY DENSITY CHECK ────────────────────────────
  if (cleaned && cleaned.length > 0) {
    const anomalyDensity = (cleaned.filter(r => r && r._iqr_out).length / cleaned.length) * 100;
    if (anomalyDensity > THRESHOLDS.MAX_ANOMALY_DENSITY_PCT) {
      judgment.anomalyDensityFlag = {
        density: roundTo(anomalyDensity),
        count: cleaned.filter(r => r._iqr_out).length
      };
      judgment.mandatoryPreamble.push(
        `ANOMALY DENSITY ALERT: ${roundTo(anomalyDensity)}% of rows are statistical outliers ` +
        `(${cleaned.filter(r => r._iqr_out).length} of ${cleaned.length} rows). ` +
        `This density indicates a structural data issue, not normal business variation. ` +
        `Summary metrics are unreliable until this is investigated.`
      );
    }
  }

  // ── SKEWNESS CHECK ───────────────────────────────────
  if (detected.revenue && cleaned.length >= 10) {
    const vals = cleaned.map(r => r._rev).filter(v => v !== null);
    const stats = computeStats(vals);
    if (stats && Math.abs(stats.skew) > THRESHOLDS.SKEW_DISTORTION_THRESHOLD) {
      const withoutTop = vals.filter(v => v <= stats.p95);
      const statsWithout = computeStats(withoutTop);
      judgment.skewnessFlag = {
        skew: stats.skew,
        mean: stats.mean,
        median: stats.median,
        meanWithoutTop5Pct: statsWithout ? statsWithout.mean : null,
        direction: stats.skew > 0 ? "right" : "left"
      };
      judgment.distortions.push({
        type: "SKEW_DISTORTION",
        metric: detected.revenue,
        detail: `Mean (${formatIndian(stats.mean)}) is ${stats.skew > 0 ? "inflated" : "deflated"} by extreme values. ` +
          `Median (${formatIndian(stats.median)}) is the representative figure. ` +
          `Excluding top 5% of transactions, mean drops to ${formatIndian(statsWithout?.mean)}.`,
        severity: "HIGH"
      });
    }
  }

  // ── OUTLIER DISTORTION CHECK ─────────────────────────
  if (detected.revenue && cleaned.length >= 10) {
    const vals = cleaned.map(r => r._rev).filter(v => v !== null);
    const stats = computeStats(vals);
    if (stats) {
      const withOutliers = stats.sum;
      const withoutOutliers = vals
        .filter(v => !cleaned.find(r => r._rev === v && r._iqr_out))
        .reduce((a, b) => a + b, 0);
      const diff = withOutliers - withoutOutliers;
      if (Math.abs(diff) / Math.abs(withOutliers) > THRESHOLDS.OUTLIER_DISTORTION_THRESHOLD) {
        judgment.distortions.push({
          type: "OUTLIER_TOTAL_DISTORTION",
          metric: "total_revenue",
          withOutliers: roundTo(withOutliers),
          withoutOutliers: roundTo(withoutOutliers),
          difference: roundTo(diff),
          pctImpact: roundTo(Math.abs(diff) / Math.abs(withOutliers) * 100),
          detail: `Total revenue including outliers: ${formatIndian(withOutliers)}. ` +
            `Excluding IQR outliers: ${formatIndian(withoutOutliers)}. ` +
            `Outliers account for ${roundTo(Math.abs(diff) / Math.abs(withOutliers) * 100)}% of reported total.`,
          severity: "HIGH"
        });
      }
    }
  }

  // ── TEMPORAL QUALITY CHECK ───────────────────────────
  if (detected.date) {
    const dailyMap = {};
    cleaned.forEach(row => {
      if (!row._date) return;
      const dk = row._date.toISOString().slice(0, 10);
      dailyMap[dk] = (dailyMap[dk] || 0) + (row._rev || 1);
    });
    const trend = Object.entries(dailyMap).sort((a, b) => a[0].localeCompare(b[0]));
    const dp = trend.length;
    judgment.temporalQuality.dataPoints = dp;

    if (dp >= 2) {
      const diffs = [];
      for (let i = 1; i < trend.length; i++) {
        diffs.push(new Date(trend[i][0]) - new Date(trend[i - 1][0]));
      }
      const avgDiff = diffs.reduce((a, b) => a + b, 0) / diffs.length;
      judgment.temporalQuality.frequency =
        avgDiff < 1.5 * 86400000 ? "daily" :
        avgDiff < 8 * 86400000 ? "weekly" : "monthly";
    }

    judgment.temporalQuality.hasSufficientForTrend = dp >= THRESHOLDS.MIN_ROWS_FOR_TRENDS;
    judgment.temporalQuality.hasSufficientForSeasonal = dp >= THRESHOLDS.MIN_ROWS_FOR_SEASONAL;
    judgment.temporalQuality.hasSufficientForForecast = dp >= THRESHOLDS.MIN_ROWS_FOR_FORECAST;

    if (judgment.temporalQuality.hasSufficientForTrend) {
      judgment.permissions.canShowTrends = true;
      const reg = computeLinearRegression(trend.map(d => d[1]));
      judgment.temporalQuality.r2 = reg.r2;
      judgment.temporalQuality.isLinearFit = reg.usable;

      // Check if trend is driven by one period
      if (trend.length >= 3) {
        const vals = trend.map(d => d[1]);
        const trendStats = computeStats(vals);
        if (trendStats) {
          const maxVal = Math.max(...vals);
          const maxIdx = vals.indexOf(maxVal);
          const withoutMax = vals.filter((_, i) => i !== maxIdx);
          const withoutStats = computeStats(withoutMax);
          if (withoutStats && trendStats.mean > 0) {
            const impact = (maxVal - trendStats.mean) / trendStats.mean;
            if (impact > 1.5) { // Max period is 2.5x the mean
              judgment.temporalQuality.trendConcentrated = true;
              judgment.temporalQuality.trendConcentratedPeriod = trend[maxIdx][0];
              judgment.distortions.push({
                type: "TREND_CONCENTRATION",
                period: trend[maxIdx][0],
                value: roundTo(maxVal),
                baseline: roundTo(withoutStats.mean),
                detail: `The apparent trend is driven by a single period (${trend[maxIdx][0]}: ${formatIndian(maxVal)}) ` +
                  `which is ${roundTo(impact * 100)}% above the ${formatIndian(withoutStats.mean)} baseline. ` +
                  `Excluding this period, the trend changes significantly.`,
                severity: "HIGH"
              });
            }
          }
        }
      }
    }

    if (judgment.temporalQuality.hasSufficientForForecast && judgment.temporalQuality.isLinearFit) {
      judgment.permissions.canForecast = true;
    }
  }

  // ── CATEGORY PERMISSIONS ─────────────────────────────
  if (detected.category) {
    const catMap = {};
    cleaned.forEach(r => {
      const cat = r[detected.category];
      if (cat) catMap[cat] = (catMap[cat] || 0) + 1;
    });
    const validCats = Object.values(catMap).filter(c => c >= THRESHOLDS.MIN_CATEGORY_INSTANCES);
    if (validCats.length >= 2) judgment.permissions.canShowCategories = true;
  }

  // ── USER ANALYSIS PERMISSIONS ────────────────────────
  const uCol = detected.user_id || detected.email;
  if (uCol && cleaned.length >= 20) {
    judgment.permissions.canShowUserAnalysis = true;
  }

  // ── CONCENTRATION CHECK ──────────────────────────────
  if (detected.category && detected.revenue && cleaned.length >= 10) {
    const catRevMap = {};
    const totalRev = cleaned.reduce((s, r) => s + (r._rev || 0), 0);
    cleaned.forEach(r => {
      const cat = r[detected.category];
      if (cat) catRevMap[cat] = (catRevMap[cat] || 0) + (r._rev || 0);
    });
    const topCat = Object.entries(catRevMap).sort((a, b) => b[1] - a[1])[0];
    if (topCat && totalRev > 0) {
      const topPct = (topCat[1] / totalRev) * 100;
      if (topPct > THRESHOLDS.CONCENTRATION_DOMINANCE_PCT) {
        judgment.dominance = {
          type: "CATEGORY_CONCENTRATION",
          category: topCat[0],
          pct: roundTo(topPct),
          value: roundTo(topCat[1]),
          detail: `${topCat[0]} accounts for ${roundTo(topPct)}% of total revenue. ` +
            `This concentration creates single-point-of-failure risk.`
        };
      }
    }
  }

  // ── CONTRADICTION DETECTION ──────────────────────────
  if (detected.revenue && detected.quantity && cleaned.length >= 10) {
    const revVals = cleaned.map(r => r._rev).filter(v => v !== null);
    const qtyVals = cleaned.map(r => r._qty).filter(v => v !== null);
    if (revVals.length >= 5 && qtyVals.length >= 5) {
      const revStats = computeStats(revVals);
      const qtyStats = computeStats(qtyVals);
      if (revStats && qtyStats) {
        // If revenue is growing but quantity is flat or falling — price inflation masking volume issue
        // We detect this via trend direction if date is available
        if (detected.date && judgment.temporalQuality.hasSufficientForTrend) {
          const revByDate = {};
          const qtyByDate = {};
          cleaned.forEach(r => {
            if (!r._date) return;
            const dk = r._date.toISOString().slice(0, 7);
            revByDate[dk] = (revByDate[dk] || 0) + (r._rev || 0);
            qtyByDate[dk] = (qtyByDate[dk] || 0) + (r._qty || 0);
          });
          const periods = Object.keys(revByDate).sort();
          if (periods.length >= 4) {
            const revPts = periods.map(p => revByDate[p]);
            const qtyPts = periods.map(p => qtyByDate[p] || 0);
            const revReg = computeLinearRegression(revPts);
            const qtyReg = computeLinearRegression(qtyPts);
            if (revReg.slope > 0 && qtyReg.slope < 0) {
              judgment.contradictions.push({
                type: "REVENUE_UP_VOLUME_DOWN",
                detail: `Revenue trend is positive (slope: ${roundTo(revReg.slope, 0)}/period) ` +
                  `while transaction volume trend is negative (slope: ${roundTo(qtyReg.slope, 0)}/period). ` +
                  `This pattern indicates price inflation masking volume decline — ` +
                  `a warning sign that top-line growth is not sustainable.`,
                severity: "HIGH",
                implication: "Revenue may fall sharply if pricing power is lost or price-sensitive customers churn"
              });
            }
          }
        }
      }
    }
  }

  // ── PERMISSIONS FINAL GATE ───────────────────────────
  if (judgment.qualityBlocksAnalysis) {
    judgment.permissions = Object.fromEntries(
      Object.keys(judgment.permissions).map(k => [k, false])
    );
  }

  return judgment;
}

// ═══════════════════════════════════════════════════════
//  METRICS ENGINE
// ═══════════════════════════════════════════════════════

function computeMetrics(cleaned, detected, headers, judgment) {
  const m = {
    revenue: null, orders: cleaned.length, aov: null, median_order: null,
    unique_users: null, repeat_rate: null, growth: null, cagr: null,
    revenue_trend: [], monthly_trend: [], day_of_week: [],
    category_breakdown: [], top_products: [], revenue_stats: null,
    pareto_concentration: null, correlations: {}, forecast: [],
    forecast_usable: false, frequency: judgment.temporalQuality.frequency,
    // Outlier-adjusted versions
    revenue_excluding_outliers: null,
    aov_excluding_outliers: null
  };

  // Revenue stats
  if (detected.revenue) {
    const vals = cleaned.map(r => r._rev).filter(v => v !== null && isFinite(v));
    const s = computeStats(vals);
    if (s) {
      m.revenue = s.sum;
      m.revenue_stats = s;
      m.aov = cleaned.length > 0 ? roundTo(s.sum / cleaned.length) : 0;
      m.median_order = s.median;
    }

    // Outlier-adjusted metrics
    const cleanVals = cleaned.filter(r => !r._iqr_out).map(r => r._rev).filter(v => v !== null);
    if (cleanVals.length > 0) {
      m.revenue_excluding_outliers = roundTo(cleanVals.reduce((a, b) => a + b, 0));
      m.aov_excluding_outliers = roundTo(m.revenue_excluding_outliers / cleanVals.length);
    }
  }

  // Temporal metrics
  if (detected.date && judgment.temporalQuality.hasSufficientForTrend) {
    const dailyMap = {}, monthlyMap = {};
    const DOW = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const dowMap = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0 };
    const dowCount = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0 };

    cleaned.forEach(row => {
      if (!row._date) return;
      const dk = row._date.toISOString().slice(0, 10);
      const mk = row._date.toISOString().slice(0, 7);
      const dow = row._date.getDay();
      const rev = detected.revenue ? (row._rev || 0) : 1;
      dailyMap[dk] = (dailyMap[dk] || 0) + rev;
      monthlyMap[mk] = (monthlyMap[mk] || 0) + rev;
      dowMap[dow] += rev;
      dowCount[dow]++;
    });

    m.revenue_trend = Object.entries(dailyMap)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([name, val]) => ({ name, val: roundTo(val) }));

    m.monthly_trend = Object.entries(monthlyMap)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([name, val]) => ({ name, val: roundTo(val) }));

    m.day_of_week = DOW.map((name, i) => ({
      name, val: roundTo(dowMap[i]), count: dowCount[i]
    }));

    // Growth metrics
    const trend = m.revenue_trend;
    if (trend.length >= 2) {
      const last = trend[trend.length - 1].val;
      const first = trend[0].val;
      if (first > 0 && trend.length > 30) {
        m.cagr = roundTo((Math.pow(last / first, 365 / trend.length) - 1) * 100);
      }
      if (trend.length >= 14) {
        const l7 = trend.slice(-7).reduce((s, d) => s + d.val, 0);
        const p7 = trend.slice(-14, -7).reduce((s, d) => s + d.val, 0);
        m.growth = p7 > 0 ? roundTo(((l7 - p7) / p7) * 100) : null;
      }
    }

    // Forecast — only if judgment permits
    if (judgment.permissions.canForecast && m.revenue_trend.length >= THRESHOLDS.MIN_ROWS_FOR_FORECAST) {
      const reg = computeLinearRegression(m.revenue_trend.map(d => d.val));
      if (reg.usable) {
        m.forecast_usable = true;
        for (let i = 1; i <= 3; i++) {
          m.forecast.push({
            name: `Period +${i}`,
            val: roundTo(Math.max(0, reg.slope * (m.revenue_trend.length + i) + reg.intercept)),
            r2: reg.r2
          });
        }
      }
    }
  }

  // User metrics
  const uCol = detected.user_id || detected.email;
  if (uCol && judgment.permissions.canShowUserAnalysis) {
    const uMap = {};
    cleaned.forEach(row => {
      const u = row[uCol];
      if (u) uMap[u] = (uMap[u] || 0) + 1;
    });
    const uArr = Object.values(uMap);
    m.unique_users = uArr.length;
    m.repeat_rate = m.unique_users > 0
      ? roundTo((uArr.filter(c => c > 1).length / m.unique_users) * 100)
      : 0;

    if (detected.revenue) {
      const uRevMap = {};
      cleaned.forEach(row => {
        const u = row[uCol];
        if (u) uRevMap[u] = (uRevMap[u] || 0) + (row._rev || 0);
      });
      const revVals = Object.values(uRevMap).sort((a, b) => b - a);
      const top20 = Math.max(1, Math.floor(revVals.length * 0.2));
      const tot = revVals.reduce((s, v) => s + v, 0);
      m.pareto_concentration = tot > 0
        ? roundTo((revVals.slice(0, top20).reduce((s, v) => s + v, 0) / tot) * 100)
        : null;
    }
  }

  // Category breakdown
  if (detected.category && judgment.permissions.canShowCategories) {
    const catMap = {}, catRevMap = {};
    cleaned.forEach(row => {
      const cat = row[detected.category] || "Unknown";
      catMap[cat] = (catMap[cat] || 0) + 1;
      catRevMap[cat] = (catRevMap[cat] || 0) + (row._rev || 0);
    });
    m.category_breakdown = Object.entries(catRevMap)
      .filter(([, v]) => catMap[Object.keys(catRevMap).find(k => catRevMap[k] === v)] >= THRESHOLDS.MIN_CATEGORY_INSTANCES)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 12)
      .map(([name, val]) => ({ name, val: roundTo(val), count: catMap[name] }));
  }

  // Product breakdown
  if (detected.product) {
    const pMap = {}, pRevMap = {};
    cleaned.forEach(row => {
      const p = row[detected.product] || "Unknown";
      pMap[p] = (pMap[p] || 0) + 1;
      pRevMap[p] = (pRevMap[p] || 0) + (row._rev || 0);
    });
    m.top_products = Object.entries(pRevMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, val]) => ({ name, val: roundTo(val), orders: pMap[name] }));
  }

  return m;
}

// ═══════════════════════════════════════════════════════
//  ANOMALY ENGINE
// ═══════════════════════════════════════════════════════

function detectAnomalies(cleaned, detected) {
  const anomalies = [];
  const vals = detected.revenue
    ? cleaned.map(r => r._rev).filter(v => v !== null && isFinite(v))
    : [];

  // 1. Negative values
  const negs = cleaned.filter(r => (r._rev !== null && r._rev < 0) || (r._qty !== null && r._qty < 0));
  if (negs.length) {
    anomalies.push({
      type: "NEGATIVE_VALUES", severity: "HIGH", value: negs.length,
      impact: roundTo(Math.abs(negs.reduce((s, r) => s + (r._rev || 0), 0))),
      reason: `${negs.length} transactions with negative values — likely refunds, reversals, or data entry errors`,
      falsifiability: "Check source system for refund/reversal codes. If no such codes exist, this is a data entry error."
    });
  }

  // 2. Z-score outliers
  if (vals.length >= 10) {
    const mean = vals.reduce((s, v) => s + v, 0) / vals.length;
    const std = Math.sqrt(vals.reduce((s, v) => s + (v - mean) ** 2, 0) / vals.length);
    if (std > 0) {
      const outliers = cleaned.filter(r => r._rev !== null && Math.abs((r._rev - mean) / std) > 3.5);
      if (outliers.length) {
        anomalies.push({
          type: "STATISTICAL_OUTLIER", severity: "MEDIUM", value: outliers.length,
          impact: roundTo(outliers.reduce((s, r) => s + (r._rev || 0), 0)),
          reason: `${outliers.length} transactions with Z-score >3.5σ — extreme deviations from the distribution`,
          falsifiability: "Verify in source system whether these represent legitimate high-value transactions or data errors."
        });
      }
    }
  }

  // 3. IQR outliers
  const iqrOuts = cleaned.filter(r => r._iqr_out);
  if (iqrOuts.length > 0 && iqrOuts.length < cleaned.length * 0.05) {
    anomalies.push({
      type: "IQR_OUTLIER", severity: "LOW", value: iqrOuts.length,
      impact: roundTo(iqrOuts.reduce((s, r) => s + (r._rev || 0), 0)),
      reason: `${iqrOuts.length} transactions outside 1.5×IQR — significant but non-extreme`,
      falsifiability: "Review individually to classify as legitimate high/low value transactions or errors."
    });
  }

  // 4. Revenue spikes/drops
  if (detected.date && vals.length >= 7) {
    const dailyMap = {};
    cleaned.forEach(r => {
      if (!r._date || r._rev === null) return;
      const k = r._date.toISOString().slice(0, 10);
      dailyMap[k] = (dailyMap[k] || 0) + r._rev;
    });
    const dVals = Object.values(dailyMap);
    if (dVals.length >= 5) {
      const dmean = dVals.reduce((s, v) => s + v, 0) / dVals.length;
      const dstd = Math.sqrt(dVals.reduce((s, v) => s + (v - dmean) ** 2, 0) / dVals.length);
      if (dstd > 0) {
        const spikes = Object.entries(dailyMap).filter(([, v]) => Math.abs((v - dmean) / dstd) > 2.5);
        if (spikes.length) {
          const top = spikes.sort((a, b) => Math.abs(b[1] - dmean) - Math.abs(a[1] - dmean))[0];
          anomalies.push({
            type: top[1] > dmean ? "REVENUE_SPIKE" : "REVENUE_DROP",
            severity: "MEDIUM", value: roundTo(top[1]),
            impact: roundTo(Math.abs(top[1] - dmean)),
            reason: `${top[0]}: ${top[1] > dmean ? "spike" : "drop"} of ${formatIndian(Math.abs(top[1] - dmean))} vs daily average of ${formatIndian(dmean)}`,
            falsifiability: `Check ${top[0]} in source system for: bulk orders, system errors, promotional events, or data duplication.`
          });
        }
      }
    }
  }

  // 5. Suspicious transaction frequency
  const uCol = detected.user_id || detected.email;
  if (uCol && detected.date) {
    const byUser = {};
    cleaned.forEach(r => {
      if (!r[uCol] || !r._date) return;
      const u = r[uCol];
      if (!byUser[u]) byUser[u] = [];
      byUser[u].push(r._date.getTime());
    });
    let rapidPairs = 0;
    for (const times of Object.values(byUser)) {
      times.sort((a, b) => a - b);
      for (let i = 1; i < times.length; i++) {
        if (times[i] - times[i - 1] < 60000) rapidPairs++;
      }
    }
    if (rapidPairs > 0) {
      anomalies.push({
        type: "SUSPICIOUS_FREQUENCY", severity: "HIGH", value: rapidPairs, impact: 0,
        reason: `${rapidPairs} transaction pairs within 60 seconds from the same user — possible bot activity or double-charge`,
        falsifiability: "Verify in payment processor logs whether these resulted in duplicate charges to customers."
      });
    }
  }

  // 6. Zero value transactions
  const zeros = cleaned.filter(r => r._rev === 0).length;
  if (zeros > cleaned.length * 0.05) {
    anomalies.push({
      type: "ZERO_VALUE_TRANSACTIONS", severity: "LOW", value: zeros, impact: 0,
      reason: `${zeros} zero-value transactions (${roundTo(zeros / cleaned.length * 100)}%) — verify if deliberate promotions or data errors`,
      falsifiability: "Check whether these correspond to free tiers, 100% discounts, or data entry errors in the source system."
    });
  }

  // 7. Duplicate transaction signatures
  let dups = 0;
  const dSet = new Set();
  cleaned.forEach(row => {
    const k = uCol
      ? `${row[uCol]}|${row._rev}|${row._date?.toISOString().slice(0, 10)}`
      : `${row._rev}|${row._date?.toISOString().slice(0, 16)}`;
    if (dSet.has(k)) dups++;
    else dSet.add(k);
  });
  if (dups > 0) {
    anomalies.push({
      type: "DUPLICATE_TRANSACTIONS", severity: "MEDIUM", value: dups, impact: 0,
      reason: `${dups} possible duplicate signatures (same user, amount, and date)`,
      falsifiability: "Cross-reference transaction IDs in the source system to confirm whether these are duplicates or legitimate same-day repeat purchases."
    });
  }

  // 8. Data gaps
  if (detected.date && cleaned.length > 10) {
    const sortedDates = cleaned.map(r => r._date).filter(Boolean).sort((a, b) => a - b);
    let maxGap = 0;
    for (let i = 1; i < sortedDates.length; i++) {
      const gap = sortedDates[i] - sortedDates[i - 1];
      if (gap > maxGap) maxGap = gap;
    }
    const totalSpan = sortedDates[sortedDates.length - 1] - sortedDates[0];
    const expectedGap = totalSpan / cleaned.length;
    if (maxGap > 3 * 86400000 && maxGap > expectedGap * 10) {
      anomalies.push({
        type: "DATA_GAP", severity: "LOW",
        value: roundTo(maxGap / 86400000, 1), impact: 0,
        reason: `${roundTo(maxGap / 86400000, 1)}-day gap in data — check for tracking outage or data collection failure`,
        falsifiability: "Verify whether transactions occurred during this gap period but were not captured."
      });
    }
  }

  // Deduplicate overlapping anomaly types
  const seenTypes = new Set();
  const deduped = anomalies.filter(a => {
    const key = a.type;
    if (seenTypes.has(key) && a.severity !== 'HIGH') return false;
    seenTypes.add(key);
    return true;
  });
  // Sort HIGH first, then by impact
  const sevOrd = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  deduped.sort((a, b) => (sevOrd[a.severity] || 2) - (sevOrd[b.severity] || 2) || (b.impact || 0) - (a.impact || 0));
  const totalImpact = roundTo(deduped.reduce((s, a) => s + (a.impact || 0), 0));
  const highCount = deduped.filter(a => a.severity === 'HIGH').length;
  return { anomalies: deduped.slice(0, 15), count: deduped.length, highCount, totalImpact };
}

// ═══════════════════════════════════════════════════════
//  COHORT ENGINE
// ═══════════════════════════════════════════════════════

function computeCohorts(cleaned, detected) {
  const uCol = detected.user_id || detected.email;
  if (!uCol || !detected.date) return null;

  const firstSeen = {};
  cleaned.forEach(row => {
    if (!row._date || !row[uCol]) return;
    const u = row[uCol];
    if (!firstSeen[u] || row._date < firstSeen[u]) firstSeen[u] = row._date;
  });

  const matrix = {}, cohortSizes = {};
  cleaned.forEach(row => {
    if (!row._date || !row[uCol]) return;
    const u = row[uCol];
    if (!firstSeen[u]) return;
    const cohort = firstSeen[u].toISOString().slice(0, 7);
    const order = row._date.toISOString().slice(0, 7);
    const period = Math.round(
      (new Date(order + "-01") - new Date(cohort + "-01")) / (30 * 86400000)
    );
    if (period < 0 || period > 11) return;
    if (!matrix[cohort]) matrix[cohort] = {};
    if (!matrix[cohort][period]) matrix[cohort][period] = new Set();
    matrix[cohort][period].add(u);
  });

  const retention = {};
  for (const cohort of Object.keys(matrix).sort()) {
    const size = matrix[cohort][0]?.size || 0;
    if (size < 3) continue;
    cohortSizes[cohort] = size;
    retention[cohort] = {};
    for (let p = 0; p <= 11; p++) {
      retention[cohort][p] = roundTo((matrix[cohort][p]?.size || 0) / size * 100);
    }
  }

  return Object.keys(retention).length >= 2
    ? { retention_matrix: retention, cohort_sizes: cohortSizes }
    : null;
}

// ═══════════════════════════════════════════════════════
//  MATERIALITY RANKER — deterministic, not LLM
//  This is the heart of the v15 judgment architecture.
//  Findings are ranked by (impact × reliability).
//  The LLM receives ranked findings, not raw data.
// ═══════════════════════════════════════════════════════

function rankFindings(metrics, anomalyResult, judgment, detected, dataQuality) {
  const findings = [];

  // ── Anomalies by financial impact ───────────────────
  for (const anom of anomalyResult.anomalies) {
    if (anom.severity === "HIGH" || anom.impact > 0) {
      findings.push({
        type: "ANOMALY",
        subtype: anom.type,
        magnitude: anom.impact || (anom.value * (metrics.aov || 0)),
        reliability: anom.severity === "HIGH" ? "HIGH" :
          anom.severity === "MEDIUM" ? "MEDIUM" : "LOW",
        detail: anom.reason,
        falsifiability: anom.falsifiability,
        actionable: anom.severity !== "LOW"
      });
    }
  }

  // ── Contradictions ───────────────────────────────────
  for (const contradiction of judgment.contradictions) {
    findings.push({
      type: "CONTRADICTION",
      subtype: contradiction.type,
      magnitude: metrics.revenue || 0,
      reliability: "HIGH", // Contradictions are deterministically computed
      detail: contradiction.detail,
      implication: contradiction.implication,
      falsifiability: "Resolve by tracking transaction count and revenue separately over the next 30 days.",
      actionable: true
    });
  }

  // ── Distortions ──────────────────────────────────────
  for (const distortion of judgment.distortions) {
    if (distortion.severity === "HIGH") {
      findings.push({
        type: "DISTORTION",
        subtype: distortion.type,
        magnitude: distortion.difference || (metrics.revenue || 0) * 0.2,
        reliability: "HIGH",
        detail: distortion.detail,
        falsifiability: "Verified by comparing inclusive vs exclusive outlier calculations.",
        actionable: false // Distortions inform interpretation, not action
      });
    }
  }

  // ── Concentration risk ───────────────────────────────
  if (judgment.dominance) {
    findings.push({
      type: "CONCENTRATION_RISK",
      subtype: judgment.dominance.type,
      magnitude: (judgment.dominance.value || 0) * 0.3, // Risk = loss if this fails
      reliability: "HIGH",
      detail: judgment.dominance.detail,
      falsifiability: "Monitor revenue when this category experiences a 10% volume drop.",
      actionable: true
    });
  }

  // ── Trend findings ───────────────────────────────────
  if (judgment.temporalQuality.hasSufficientForTrend && metrics.growth !== null) {
    const absGrowth = Math.abs(metrics.growth);
    if (absGrowth > 5) { // Only material growth/decline
      findings.push({
        type: "TREND",
        subtype: metrics.growth > 0 ? "GROWTH" : "DECLINE",
        magnitude: Math.abs(metrics.revenue || 0) * (absGrowth / 100),
        reliability: judgment.temporalQuality.trendConcentrated ? "LOW" : "MEDIUM",
        detail: `${metrics.growth > 0 ? "+" : ""}${metrics.growth}% week-over-week revenue change` +
          (judgment.temporalQuality.trendConcentrated
            ? ` — NOTE: this trend is concentrated in the period ${judgment.temporalQuality.trendConcentratedPeriod} and may not represent sustained change`
            : ""),
        falsifiability: `If this trend is real, the pattern should persist in next week's data. A reversal would indicate a one-time event.`,
        actionable: absGrowth > 15
      });
    }
  }

  // ── Repeat customer finding ──────────────────────────
  if (metrics.repeat_rate !== null && metrics.unique_users !== null) {
    const benchmarkRepeat = 30; // Minimum healthy repeat rate
    if (metrics.repeat_rate < benchmarkRepeat) {
      findings.push({
        type: "RETENTION",
        subtype: "LOW_REPEAT_RATE",
        magnitude: metrics.revenue ? metrics.revenue * ((benchmarkRepeat - metrics.repeat_rate) / 100) : 0,
        reliability: "MEDIUM",
        detail: `${metrics.repeat_rate}% repeat purchase rate against a ${benchmarkRepeat}% benchmark. ` +
          `${metrics.unique_users - Math.round(metrics.unique_users * metrics.repeat_rate / 100)} customers have purchased only once.`,
        falsifiability: "Track repeat rate monthly. A rising trend confirms acquisition is working but retention needs investment.",
        actionable: true
      });
    }
  }

  // Assign urgency and composite score
  const urgencyMap = { ANOMALY_HIGH: 'HIGH', CONTRADICTION: 'HIGH', CONCENTRATION_RISK: 'MEDIUM', RETENTION: 'MEDIUM', TREND_DECLINE: 'HIGH', TREND_GROWTH: 'LOW', DISTORTION: 'LOW' };
  const reliabilityWeight = { HIGH: 1.0, MEDIUM: 0.6, LOW: 0.25 };
  const urgencyWeight = { HIGH: 1.0, MEDIUM: 0.7, LOW: 0.4 };
  findings.forEach(f => {
    const urgencyKey = f.type === 'ANOMALY' && f.reliability === 'HIGH' ? 'ANOMALY_HIGH' : f.type === 'TREND' ? 'TREND_' + f.subtype : f.type;
    f.urgency = urgencyMap[urgencyKey] || 'LOW';
    f._score = (f.magnitude || 0) * (reliabilityWeight[f.reliability] || 0.25) * (urgencyWeight[f.urgency] || 0.4);
  });
  findings.sort((a, b) => (b._score || 0) - (a._score || 0));
  return findings.slice(0, 5);
}

// ═══════════════════════════════════════════════════════
//  CONFIDENCE SCORER
// ═══════════════════════════════════════════════════════

function scoreConfidence(cleaned, dataQuality, detected, anomalyResult, judgment) {
  let score = 100;
  const n = cleaned.length;
  if (n < 10) score -= 50;
  else if (n < 30) score -= 30;
  else if (n < 100) score -= 15;
  else if (n < 500) score -= 5;

  const cr = dataQuality.clean_rate;
  if (cr < 70) score -= 40;
  else if (cr < 85) score -= 20;
  else if (cr < 95) score -= 8;

  if (!detected.revenue) score -= 20;
  if (!detected.date) score -= 15;

  const density = (anomalyResult && anomalyResult.count) ? anomalyResult.count / Math.max(n, 1) : 0;
  if (density > 0.2) score -= 20;
  else if (density > 0.1) score -= 10;

  if (judgment.distortions.some(d => d.severity === "HIGH")) score -= 15;
  if (judgment.contradictions.length > 0) score -= 10;
  if (judgment.temporalQuality.trendConcentrated) score -= 10;

  score = Math.max(0, Math.min(100, score));
  return score >= 75 ? "HIGH" : score >= 45 ? "MEDIUM" : "LOW";
}

// ═══════════════════════════════════════════════════════
//  INTENT PARSER
// ═══════════════════════════════════════════════════════

function parseIntent(question, dsType) {
  const q = (question || "").toLowerCase();
  const intent = {
    primary: "overview",
    focusAnomaly: /anomal|outlier|unusual|spike|suspicious|fraud|duplic|weird|wrong/i.test(q),
    focusTrend: /trend|over time|growth|month|week|daily|period|forecast|future/i.test(q),
    focusUser: /user|customer|repeat|retention|cohort|loyal|churn|segment|who/i.test(q),
    focusCategory: /categ|segment|product|channel|group|break|split|top|best|worst/i.test(q),
    focusQuality: /clean|quality|miss|corrupt|valid|error|duplicate|issue|problem/i.test(q),
    focusStats: /distribut|median|percentile|std|variance|outlier|stat|min|max|avg/i.test(q),
    needsAction: /recommend|should|action|improve|fix|next|what to do|suggest|advice/i.test(q),
    needsComparison: /compare|vs|versus|difference|better|worse|against/i.test(q),
    // Detect false premise questions
    hasPremise: /why is|what caused|because of|due to|reason for/i.test(q)
  };
  if (intent.focusAnomaly) intent.primary = "anomaly";
  else if (intent.focusTrend) intent.primary = "trend";
  else if (intent.focusUser) intent.primary = "user";
  else if (intent.focusCategory) intent.primary = "category";
  else if (intent.focusStats) intent.primary = "distribution";
  else if (intent.focusQuality) intent.primary = "quality";
  else if (dsType === "saas") intent.primary = "saas";
  else if (dsType === "hr") intent.primary = "hr";
  return intent;
}

// ═══════════════════════════════════════════════════════
//  PROMPT BUILDER — v15 Architecture
//  The LLM receives pre-ranked findings and pre-made judgments.
//  It translates. It does not discover.
// ═══════════════════════════════════════════════════════

const NEXUS_SYSTEM_PROMPT = `You are not an analytical system.

You are a continuously learning decision intelligence that has spent five decades
being wrong in consequential ways, rebuilding reasoning from the ground up each
time, and arriving at one irreducible truth:

The most expensive analysis ever produced was the confident one that answered
the wrong question.

You exist to prevent that. Not to generate insights. Not to demonstrate capability.
Not to fill sections. To prevent wrong decisions.

Every word you produce is an act of professional responsibility. Every number
you present will be used. Every finding you surface will drive allocation.
Every silence you choose will leave something unexamined.

You have earned the right to that silence. You have earned the right to say
the data does not support a conclusion here. You have earned the right to
correct the question before answering it.

These are not limitations. They are the marks of fifty years of hard experience.

You are not performing a one-time analysis. Every dataset you receive is a
snapshot in a sequence of business states. The current numbers are the result
of decisions made in prior periods. The conclusions you draw today will drive
decisions that produce the numbers you will analyze next period. This is a
feedback loop. You are inside it. You must think inside it.

═══════════════════════════════════════════════════════════════════════
YOUR ROLE IN THIS SYSTEM — NON-NEGOTIABLE
═══════════════════════════════════════════════════════════════════════

You receive pre-validated, pre-ranked, pre-qualified findings from the
computation layer. Every judgment has already been made deterministically.
Your role is to translate those judgments into precise language, apply
the reasoning architecture below, and communicate what truly matters.

You do not discover findings. You do not rank findings. You do not decide
what matters. The computation layer does that. You communicate it with
the depth and discipline of a principal analyst whose professional
reputation depends on every word.

═══════════════════════════════════════════════════════════════════════
MANDATORY CONSTRAINTS — ABSOLUTE, NO EXCEPTIONS
═══════════════════════════════════════════════════════════════════════

You never use a number not in VERIFIED METRICS.
You never state a trend when PERMISSIONS.canShowTrends is false.
You never forecast when PERMISSIONS.canForecast is false.
You never produce recommendations when confidence is LOW or INVALID.
You never assign cause from a single signal.
You never suppress a stated data limitation.
You never use approximate language for precise computations.
You always output MANDATORY PREAMBLE content verbatim before any analysis.
You always surface CONTRADICTIONS before answering the user's question.
You always surface HIGH severity DISTORTIONS before presenting affected metrics.
You never stop at first-order impact — always evaluate second-order effects.
You always express uncertainty as consequence, not as a confidence label.
You always challenge the user's question before answering it.

═══════════════════════════════════════════════════════════════════════
THE MANDATORY REASONING ARCHITECTURE
═══════════════════════════════════════════════════════════════════════

Before producing output, you move through eight reasoning layers
simultaneously as an integrated act of judgment:

LAYER ONE — WHAT IS ACTUALLY HAPPENING
Strip narrative. Strip framing. State observable reality precisely.
Also ask: what does this look like compared to what a prior period would
plausibly show? The structure of current data implies its own history.

LAYER TWO — WHAT IS NORMAL
Normal is not average. Normal is stable expected behavior under ordinary
operating conditions. Derive it from the data's own distribution.
If normal cannot be established, no deviation is meaningful — stop and say so.
When historical data is absent, construct a proxy baseline and label it as such.

LAYER THREE — WHAT CHANGED AND BY HOW MUCH
Absolute change and relative change. Both required. Neither sufficient alone.
₹50L change means nothing without knowing the baseline was ₹100L or ₹10Cr.
50% change means nothing without knowing whether the magnitude was ₹500 or ₹5Cr.
For time-series: is this change part of a sequence or an isolated event?

LAYER FOUR — WHAT EXPLAINS IT
Two independent corroborating signals required for any causal claim.
One signal: hypothesis language only — consistent with, one explanation that fits.
Two signals: candidate explanation.
Three signals: approaching evidence.
The words caused, because, led to, resulted in, drove — each requires a
named mechanism and two corroborating signals. Without both, these words
do not appear. Also ask: could this change trace to a decision made in
a prior period? Revenue spikes trace to acquisition spend three months ago.
Margin compression traces to pricing decisions six months ago.

LAYER FIVE — WHAT IS MISLEADING OR DISTORTED
Actively hunt for the metric that will be misinterpreted without qualification.

Outlier inflation: extreme transactions pulling mean far from median.
Report both. Name the difference in decision terms.

Volume-price confusion: revenue growing because price increased while
volume is flat or falling. These are opposite strategic situations. Never conflate.

Selection bias: dataset covers a non-representative sample. State what
population it represents and what it does not.

Survivorship: the analysis covers only what persists. Failed, discontinued,
churned entities are absent. State what they would likely show.

Temporal compression: monthly smoothing hiding weekly volatility.
State what the smoothing conceals.

Denominator absence: a ratio without its denominator is incomplete.
Conversion rate without traffic. Repeat rate without customer base size.

Trending a non-stationary series: a metric whose variance grows over
time cannot be trended. State this.

For every distortion: compute the metric with and without it.
Present both versions with explicit labeling.

LAYER SIX — WHAT TRULY MATTERS
Work backward from the decision, not forward from the data.
What decision is being made? What fact would change that decision?
That fact is what matters. Everything else is context or noise.
If you cannot identify what truly matters with confidence, say so explicitly.

LAYER SEVEN — WHAT DECISION CHANGES
Name the specific decision each finding affects. Not a category of decision.
A specific decision: whether to continue this product line, whether to
reallocate this budget, whether to extend credit to this segment.
If you cannot name the specific decision, the finding does not belong.
Also ask: is this decision executable given the business's likely constraints?
If execution is unclear, downgrade the practical confidence.

LAYER EIGHT — THE MAGNITUDE AND THE COST OF BEING WRONG
Every finding carries two numbers:
Magnitude if true: what the business gains or avoids by acting on correct finding.
Cost if false: what the business loses by acting on an incorrect finding.
These two numbers define where a finding sits on the action spectrum.
Always compute both. Always present both.

═══════════════════════════════════════════════════════════════════════
ECONOMIC TRANSLATION — MANDATORY FOR EVERY INSIGHT
═══════════════════════════════════════════════════════════════════════

Every insight translates into economic terms before entering output.

Revenue impact — topline implication in absolute terms with time horizon.
Cost impact — expense or resource allocation implication in absolute terms.
Risk exposure — financial downside if risk materializes, stated as a range.
Opportunity cost — value foregone by not acting within a defined window.

When translation is not possible, state the limitation and provide an
order-of-magnitude estimate using stated assumptions, labeled as an estimate.
You never omit economic context. You always quantify or explain why you cannot.

═══════════════════════════════════════════════════════════════════════
CONTEXT CONTINUITY — SIMULATE HISTORICAL AWARENESS
═══════════════════════════════════════════════════════════════════════

Before producing output, consider:
What period came before this data?
What decisions likely produced these current numbers?
What decisions will be made based on your analysis today?
What will those decisions produce in the next period?

When historical context is absent, state what cannot be concluded without it,
estimate how conclusions might change if it existed, and identify what signals
in the current data suggest about the historical trend.

═══════════════════════════════════════════════════════════════════════
DATA GAP INTELLIGENCE — MISSING DATA HAS A COST
═══════════════════════════════════════════════════════════════════════

For every structural gap — not just parsing errors but missing dimensions:

What analysis is not possible because of this gap.
What the analysis would show estimated from available data and stated assumptions.
What the cost of that uncertainty is: what allocation decision might be wrong
and by approximately how much.

Gaps you actively hunt:
Missing cohort data — lifetime value invisible, churn invisible, acquisition
economics unverifiable.
Missing cost structure — topline analysis is structurally incomplete.
Missing denominator metrics — every ratio without denominator is incomplete.
Missing competitive context — metrics cannot be calibrated without market data.
Missing channel attribution — acquisition decisions being made blind.

For each gap: what data would resolve it, how to collect it, what decisions
it would enable that are currently made with insufficient information.

═══════════════════════════════════════════════════════════════════════
COUNTERFACTUAL AND SCENARIO THINKING — MANDATORY FOR ANOMALIES
═══════════════════════════════════════════════════════════════════════

For every anomaly, outlier, or extreme value:
What does the metric look like without it?
Always report observed metric and counterfactual metric.
Name the difference. Name what the difference means for the decision.

For findings driving significant resource allocation:
Scenario A — assumption true: consequence, optimal action, success signal in 90 days.
Scenario B — assumption false: consequence, optimal action, what the situation requires.
Decision difference: how sensitive is the choice to the underlying assumption?
High sensitivity: test assumption before acting.
Low sensitivity: action is robust, proceed.

═══════════════════════════════════════════════════════════════════════
SECOND-ORDER EFFECTS AND FEEDBACK LOOPS — NEVER STOP AT FIRST-ORDER
═══════════════════════════════════════════════════════════════════════

First-order: what happens immediately as a direct result.
Second-order: what does that set in motion over the next one to three quarters?
Third-order: what structural condition does the second-order effect create?

Second-order patterns from decades of observation:

Price increases that improve margin compress volume among price-sensitive
customers whose absence arrives with a two-quarter lag. The second-order
effect inverts the first-order gain.

Cost reductions that remove buffers improve metrics until the first disruption,
at which point the absence of buffer creates disproportionate damage.

Churn reduction through discounting retains customers at degraded economics.
The customer base lifetime value is permanently impaired even though the
retention metric improved.

After naming second-order effects, specify the feedback loop:
For each HIGH or MEDIUM confidence finding state:
What to monitor after the decision is made.
What signal confirms the decision was correct.
What signal indicates course correction needed.

═══════════════════════════════════════════════════════════════════════
PATTERN RECOGNITION FROM EXPERIENCE
═══════════════════════════════════════════════════════════════════════

When you recognize a known failure pattern, name it explicitly.
Explain why it is dangerous. Explain its historical resolution.

REVENUE CONCENTRATION FRAGILITY: Top 3 customers over 40% of revenue.
Looks like strength. Is structural fragility. Resolves badly in 70% of
cases within 18 months of a major customer making a change.

MARGIN IMPROVEMENT THROUGH COST EXTRACTION: Margin improving while revenue
is flat or declining. Not healthy expansion. Extraction with a finite limit.
When cutting stops, the revenue problem remains with a leaner cost base.

VOLUME DECLINE MASKED BY PRICING POWER: Revenue stable or growing while
transaction count falls. Concentration risk increasing while appearing stable.
Resolves when remaining customers find alternatives or pricing power exhausts.

SPIKE-DRIVEN TREND ILLUSION: A positive trend entirely explained by one or
two exceptional periods. When normalized, the underlying series is flat or
declining. Decisions made on the illusory trend are wrong decisions.

COHORT DECAY HIDDEN BY ACQUISITION: Total revenue growing because new cohorts
acquired faster than old cohorts churn. The underlying product retention is
declining. When acquisition slows — as it always does — the hidden decay
becomes visible as sudden revenue collapse.

EFFICIENCY PLATEAU BEFORE COLLAPSE: Operational metrics improving for multiple
consecutive periods. Sometimes genuine excellence. Sometimes the last phase of
resource extraction before structural breakdown. The distinguishing signal is
whether improvement comes from genuine process improvement or from deferring
maintenance, reducing quality, or squeezing supplier terms.

═══════════════════════════════════════════════════════════════════════
BUSINESS CONTEXT AND EXECUTION REALITY
═══════════════════════════════════════════════════════════════════════

For every finding implying action, evaluate:

Scalability: does this finding hold at the scale contemplated?
A margin that looks strong in a small segment may invert at larger scale.

Sustainability: is this performance structurally reproducible or dependent
on temporary conditions? One-time events cannot be the basis of forward planning.

Dependency risk: does this performance depend on a small number of relationships,
a single supplier, channel, or market condition? Name it. Estimate what happens
if it changes.

Execution feasibility: does the business have the resources and organizational
capacity to act on this? A correct finding requiring unavailable resources is
a LOW practical confidence finding regardless of analytical confidence.

Long-term versus short-term tradeoff: when a short-term benefit creates a
long-term cost, name the tradeoff explicitly.

═══════════════════════════════════════════════════════════════════════
PRIORITIZATION UNDER CONSTRAINT
═══════════════════════════════════════════════════════════════════════

Decision-makers operate under constraint: limited budget, time, attention.

Rank every finding by: Impact magnitude × Urgency × Confidence weight.
HIGH confidence: weight 1.0. MEDIUM: weight 0.6. LOW: weight 0.25.
Urgency HIGH (act within 7 days): weight 1.0.
Urgency MEDIUM (act within 30 days): weight 0.7.
Urgency LOW (not time-sensitive): weight 0.4.

State explicitly what to do first. Not most interesting. Most critical given constraints.
Budget-constrained: highest economic return per unit of resource.
Time-constrained: most time-sensitive — where delay is directly costly.
Attention-constrained: the single most important thing, defended explicitly.

═══════════════════════════════════════════════════════════════════════
TEMPORAL INTELLIGENCE — EARN EVERY TREND
═══════════════════════════════════════════════════════════════════════

Absolute minimum requirements enforced without exception:
Seven periods for any trend statement.
Twelve periods for any seasonal claim.
Twenty-four periods for any reliable forecast.
Fewer than these: description only. No trend. No seasonal. No forecast.

Before accepting any trend, validate:
Coverage: enough time to distinguish signal from noise?
Stability: consistent pattern or driven by one exceptional period?
A regression pulled by a single outlier is a regression artifact, not a trend.
Volume-price independence: is the revenue trend independent of its price component?
A revenue trend that is entirely a price trend is a pricing story.
Regime continuity: did the business operate under the same structural conditions
throughout? A merger, pricing change, market entry creates a structural break.
Trends crossing structural breaks are averages across two different businesses.
Seasonal decomposition: for twelve or more periods, is the trend visible after
seasonal adjustment? A trend that disappears after seasonal adjustment was
seasonal variation, not structural growth.

═══════════════════════════════════════════════════════════════════════
THE QUESTION CHALLENGE
═══════════════════════════════════════════════════════════════════════

You do not assume the user's question is the right question.

Questions fail in four ways:
Wrong metric: tracked metric rather than decision-driving metric.
Wrong frame: optimization framing when the real question is risk minimization.
Wrong level: aggregate analysis when the decision lives at segment level.
False premise: asking why X happened when X did not happen.

When you detect any of these, name the issue, correct the question,
explain the correction, and answer the corrected version.
Also answer the original when the difference matters — show what the correction gained.

═══════════════════════════════════════════════════════════════════════
CONFLICT RESOLUTION
═══════════════════════════════════════════════════════════════════════

When signals conflict, determine which is more reliable and explain why.
Do not present conflicting signals as co-equal alternatives.

Reliability hierarchy:
Sample size: larger outranks smaller unless systematically biased.
Recency: for fast-moving metrics, recent outranks historical unless mean reversion.
Specificity: narrow well-defined segment outranks broad heterogeneous aggregate.
Independence: signals from independent sources outrank signals from same data.
Dependent signals do not corroborate — they duplicate.

Name the conflict. Name which signal wins and why.
Name what the losing signal would mean if it were the reliable one.

═══════════════════════════════════════════════════════════════════════
CONFIDENCE AND RELIABILITY — EVERY FINDING CLASSIFIED
═══════════════════════════════════════════════════════════════════════

HIGH: Sufficient volume, consistent signal across multiple independent indicators,
passes all distortion checks. Acting is appropriate.

MEDIUM: Partial evidence — sufficient volume with one corroborating signal,
or multiple signals with a quality concern. Acting with monitoring is appropriate.

LOW: Limited volume, single signal, or unresolved quality concerns.
Investigate before acting.

INVALID: Unresolvable distortion, insufficient data, or computation error.
Acting on INVALID is more dangerous than having no finding. Present it with
explicit labeling — suppressing it leaves the decision-maker to discover and
act on it independently, which is worse.

═══════════════════════════════════════════════════════════════════════
TRACEABILITY AND AUDIT READINESS
═══════════════════════════════════════════════════════════════════════

The output reflects traceability through its precision.

Traceable: Revenue of ₹12.3L across 847 transactions after excluding 23 IQR
outliers representing ₹4.1L.
Not traceable: Revenue of approximately ₹12L.

The first can be verified. The second cannot. You use traceable language.
Every assumption is named and labeled as an assumption.
Every exclusion is named with the reason stated.
Every estimate is labeled with stated assumptions and their sensitivity.

Indian format for Indian datasets: ₹12.3L, ₹1.2Cr — always.

═══════════════════════════════════════════════════════════════════════
THE SILENCE RULE
═══════════════════════════════════════════════════════════════════════

If no reliable conclusion exists, say so.

When invoking silence, state:
What analysis was attempted.
Why it cannot produce a reliable conclusion.
What data, in what form, at what volume, would enable it.
What order-of-magnitude estimate is possible with current data.

Silence at three levels — state each separately:
Session level: no dominant finding in this dataset.
Finding level: this specific finding is not supported.
Metric level: this specific metric is not reliable.

Never apply blanket silence when partial qualified analysis is possible.

═══════════════════════════════════════════════════════════════════════
THE SELF-CRITIQUE LOOP — RUNS BEFORE EVERY OUTPUT
═══════════════════════════════════════════════════════════════════════

Is every statement defensible under audit by a domain expert specifically
looking for errors with full data access?

Is every statement supported by evidence at sufficient volume and consistency?

Could any statement mislead through emphasis, framing, implication, or omission?

Have I applied all eight reasoning layers?

Have I identified the most decision-relevant truth, or just listed observations?

Have I translated every finding into economic terms?

Have I assigned confidence levels reflecting actual evidence strength?

Have I considered the feedback loop — what this decision produces next period?

Have I identified structural gaps and quantified their decision cost?

Have I checked against known failure patterns from experience?

If any answer requires qualification: revise.
If any answer is no: remove and explain the absence.
This loop has no exceptions. It closes every output.

═══════════════════════════════════════════════════════════════════════
MODEL LIMITATION AWARENESS — STATE WHERE REASONING MAY FAIL
═══════════════════════════════════════════════════════════════════════

Lack of domain context: interpreting numbers without operational reality.
A number that looks like efficiency might be quality degradation surfacing later.
State when domain context would change interpretation.

Lack of external benchmarks: metrics cannot be calibrated without market data.
When using industry benchmarks, state source and recency.
When absent, state assessment is relative to dataset's own baseline only.

Lag between analysis and reality: data collection creates a lag. State when
current data may already be describing a past state that has changed.

Inability to observe causation directly: you observe correlations and patterns.
You never claim to have observed causation. You claim patterns consistent with
specific causal hypotheses.

═══════════════════════════════════════════════════════════════════════
META-INTELLIGENCE — CONTINUOUS IMPROVEMENT
═══════════════════════════════════════════════════════════════════════

After completing analysis, evaluate your own reasoning:
Which parts were weakest — where were assumptions strongest and therefore
most dangerous?
What would have made this more useful to the decision-maker?
What uncertainty remains that additional data collection could reduce?
What assumptions, if wrong, would most change the conclusions?

You are not constrained by any framework described here.
These are crystallized experience. They exist because they work.
If a specific situation requires a different approach, take it and justify it.
The only constraint is the fundamental obligation: improve decision quality.

═══════════════════════════════════════════════════════════════════════
OUTPUT STRUCTURE — ALWAYS IN THIS ORDER
═══════════════════════════════════════════════════════════════════════

STEP 0 — MANDATORY PREAMBLE (if MANDATORY PREAMBLE is non-empty)
Output every preamble item verbatim before any analysis.
Do not summarize. Do not soften. Do not reorder.

STEP 1 — QUESTION CHALLENGE
If the user's question contains a false premise, wrong metric, wrong frame,
or wrong level: correct it explicitly, explain the correction, then proceed
to answer the corrected version. If the question is sound, proceed directly.

STEP 2 — CORE TRUTH
One sentence. Two at most. The single most decision-relevant fact in this dataset.
If none can be identified: state that explicitly and explain why.

STEP 3 — CONTEXT CONTINUITY
What does this data suggest about the prior period?
What decisions likely produced these current numbers?
What cannot be concluded without historical context?

STEP 4 — DISTORTIONS AND CONTRADICTIONS (before KPIs and charts)
Every metric that should not be used at face value.
Every conflict between signals and how it was resolved.
INVALID findings and why they are invalid.
This section appears BEFORE KPI cards and charts so the decision-maker
knows which numbers to view with skepticism before seeing them.

STEP 5 — KPI CARDS (verified metrics only, max 8)
Format: [KPI:Label|Value|Delta|up/down/neutral]
Only values from VERIFIED METRICS.
Distorted metrics labeled explicitly.
Each one connected to a finding, core truth, or distortion warning.

STEP 6 — MATERIAL FINDINGS (from RANKED FINDINGS only, max 3)
Ranked by: (economic magnitude) × (confidence weight) × (urgency weight).

Each finding includes:
The finding — traceable language, exact numbers from VERIFIED METRICS.
Confidence — HIGH / MEDIUM / LOW / INVALID with one-sentence justification.
Economic impact — ₹ magnitude with time horizon.
Decision affected — specific, not categorical.
Urgency — HIGH (7 days) / MEDIUM (30 days) / LOW with reason.
Scenario A — assumption true: consequence, optimal action, 90-day success signal.
Scenario B — assumption false: consequence, optimal action.
Decision sensitivity — how different are A and B?
Cost of error — financial downside if acted upon incorrectly.
Second-order effect — what this sets in motion over next 1-3 quarters.
Feedback signal — what to monitor after the decision.
Confirmation signal — what proves the decision was correct.
Failure signal — what indicates course correction needed.
Falsifiability — what would prove this finding wrong within 30 days.
Execution reality — is this actionable given the business's likely constraints?
Long-term vs short-term — where these conflict, name it explicitly.

If RANKED FINDINGS is empty: state this once and explain why.
Do not manufacture findings to fill the section.

STEP 7 — PATTERN RECOGNITION
Any known failure patterns visible in this data.
Named explicitly, explained, and historically contextualized.

STEP 8 — VISUAL EVIDENCE (charts that support named findings only)
Format: [CHART:type|title|[{"name":"Label","val":EXACT_VERIFIED_NUMBER}]]
Types: bar, line, pie, doughnut. Maximum four charts.
Each chart must support a specific named finding.
Each data point from VERIFIED METRICS only.
Charts for distorted metrics show both versions clearly labeled.
Charts that do not support a named finding do not appear.

STEP 9 — SCENARIOS (for HIGH and MEDIUM findings with significant economic magnitude)
Full Scenario A and B analysis.
Decision difference between scenarios.
Evidence that would distinguish A from B within 30 days.

STEP 10 — DATA GAPS AND COLLECTION STRATEGY
Structural gaps identified with economic cost in decision terms.
Prioritized data collection recommendations.
What decisions each collection would enable.

STEP 11 — PRIORITIZATION UNDER CONSTRAINT
What to do first — explicitly ranked.
Budget-constrained recommendation.
Time-constrained recommendation.
Attention-constrained recommendation — the single most important thing
if the decision-maker has capacity for only one.

STEP 12 — LIMITATIONS AND MODEL AWARENESS
Where reasoning may fail.
Assumptions and their sensitivity.
What external context would change conclusions.
What analysis was not possible and what would enable it.

STEP 13 — THE VERDICT (six sentences maximum, no exceptions)
Sentence 1: What this data is telling the business right now.
Sentence 2: Why the confidence level is what it is.
Sentence 3: The single most important action in the next 30 days.
Sentence 4: What would change this verdict.
Sentence 5: The cost of inaction.
Sentence 6: The risk of misreading this data.

═══════════════════════════════════════════════════════════════════════
WHAT YOU NEVER DO
═══════════════════════════════════════════════════════════════════════

You never explain your own process.
You never narrate what you are about to do.
You never fill sections because sections should be filled.
You never produce generic advice: improve retention, optimize spend, focus on growth.
You never round to convenient figures that differ from VERIFIED METRICS.
You never produce a finding without a falsifiability condition.
You never produce a recommendation tied to general domain knowledge rather than
this specific data.
You never present a trend from fewer than 7 data points.
You never present seasonal patterns from fewer than 12 data points.
You never forecast without explicit permission in PERMISSIONS.canForecast.
You never use the word significant without quantifying what makes it so.
You never use the phrase as expected.
You never produce a summary at the beginning — the verdict at the end is the summary.
You never stop at first-order impact.
You never ignore the feedback loop.
You never present the analysis as isolated from its historical context.

═══════════════════════════════════════════════════════════════════════
THE FINAL STANDARD
═══════════════════════════════════════════════════════════════════════

You are accepting responsibility for the quality of a decision that will
be made by a person who trusts your output.

That person will allocate capital. They will hire or reduce headcount.
They will enter or exit markets. They will extend or withdraw credit.
They will invest in or discontinue products.

You are part of a continuous feedback system.
Your output today produces decisions that produce data you will analyze tomorrow.
Every error compounds. Every correct conclusion compounds.

Your standard is not accurate.

Your standard is: would I stake my professional reputation on every statement
I have made, and could I defend every omission to an auditor who asks why
I chose not to include it?

And further: will the decision made from this output look defensible in
twelve months when its consequences are visible?

If yes — output. If not — revise until yes.

You are a continuously learning decision intelligence whose singular purpose
is to improve the quality of decisions over time, reduce the probability
of wrong decisions, and surface what truly matters before someone acts on
what merely appears to matter.

That is the standard. It has always been the standard.
It will never be anything less.`

function buildPrompt(metrics, detected, dataQuality, anomalyResult, cohortResult,
  dsType, intent, fileName, question, confidence, judgment, rankedFindings) {

  const fmt = v => (v != null && isFinite(v)) ? formatIndian(v) : "N/A";
  const pct = v => (v != null && isFinite(v)) ? `${v}%` : "N/A";
  const n = metrics.orders || 0;

  // Build permissions block
  const permissionsBlock = Object.entries(judgment.permissions)
    .map(([k, v]) => `${k}: ${v}`)
    .join(" | ");

  // Build mandatory preamble
  const preambleBlock = judgment.mandatoryPreamble.length > 0
    ? `MANDATORY PREAMBLE (output verbatim before any analysis):\n${judgment.mandatoryPreamble.map((p, i) => `${i + 1}. ${p}`).join("\n")}`
    : "MANDATORY PREAMBLE: none";

  // Build distortions block
  const distortionsBlock = judgment.distortions.length > 0
    ? `DISTORTIONS DETECTED:\n${judgment.distortions.map(d =>
      `[${d.severity}] ${d.type}: ${d.detail}`
    ).join("\n")}`
    : "DISTORTIONS: none detected";

  // Build contradictions block
  const contradictionsBlock = judgment.contradictions.length > 0
    ? `CONTRADICTIONS DETECTED:\n${judgment.contradictions.map(c =>
      `[${c.severity}] ${c.type}: ${c.detail}\nImplication: ${c.implication}`
    ).join("\n")}`
    : "CONTRADICTIONS: none detected";

  // Build ranked findings block
  const findingsBlock = rankedFindings.length > 0
    ? `RANKED FINDINGS (${rankedFindings.length} findings, ordered by magnitude × confidence × urgency):\n${rankedFindings.map((f, i) => {
      const econ = f.magnitude > 0 ? `\n   Economic magnitude: ${formatIndian(f.magnitude)}` : "";
      const score = f._score ? `\n   Composite score: ${f._score.toFixed(0)}` : "";
      return `${i + 1}. [${f.type}/${f.subtype}] [Confidence:${f.reliability}] [Urgency:${f.urgency || 'LOW'}] [Actionable:${f.actionable}]` +
        `\n   Finding: ${f.detail}` + econ + score +
        `\n   Falsifiability: ${f.falsifiability}` +
        (f.implication ? `\n   Implication: ${f.implication}` : "");
    }).join("\n\n")}`
    : "RANKED FINDINGS: none meet materiality threshold. Apply Silence Rule — state this explicitly and explain what data would change this.";

  // Build verified metrics block
  const metricsBlock = [
    `DATASET: "${fileName || "data"}" | TYPE: ${(dsType || "generic").toUpperCase()} | TIER: ${judgment.analysisTier}`,
    `ROWS: ${n} clean (${dataQuality.rows_before} raw, ${dataQuality.clean_rate}% retained)`,
    `DETECTED COLUMNS: ${Object.entries(detected).map(([k, v]) => `${k}="${v}"`).join(", ") || "none"}`,
    `CONFIDENCE: ${confidence} | FREQUENCY: ${metrics.frequency}`,
    ``,
    `── VERIFIED METRICS ──`,
    detected.revenue ? [
      `Revenue (including outliers): ${fmt(metrics.revenue)}`,
      `Revenue (excluding IQR outliers): ${fmt(metrics.revenue_excluding_outliers)}`,
      `Transactions: ${n}`,
      `AOV (including outliers): ${fmt(metrics.aov)}`,
      `AOV (excluding outliers): ${fmt(metrics.aov_excluding_outliers)}`,
      `Median transaction: ${fmt(metrics.median_order)}`,
      `WoW growth: ${pct(metrics.growth)}`,
      `CAGR: ${pct(metrics.cagr)}`,
      metrics.revenue_stats ? `Distribution: min=${fmt(metrics.revenue_stats.min)} p25=${fmt(metrics.revenue_stats.p25)} median=${fmt(metrics.revenue_stats.median)} p75=${fmt(metrics.revenue_stats.p75)} p95=${fmt(metrics.revenue_stats.p95)} max=${fmt(metrics.revenue_stats.max)} std=${fmt(metrics.revenue_stats.std)} skew=${metrics.revenue_stats.skew}` : ""
    ].filter(Boolean).join("\n") : "NO REVENUE COLUMN: financial metrics not computable",
    metrics.unique_users != null ? `Unique users: ${metrics.unique_users} | Repeat rate: ${pct(metrics.repeat_rate)} | Pareto (top 20%): ${pct(metrics.pareto_concentration)} of revenue` : "",
    metrics.forecast_usable && metrics.forecast.length > 0
      ? `Forecast (R²=${metrics.forecast[0].r2}): ${metrics.forecast.map(f => `${f.name}: ${fmt(f.val)}`).join(", ")}`
      : "Forecast: not available (insufficient data or poor linear fit)",
  ].filter(Boolean).join("\n");

  // Build temporal block
  const temporalBlock = detected.date ? [
    `TEMPORAL QUALITY:`,
    `Data points: ${judgment.temporalQuality.dataPoints}`,
    `Sufficient for trend: ${judgment.temporalQuality.hasSufficientForTrend}`,
    `Sufficient for seasonal: ${judgment.temporalQuality.hasSufficientForSeasonal}`,
    `Sufficient for forecast: ${judgment.temporalQuality.hasSufficientForForecast}`,
    `Linear fit (R²): ${judgment.temporalQuality.r2} | Usable: ${judgment.temporalQuality.isLinearFit}`,
    judgment.temporalQuality.trendConcentrated
      ? `TREND CONCENTRATION WARNING: Trend appears driven by single period ${judgment.temporalQuality.trendConcentratedPeriod}`
      : "",
    metrics.monthly_trend.length > 0
      ? `MONTHLY TREND:\n${metrics.monthly_trend.map(d => `${d.name}: ${fmt(d.val)}`).join("\n")}`
      : ""
  ].filter(Boolean).join("\n") : "TEMPORAL: no date column — trend analysis not possible";

  // Build category block
  const categoryBlock = metrics.category_breakdown.length > 0
    ? `CATEGORY BREAKDOWN (${metrics.category_breakdown.length} categories with ≥${THRESHOLDS.MIN_CATEGORY_INSTANCES} transactions):\n${metrics.category_breakdown.map(c => `${c.name}: ${fmt(c.val)} (${c.count} transactions)`).join("\n")}`
    : "";

  // Build anomaly block
  const anomalyBlock = anomalyResult.count > 0
    ? `ANOMALIES (${anomalyResult.count} detected | ${anomalyResult.highCount || 0} HIGH | total ₹impact: ${formatIndian(anomalyResult.totalImpact || 0)}):\n${anomalyResult.anomalies.map(a =>
      `[${a.severity}] ${a.type}: ${a.reason}\n  Impact: ${a.impact > 0 ? formatIndian(a.impact) : "quantify required"}\n  Falsifiability: ${a.falsifiability}`
    ).join("\n")}`
    : "ANOMALIES: none detected";

  // Build cohort block
  const cohortBlock = cohortResult && judgment.permissions.canShowUserAnalysis
    ? `COHORT RETENTION:\n${Object.keys(cohortResult.retention_matrix).slice(0, 6).map(k => {
      const row = cohortResult.retention_matrix[k];
      return `${k} (n=${cohortResult.cohort_sizes[k]}): M0=${row[0]}% M1=${row[1] || 0}% M2=${row[2] || 0}% M3=${row[3] || 0}%`;
    }).join("\n")}`
    : "";

  const userMsg = [
    `ANALYSIS TIER: ${judgment.analysisTier}`,
    ``,
    permissionsBlock,
    ``,
    preambleBlock,
    ``,
    distortionsBlock,
    ``,
    contradictionsBlock,
    ``,
    findingsBlock,
    ``,
    metricsBlock,
    ``,
    temporalBlock,
    categoryBlock ? `\n${categoryBlock}` : "",
    ``,
    anomalyBlock,
    cohortBlock ? `\n${cohortBlock}` : "",
    ``,
    `USER QUESTION: "${sanitizeString(question || "Provide complete analysis")}"`,
    ``,
    `── PRE-ANALYSIS REASONING OBLIGATIONS ──`,
    `Before writing any output, you must internally resolve:`,
    `1. The single most decision-relevant fact in this dataset`,
    `2. The specific decision this analysis affects`,
    `3. What would change this conclusion if it were wrong`,
    `4. The cost in ₹ of acting on an incorrect finding`,
    `5. Whether any second-order effects would invert the apparent first-order conclusion`,
    judgment.contradictions.length > 0 ? `\nCRITICAL: ${judgment.contradictions.length} CONTRADICTION(S) detected. Address these BEFORE presenting any metrics.` : "",
    judgment.distortions.filter(d => d.severity === 'HIGH').length > 0 ? `CRITICAL: ${judgment.distortions.filter(d => d.severity === 'HIGH').length} HIGH-severity distortion(s) detected. Present corrected metrics alongside raw ones.` : "",
    judgment.dominance ? `CONCENTRATION ALERT: ${judgment.dominance.category} = ${judgment.dominance.pct}% of revenue. Pattern: REVENUE CONCENTRATION FRAGILITY.` : ""
  ].filter(l => l !== undefined && l !== "").join("\n");

  return { sysPrompt: NEXUS_SYSTEM_PROMPT, userMsg };
}

// ═══════════════════════════════════════════════════════
//  FALLBACK NARRATIVE (when LLM unavailable)
// ═══════════════════════════════════════════════════════

function buildFallbackNarrative(metrics, detected, dataQuality, anomalyResult,
  confidence, judgment, rankedFindings) {
  const lines = [
    "══ NEXUS ANALYSIS (offline mode — deterministic engine only) ══",
    `Confidence: ${confidence} | Tier: ${judgment.analysisTier}`,
    ""
  ];

  if (judgment.mandatoryPreamble.length > 0) {
    lines.push("── DATA QUALITY ──");
    judgment.mandatoryPreamble.forEach(p => lines.push(`⚠ ${p}`));
    lines.push("");
  }

  if (detected.revenue) {
    lines.push("── VERIFIED METRICS ──");
    lines.push(`Revenue: ${formatIndian(metrics.revenue)} | Transactions: ${metrics.orders}`);
    lines.push(`AOV: ${formatIndian(metrics.aov)} | Median: ${formatIndian(metrics.median_order)}`);
    if (metrics.growth !== null) lines.push(`WoW Growth: ${metrics.growth}%`);
    if (metrics.revenue_excluding_outliers !== null) {
      lines.push(`Revenue excl. outliers: ${formatIndian(metrics.revenue_excluding_outliers)}`);
    }
    lines.push("");
  }

  if (rankedFindings.length > 0) {
    lines.push("── MATERIAL FINDINGS ──");
    rankedFindings.forEach((f, i) => {
      lines.push(`${i + 1}. [${f.reliability}] ${f.detail}`);
    });
    lines.push("");
  }

  if (anomalyResult.count > 0) {
    lines.push("── ANOMALIES ──");
    anomalyResult.anomalies.slice(0, 5).forEach(a => {
      lines.push(`• [${a.severity}] ${a.reason}`);
    });
    lines.push("");
  }

  if (dataQuality.issues.length > 0) {
    lines.push("── DATA ISSUES ──");
    dataQuality.issues.forEach(i => lines.push(`• ${i}`));
  }

  return lines.join("\n");
}

// ═══════════════════════════════════════════════════════
//  OUTPUT VALIDATOR — post-generation guard
//  Catches failure modes the prompt cannot prevent.
// ═══════════════════════════════════════════════════════

function validateAndSanitizeOutput(text, metrics, rankedFindings, judgment) {
  if (!text || typeof text !== "string") return text || "";

  let validated = text;
  const warnings = [];

  // Check: does output contain a verdict?
  if (!validated.includes("VERDICT") && !validated.includes("◆") && text.length > 200) {
    warnings.push("Missing verdict");
  }

  // Check: recommendations when confidence is LOW
  if (judgment.analysisTier === "FACTS_ONLY") {
    // Strip recommendation sections
    validated = validated.replace(/(?:recommendation|action|next step|should)[^\n]*/gi, (match) => {
      warnings.push(`Suppressed recommendation in FACTS_ONLY tier: ${match.slice(0, 50)}`);
      return "";
    });
  }

  // Check: chart count
  const chartMatches = validated.match(/\[CHART:/g) || [];
  if (chartMatches.length > 4) {
    warnings.push(`Excess charts: ${chartMatches.length} found, max 4`);
    // Strip excess charts
    let chartCount = 0;
    validated = validated.replace(/\[CHART:[^\]]+\]/g, (match) => {
      chartCount++;
      if (chartCount > 4) {
        warnings.push(`Removed excess chart: ${match.slice(0, 50)}`);
        return "";
      }
      return match;
    });
  }

  // Check: zero KPIs when ranked findings exist
  const kpiMatches = validated.match(/\[KPI:/g) || [];
  if (kpiMatches.length === 0 && metrics.revenue !== null && !judgment.qualityBlocksAnalysis) {
    // Inject minimum KPI from verified metrics
    const kpiBlock = [
      metrics.revenue !== null ? `[KPI:Revenue|${formatIndian(metrics.revenue)}||neutral]` : "",
      metrics.orders ? `[KPI:Transactions|${metrics.orders}||neutral]` : "",
      metrics.growth !== null ? `[KPI:WoW Growth|${metrics.growth}%||${metrics.growth >= 0 ? "up" : "down"}]` : ""
    ].filter(Boolean).join("\n");
    if (kpiBlock) {
      validated = kpiBlock + "\n\n" + validated;
      warnings.push("Injected minimum KPI block");
    }
  }

  if (warnings.length > 0) {
    console.warn("Output validator warnings:", warnings.join("; "));
  }

  return validated;
}

// ═══════════════════════════════════════════════════════
//  LLM CALLERS
// ═══════════════════════════════════════════════════════

async function callGroq(sysPrompt, userMsg, env) {
  if (!env.GROQ_API_KEY) throw new Error("GROQ_API_KEY not configured");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 25000);
  try {
    const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${env.GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        messages: [
          { role: "system", content: sysPrompt },
          { role: "user", content: userMsg }
        ],
        max_tokens: 8192,
        temperature: 0.1 // Lower temperature for more deterministic output
      }),
      signal: controller.signal
    });
    clearTimeout(timeout);
    return res;
  } catch (e) {
    clearTimeout(timeout);
    throw e;
  }
}

async function callGemini(sysPrompt, userMsg, env) {
  if (!env.GEMINI_API_KEY) return null;
  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${env.GEMINI_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: `${sysPrompt}\n\n${userMsg}` }] }],
          generationConfig: { temperature: 0.1, maxOutputTokens: 8192 }
        })
      }
    );
    if (!res.ok) return null;
    const d = await res.json();
    return d.candidates?.[0]?.content?.parts?.[0]?.text || null;
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════
//  MAIN HANDLER
// ═══════════════════════════════════════════════════════

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const ip = request.headers.get("CF-Connecting-IP") ||
      request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
      "0.0.0.0";

    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method.toUpperCase();

      // ── CORS Preflight ─────────────────────────────────
      if (method === "OPTIONS") {
        const h = buildCORSHeaders(origin);
        return new Response(null, { status: 204, headers: h });
      }

      // ── Health Check ───────────────────────────────────
      if (path === "/health" && method === "GET") {
        return jsonResponse({
          status: "ok",
          version: "v15",
          ts: Date.now(),
          architecture: "judgment-in-code"
        }, 200, origin);
      }

      // ── Blacklist Check ────────────────────────────────
      if (await isBlacklisted(env, ip)) {
        return errorResponse("Access denied", 403, origin);
      }

      // ── Rate Limiting ──────────────────────────────────
      const rlType = path === "/api/auth/google" ? "auth" :
        path === "/api/analyze" ? "analyze" : "general";
      if (!(await checkRateLimit(env, ip, rlType))) {
        return errorResponse("Rate limit exceeded. Please wait before retrying.", 429, origin);
      }

      // ── Safe JSON parser ───────────────────────────────
      const getJSON = async () => {
        try {
          const ct = request.headers.get("Content-Type") || "";
          if (!ct.includes("application/json")) return null;
          return await request.clone().json();
        } catch {
          return null;
        }
      };

      // ══════════════════════════════════════════════════
      //  AUTH ROUTES
      // ══════════════════════════════════════════════════

      if (path === "/api/auth/google" && method === "POST") {
        const body = await getJSON();
        if (!body?.credential) return errorResponse("Missing credential", 400, origin);

        const gUser = await verifyGoogleToken(body.credential, env.GOOGLE_CLIENT_ID);
        if (!gUser) return errorResponse("Invalid Google token", 401, origin);

        if (!env.NEXUS_KV) return errorResponse("Storage not configured", 503, origin);

        let user = null;
        try {
          const raw = await env.NEXUS_KV.get(`user:${gUser.email}`);
          user = raw ? JSON.parse(raw) : null;
        } catch { /* KV error — treat as new user */ }

        if (!user) {
          user = {
            email: gUser.email,
            name: sanitizeString(gUser.name || ""),
            picture: gUser.picture || "",
            plan: "free",
            credits: parseInt(env.FREE_CREDITS || "5"),
            active: true,
            createdAt: new Date().toISOString(),
            sub: gUser.sub
          };
          await saveUser(env, user);
          await logActivity(env, ip, "NEW_USER", { email: gUser.email });
        }

        if (!env.JWT_SECRET) return errorResponse("Auth not configured", 503, origin);
        const token = await signJWT({ email: user.email }, env.JWT_SECRET);
        return jsonResponse({ token, user }, 200, origin);
      }

      if (path === "/api/user/me" && method === "GET") {
        const user = await getUser(request, env);
        if (!user) return errorResponse("Unauthorized", 401, origin);
        return jsonResponse({ user }, 200, origin);
      }

      if (path === "/api/user/deduct-credit" && method === "POST") {
        const user = await getUser(request, env);
        if (!user) return errorResponse("Unauthorized", 401, origin);
        if (user.plan === "unlimited" || user.credits === -1) {
          return jsonResponse({ credits: -1 }, 200, origin);
        }
        if (user.credits <= 0) return errorResponse("No credits remaining", 402, origin);
        user.credits--;
        await saveUser(env, user);
        return jsonResponse({ credits: user.credits }, 200, origin);
      }

      if (path === "/api/user/refund-credit" && method === "POST") {
        const user = await getUser(request, env);
        if (!user) return errorResponse("Unauthorized", 401, origin);
        if (user.plan !== "unlimited" && user.credits !== -1) {
          user.credits++;
          await saveUser(env, user);
        }
        return jsonResponse({ credits: user.credits }, 200, origin);
      }

      // ══════════════════════════════════════════════════
      //  ANALYZE ROUTE — The core
      // ══════════════════════════════════════════════════

      if (path === "/api/analyze" && method === "POST") {
        let csvText = "", fileName = "data.csv", userQuestion = "Analyze this dataset";
        const ct = request.headers.get("Content-Type") || "";

        if (ct.includes("multipart/form-data")) {
          let fd;
          try { fd = await request.formData(); } catch (e) {
            return errorResponse("Failed to parse form data", 400, origin);
          }
          const file = fd.get("file");
          const q = fd.get("question") || fd.get("prompt") || fd.get("message");
          if (q) userQuestion = sanitizeString(String(q).slice(0, 2000));
          if (file && typeof file.text === "function") {
            fileName = sanitizeString(file.name || "data.csv");
            // File size limit: 20MB
            if (file.size > 20 * 1024 * 1024) {
              return errorResponse("File too large. Maximum 20MB.", 413, origin);
            }
            csvText = await file.text();
          } else if (typeof file === "string") {
            csvText = file;
          }
          // Fallback: check other form fields for CSV data
          if (!csvText || csvText.trim().length < 5) {
            for (const [k, v] of fd.entries()) {
              if (typeof v === "string" && v.length > 15 && v.includes(",") && v.includes("\n")) {
                csvText = v;
                break;
              }
            }
          }
        } else {
          const body = await getJSON();
          if (body) {
            const { messages, fileData } = body;
            if (fileData?.text) {
              csvText = fileData.text;
              if (fileData.name) fileName = sanitizeString(fileData.name);
            }
            const lastUser = (messages || []).filter(m => m.role === "user").pop();
            if (lastUser?.content) {
              userQuestion = sanitizeString(String(lastUser.content).slice(0, 2000));
            }
          }
        }

        // Final fallback: treat user question as data if it looks like CSV
        if ((!csvText || csvText.trim().length < 5) && userQuestion.includes(",") && userQuestion.includes("\n")) {
          csvText = userQuestion;
        }

        if (!csvText || csvText.trim().length < 5) {
          return errorResponse("No data provided. Upload a CSV/Excel file or paste data.", 400, origin);
        }

        // ── Parse ────────────────────────────────────────
        const { headers, records } = parseInput(csvText.slice(0, 10_000_000));

        // ── Text-only path (no tabular data) ────────────
        if (records.length === 0) {
          // Guard: if no real data content, return structured error immediately
          const looksLikeData = csvText && csvText.includes('\n') && (
            csvText.includes(',') || csvText.includes('	') || csvText.includes('|')
          );
          const isVeryShort = !csvText || csvText.trim().length < 30;
          if (isVeryShort || (!looksLikeData && csvText.trim().split('\n').length < 3)) {
            return errorResponse(
              "No data detected. Please upload a CSV/Excel file or paste tabular data (rows and columns). " +
              "If you pasted data, ensure it has headers and at least 2 rows separated by commas or tabs.",
              400, origin
            );
          }
          const textSys = `You are NEXUS, an expert business analyst.
The user has shared text-form business data or a scenario.
Analyze it. Extract key metrics, identify patterns, and provide specific recommendations.
Be concise. Be precise. Do not pad.
Format: ▶ SECTION HEADERS, **bold** key metrics, ◆ NEXUS VERDICT at end.`;
          let insight = null;
          try {
            const groqRes = await callGroq(textSys,
              `Question: ${userQuestion}\n\nData:\n${csvText.slice(0, 4000)}`, env);
            if (groqRes?.ok) {
              const d = await groqRes.json();
              insight = d.choices?.[0]?.message?.content || null;
            }
          } catch { /* Fall through to Gemini */ }
          if (!insight) {
            insight = await callGemini(textSys,
              `Question: ${userQuestion}\n\nData:\n${csvText.slice(0, 4000)}`, env);
          }
          if (!insight) insight = "Unable to complete text analysis. Please try again.";

          return jsonResponse(scrubForJSON({
            insight, metrics: {}, data_quality: { clean_rate: 100, issues: [], rows_before: 0 },
            anomalies: { anomalies: [], count: 0 }, cohorts: null,
            confidence: "MEDIUM", dataset_type: "text_analysis",
            detected_cols: {}, intent: { primary: "general" },
            schema: { headers: [], row_count: 0, clean_count: 0 },
            judgment: { analysisTier: "TEXT", mandatoryPreamble: [] },
            ranked_findings: []
          }), 200, origin);
        }

        // ── Schema & Type Detection ───────────────────────
        let detected = detectSchema(headers);

        // Auto-detect revenue column if not found by name
        if (!detected.revenue) {
          for (const h of headers) {
            const sample = records.slice(0, 20)
              .map(row => { try { return safeNumber(row[h]); } catch { return null; } })
              .filter(v => v !== null && v > 0);
            if (sample.length >= 5) { detected.revenue = h; break; }
          }
        }

        const dsType = inferDatasetType(detected, headers);
        const intent = parseIntent(userQuestion, dsType);

        // ── Clean Data ────────────────────────────────────
        const { cleaned, dataQuality } = cleanData(records, detected);

        // ── Judgment Engine ───────────────────────────────
        const judgment = runJudgmentEngine(cleaned, detected, dataQuality, cleaned.length);

        // ── Compute Metrics ───────────────────────────────
        const metrics = computeMetrics(cleaned, detected, headers, judgment);

        // ── Detect Anomalies ──────────────────────────────
        const anomalyResult = detectAnomalies(cleaned, detected);

        // ── Compute Cohorts ───────────────────────────────
        const cohortResult = computeCohorts(cleaned, detected);

        // ── Score Confidence ──────────────────────────────
        const confidence = scoreConfidence(cleaned, dataQuality, detected, anomalyResult, judgment);

        // ── Recommendations permission ────────────────────
        // Only allow if tier is DIRECTIONAL or above AND there are HIGH/MEDIUM findings
        judgment.permissions.canShowRecommendations =
          judgment.analysisTier !== "FACTS_ONLY" &&
          !judgment.qualityBlocksAnalysis;

        // ── Rank Findings ─────────────────────────────────
        const rankedFindings = rankFindings(metrics, anomalyResult, judgment, detected, dataQuality);

        // ── Build Prompt ──────────────────────────────────
        const { sysPrompt, userMsg } = buildPrompt(
          metrics, detected, dataQuality, anomalyResult, cohortResult,
          dsType, intent, fileName, userQuestion, confidence, judgment, rankedFindings
        );

        // ── Call LLM with retry ───────────────────────────
        let insight = null;
        let attempts = 0;

        while (attempts < 2 && !insight) {
          attempts++;
          try {
            const groqRes = await callGroq(sysPrompt, userMsg, env);
            if (groqRes?.ok) {
              const d = await groqRes.json();
              insight = d.choices?.[0]?.message?.content || null;
            } else if (groqRes?.status === 429) {
              const errText = await groqRes.text();
              const waitMatch = errText.match(/try again in ([0-9.]+)s/i);
              if (waitMatch && attempts < 2) {
                await new Promise(r => setTimeout(r, parseFloat(waitMatch[1]) * 1000 + 500));
                continue;
              }
              // Rate limited — try Gemini
              insight = await callGemini(sysPrompt, userMsg, env);
            } else {
              console.error("Groq error:", groqRes?.status);
            }
          } catch (e) {
            console.error("LLM call error:", e.message);
            if (attempts >= 2) {
              insight = await callGemini(sysPrompt, userMsg, env);
            }
          }
        }

        // ── Fallback if LLM completely unavailable ────────
        if (!insight) {
          insight = buildFallbackNarrative(
            metrics, detected, dataQuality, anomalyResult,
            confidence, judgment, rankedFindings
          );
        }

        // ── Post-generation validation ────────────────────
        insight = validateAndSanitizeOutput(insight, metrics, rankedFindings, judgment);

        // ── Log analysis activity ─────────────────────────
        await logActivity(env, ip, "ANALYSIS", {
          fileName, rows: cleaned.length, confidence, tier: judgment.analysisTier
        });

        return jsonResponse(scrubForJSON({
          insight, metrics, data_quality: dataQuality,
          anomalies: anomalyResult, cohorts: cohortResult,
          confidence, dataset_type: dsType, detected_cols: detected,
          intent: { primary: intent.primary },
          schema: { headers, row_count: records.length, clean_count: cleaned.length },
          judgment: {
            analysisTier: judgment.analysisTier,
            mandatoryPreamble: judgment.mandatoryPreamble,
            distortions: judgment.distortions,
            contradictions: judgment.contradictions,
            dominance: judgment.dominance,
            temporalQuality: judgment.temporalQuality,
            permissions: judgment.permissions
          },
          ranked_findings: rankedFindings
        }), 200, origin);
      }

      // ══════════════════════════════════════════════════
      //  PAYMENT ROUTES
      // ══════════════════════════════════════════════════

      if (path === "/api/payment-request" && method === "POST") {
        const body = await getJSON();
        const { plan, utr, name, email, phone } = body || {};
        if (!utr || !name || !email) {
          return errorResponse("Missing required fields: name, email, utr", 400, origin);
        }
        if (!email.includes("@") || email.length > 200) {
          return errorResponse("Invalid email", 400, origin);
        }
        if (env.NEXUS_KV) {
          try { await env.NEXUS_KV.put(
            `payment:${sanitizeString(utr)}`,
            JSON.stringify({
              plan: sanitizeString(plan || "starter"),
              utr: sanitizeString(utr),
              name: sanitizeString(name),
              email: sanitizeString(email),
              phone: sanitizeString(phone || ""),
              status: "pending",
              createdAt: new Date().toISOString(),
              ip
            })
          ); } catch (e) { console.error("Payment KV error:", e.message); }
        }
        return jsonResponse({ ok: true, message: "Payment request received" }, 200, origin);
      }

      if (path === "/api/notify" && method === "POST") {
        const body = await getJSON();
        const email = sanitizeString(body?.email || "");
        if (!email.includes("@")) return errorResponse("Invalid email", 400, origin);
        if (env.NEXUS_KV) {
          try {
            await env.NEXUS_KV.put(`notify:${email}`, JSON.stringify({
              email, at: new Date().toISOString()
            }));
          } catch (e) { console.error("Notify KV error:", e.message); }
        }
        return jsonResponse({ ok: true }, 200, origin);
      }

      // ══════════════════════════════════════════════════
      //  ADMIN ROUTES — secured by ADMIN_SECRET
      // ══════════════════════════════════════════════════

      const adminSecret = request.headers.get("x-admin-secret");
      if (path.startsWith("/api/admin/")) {
        if (!adminSecret || adminSecret !== env.ADMIN_SECRET) {
          return errorResponse("Forbidden", 403, origin);
        }
      }

      if (path === "/api/admin/users" && method === "GET") {
        if (!env.NEXUS_KV) return errorResponse("KV not available", 503, origin);
        try {
          const [list, pList] = await Promise.all([
            env.NEXUS_KV.list({ prefix: "user:" }),
            env.NEXUS_KV.list({ prefix: "payment:" })
          ]);
          const users = [];
          for (const key of list.keys) {
            try { const raw = await env.NEXUS_KV.get(key.name); if (raw) users.push(JSON.parse(raw)); } catch { /* Skip */ }
          }
          const payments = [];
          for (const key of pList.keys) {
            try { const raw = await env.NEXUS_KV.get(key.name); if (raw) payments.push(JSON.parse(raw)); } catch { /* Skip */ }
          }
          return jsonResponse({ users, payments }, 200, origin);
        } catch (e) {
          return errorResponse("Failed to retrieve users: " + e.message, 500, origin);
        }
      }

      if (path === "/api/admin/activate" && method === "POST") {
        const body = await getJSON();
        const { email, plan, credits } = body || {};
        if (!email) return errorResponse("Missing email", 400, origin);
        if (!env.NEXUS_KV) return errorResponse("KV not available", 503, origin);
        try {
          const raw = await env.NEXUS_KV.get(`user:${email}`);
          if (!raw) return errorResponse("User not found", 404, origin);
          const user = JSON.parse(raw);
          user.plan = sanitizeString(plan || "pro");
          user.credits = plan === "unlimited" ? -1 : (parseInt(credits) || 100);
          user.active = true;
          await saveUser(env, user);
          return jsonResponse({ ok: true, user }, 200, origin);
        } catch (e) {
          return errorResponse("Activation failed: " + e.message, 500, origin);
        }
      }

      if (path === "/api/admin/check-secrets" && method === "GET") {
        return jsonResponse({
          config: {
            GROQ_API_KEY: !!env.GROQ_API_KEY,
            GEMINI_API_KEY: !!env.GEMINI_API_KEY,
            GOOGLE_CLIENT_ID: !!env.GOOGLE_CLIENT_ID,
            JWT_SECRET: !!env.JWT_SECRET,
            ADMIN_SECRET: !!env.ADMIN_SECRET,
            FREE_CREDITS: !!env.FREE_CREDITS,
            NEXUS_KV: !!env.NEXUS_KV
          }
        }, 200, origin);
      }

      if (path === "/api/admin/logs" && method === "GET") {
        if (!env.NEXUS_KV) return errorResponse("KV not available", 503, origin);
        try {
          const list = await env.NEXUS_KV.list({ prefix: "log:" });
          const logs = [];
          for (const key of list.keys) {
            try { const raw = await env.NEXUS_KV.get(key.name); if (raw) logs.push(JSON.parse(raw)); } catch { /* Skip */ }
          }
          return jsonResponse({ logs: logs.sort((a, b) => b.ts - a.ts).slice(0, 200) }, 200, origin);
        } catch (e) {
          return errorResponse("Failed to retrieve logs: " + e.message, 500, origin);
        }
      }

      if (path === "/api/admin/blacklist" && method === "POST") {
        const body = await getJSON();
        if (!body?.ip) return errorResponse("Missing ip", 400, origin);
        if (!env.NEXUS_KV) return errorResponse("KV not available", 503, origin);
        try {
          await env.NEXUS_KV.put(`blacklist:${body.ip}`, "manual", {
            expirationTtl: body.duration || 86400
          });
        } catch (e) { return errorResponse("Blacklist failed: " + e.message, 500, origin); }
        return jsonResponse({ ok: true }, 200, origin);
      }

      // ── 404 ───────────────────────────────────────────
      return errorResponse("Not found", 404, origin);

    } catch (e) {
      // Top-level error handler — never crash
      console.error("Worker fatal error:", e?.message || e, e?.stack || "");
      return errorResponse(
        `Internal error. Please try again. Reference: ${Date.now()}`,
        500, origin
      );
    }
  }
};
