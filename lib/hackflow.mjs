// A tiny HackFlow API client and webhook verifier. Node 18+ standard library
// only: fetch for the REST API, node:crypto for Ed25519. No dependencies.

import { createPublicKey, verify as cryptoVerify } from "node:crypto";

// ---------------------------------------------------------------------------
// REST API, authenticated with an organizer's API key (Authorization: Bearer)
// ---------------------------------------------------------------------------

export class HackFlowClient {
  constructor({ baseUrl, apiKey, fetchImpl = globalThis.fetch }) {
    if (!baseUrl) throw new Error("HACKFLOW_URL is not set");
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.fetch = fetchImpl;
  }

  async request(method, path, body) {
    const headers = { Accept: "application/json" };
    if (this.apiKey) headers.Authorization = `Bearer ${this.apiKey}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await this.fetch(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let data = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      /* CSV and other non-JSON bodies stay as text */
    }
    if (!res.ok) {
      const detail = data && typeof data === "object" && data.detail ? JSON.stringify(data.detail) : text;
      const err = new Error(`${method} ${path} -> ${res.status}: ${detail}`);
      err.status = res.status;
      err.retryAfter = res.headers.get("retry-after");
      throw err;
    }
    return data;
  }

  get(path) { return this.request("GET", path); }
  post(path, body) { return this.request("POST", path, body ?? {}); }
  delete(path) { return this.request("DELETE", path); }

  // The calls this demo uses. Every one is a documented endpoint (/docs).
  me() { return this.get("/api/auth/me"); }
  publicKey() { return this.get("/api/public-key"); }
  events() { return this.get("/api/events"); }
  gallery(eventId) { return this.get(`/api/gallery?event_id=${encodeURIComponent(eventId)}`); }
  results(eventId) { return this.get(`/api/events/${eventId}/results`); }
  scoresCsv(eventId) { return this.get(`/api/events/${eventId}/export/scores.csv`); }
  listWebhooks(eventId) { return this.get(`/api/events/${eventId}/webhooks`); }
  createWebhook(eventId, url) { return this.post(`/api/events/${eventId}/webhooks`, { url }); }
  deleteWebhook(eventId, id) { return this.delete(`/api/events/${eventId}/webhooks/${id}`); }
  testWebhook(eventId, id) { return this.post(`/api/events/${eventId}/webhooks/${id}/test`); }
  announce(eventId, title, body) {
    return this.post(`/api/events/${eventId}/announcements`, { title, body, email_participants: false });
  }
}

// ---------------------------------------------------------------------------
// Webhook signatures
//
// HackFlow POSTs {record, signature, public_key, algorithm: "ed25519"}. The
// signature covers the *canonical JSON* of `record`: keys sorted, no spaces,
// non-ASCII escaped as \uXXXX (Python's json.dumps(sort_keys=True,
// separators=(",", ":"))). Verify against the key you fetched yourself from
// GET /api/public-key - NEVER against the public_key inside the body, which
// anyone forging a delivery would simply replace with their own.
// ---------------------------------------------------------------------------

function escapeNonAscii(json) {
  // Per UTF-16 unit, so an emoji becomes a surrogate pair exactly as in Python.
  return json.replace(/[\u0080-￿]/g, (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
}

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isInteger(value)) {
      // JS prints 4.0 as "4" where Python prints "4.0"; HackFlow's webhook
      // records carry only ids, strings and booleans, so refuse rather than
      // silently mis-verify if that ever changes.
      throw new Error("canonicalJson: non-integer numbers are not supported");
    }
    return escapeNonAscii(JSON.stringify(value));
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => escapeNonAscii(JSON.stringify(k)) + ":" + canonicalJson(value[k])).join(",") + "}";
}

export function publicKeyFromBase64(rawB64) {
  const raw = Buffer.from(rawB64, "base64");
  if (raw.length !== 32) throw new Error("expected a 32-byte raw Ed25519 public key");
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" });
}

/**
 * Verify one delivery. Returns {ok: true, record} or {ok: false, reason}.
 * `trustedKeyB64` is the key from GET /api/public-key, fetched over HTTPS.
 */
export function verifyDelivery(body, trustedKeyB64, { maxAgeSeconds = 300, now = Date.now(), seen } = {}) {
  if (!body || typeof body !== "object" || !body.record || typeof body.signature !== "string") {
    return { ok: false, reason: "not a HackFlow delivery" };
  }
  if (body.algorithm !== "ed25519") return { ok: false, reason: `unsupported algorithm ${body.algorithm}` };
  if (body.public_key && body.public_key !== trustedKeyB64) {
    return { ok: false, reason: "signed with a key that is not this HackFlow's" };
  }
  let valid = false;
  try {
    const message = Buffer.from(canonicalJson(body.record), "utf8");
    valid = cryptoVerify(null, message, publicKeyFromBase64(trustedKeyB64), Buffer.from(body.signature, "base64"));
  } catch (e) {
    return { ok: false, reason: `could not verify: ${e.message}` };
  }
  if (!valid) return { ok: false, reason: "bad signature" };

  // Replay protection: a genuine delivery is fresh and seen once.
  const issued = Date.parse(body.record.issued_at);
  if (Number.isNaN(issued)) return { ok: false, reason: "no issued_at" };
  if (Math.abs(now - issued) > maxAgeSeconds * 1000) return { ok: false, reason: "stale delivery (possible replay)" };
  const id = body.record.delivery_id;
  if (seen && id) {
    if (seen.has(id)) return { ok: false, reason: "duplicate delivery_id (replay)" };
    seen.add(id);
  }
  return { ok: true, record: body.record };
}
