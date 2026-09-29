// Raptor Relay - a third-party app that plugs into HackFlow the way any
// outside integration would: an organizer's API key to read and act, signed
// webhooks to hear about everything as it happens.
//
//   node server.mjs            (Node 18+, no npm install needed)
//
// Configuration is environment variables; see .env.example and README.md.

import { createServer } from "node:http";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { timingSafeEqual } from "node:crypto";
import { HackFlowClient, verifyDelivery } from "./lib/hackflow.mjs";

const here = dirname(fileURLToPath(import.meta.url));
loadDotEnv(join(here, ".env"));

const config = {
  hackflowUrl: process.env.HACKFLOW_URL || "http://localhost:8000",
  apiKey: process.env.HACKFLOW_API_KEY || "",
  eventId: process.env.HACKFLOW_EVENT_ID ? Number(process.env.HACKFLOW_EVENT_ID) : null,
  port: Number(process.env.PORT || 4000),
  host: process.env.HOST || "0.0.0.0",
  // The address HackFlow should POST webhooks to (this app, as HackFlow sees it).
  publicUrl: (process.env.PUBLIC_URL || "").replace(/\/+$/, ""),
  // Optional: protects the dashboard and its buttons (never the webhook route,
  // which is protected by its signature instead).
  dashboardPassword: process.env.DASHBOARD_PASSWORD || "",
  dataFile: process.env.DATA_FILE || join(here, "data", "feed.json"),
};

const client = new HackFlowClient({ baseUrl: config.hackflowUrl, apiKey: config.apiKey });

const state = {
  me: null,
  trustedKey: null,
  events: [],
  feed: loadFeed(),
  rejected: 0,
  lastError: null,
};
const seenDeliveries = new Set(state.feed.map((f) => f.record.delivery_id).filter(Boolean));
const streams = new Set();

// ---------------------------------------------------------------------------

async function connect() {
  try {
    // Pin the signing key once, over the same channel we trust for the API.
    state.trustedKey = (await client.publicKey()).public_key;
    state.me = config.apiKey ? await client.me() : null;
    state.events = await client.events();
    if (config.eventId == null && state.events.length) config.eventId = state.events[0].id;
    state.lastError = null;
    console.log(
      `[relay] connected to ${config.hackflowUrl} as ${state.me ? `${state.me.name} (${state.me.role})` : "anonymous"}; ` +
        `signing key ${state.trustedKey.slice(0, 12)}...`,
    );
  } catch (e) {
    state.lastError = e.message;
    console.error(`[relay] could not reach HackFlow: ${e.message} (retrying in 10s)`);
    setTimeout(connect, 10_000);
  }
}

function broadcast(entry) {
  const line = `data: ${JSON.stringify(entry)}\n\n`;
  for (const res of streams) res.write(line);
}

function remember(record) {
  const entry = { received_at: new Date().toISOString(), record };
  state.feed.unshift(entry);
  state.feed.length = Math.min(state.feed.length, 200);
  try {
    mkdirSync(dirname(config.dataFile), { recursive: true });
    writeFileSync(config.dataFile, JSON.stringify(state.feed, null, 2));
  } catch (e) {
    console.error(`[relay] could not save feed: ${e.message}`);
  }
  broadcast(entry);
  return entry;
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const MAX_BODY = 256 * 1024;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(Object.assign(new Error("body too large"), { status: 413 }));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function send(res, status, body, type = "application/json") {
  const payload = type === "application/json" ? JSON.stringify(body) : body;
  res.writeHead(status, {
    "Content-Type": `${type}; charset=utf-8`,
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
  });
  res.end(payload);
}

function authorized(req) {
  if (!config.dashboardPassword) return true;
  const [scheme, value] = (req.headers.authorization || "").split(" ");
  if (scheme !== "Basic" || !value) return false;
  const password = Buffer.from(value, "base64").toString("utf8").split(":").slice(1).join(":");
  const a = Buffer.from(password);
  const b = Buffer.from(config.dashboardPassword);
  return a.length === b.length && timingSafeEqual(a, b);
}

async function handleWebhook(req, res) {
  let body;
  try {
    body = JSON.parse(await readBody(req));
  } catch (e) {
    return send(res, e.status || 400, { error: "invalid JSON" });
  }
  if (!state.trustedKey) {
    // Never accept unverifiable deliveries; HackFlow records the failure.
    return send(res, 503, { error: "signing key not fetched yet" });
  }
  const result = verifyDelivery(body, state.trustedKey, { seen: seenDeliveries });
  if (!result.ok) {
    state.rejected += 1;
    console.warn(`[relay] rejected delivery: ${result.reason}`);
    return send(res, 401, { error: result.reason });
  }
  const topic = req.headers["x-hackflow-topic"] || result.record.topic;
  console.log(`[relay] verified ${topic} for event ${result.record.event_id}`);
  remember(result.record);
  return send(res, 200, { ok: true });
}

async function handleAction(name, req, res) {
  const input = JSON.parse((await readBody(req)) || "{}");
  const eventId = Number(input.event_id || config.eventId);
  switch (name) {
    case "refresh":
      await connect();
      return send(res, 200, { ok: true });
    case "register-webhook": {
      if (!config.publicUrl) return send(res, 400, { error: "Set PUBLIC_URL so HackFlow knows where to send webhooks." });
      const url = `${config.publicUrl}/webhooks/hackflow`;
      const existing = (await client.listWebhooks(eventId)).find((w) => w.url === url);
      const hook = existing || (await client.createWebhook(eventId, url));
      const ping = await client.testWebhook(eventId, hook.id);
      return send(res, 200, { webhook: hook, test: ping });
    }
    case "announce": {
      const title = String(input.title || "").trim() || "Update from Raptor Relay";
      const text = String(input.body || "").trim() || "Posted through the HackFlow API with an API key.";
      return send(res, 200, await client.announce(eventId, title, text));
    }
    default:
      return send(res, 404, { error: "no such action" });
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://relay.local");
  try {
    if (req.method === "POST" && url.pathname === "/webhooks/hackflow") return await handleWebhook(req, res);
    if (url.pathname === "/healthz") return send(res, 200, { ok: true });

    if (!authorized(req)) {
      res.writeHead(401, { "WWW-Authenticate": 'Basic realm="Raptor Relay"' });
      return res.end("Sign in with DASHBOARD_PASSWORD.");
    }
    if (req.method === "GET" && url.pathname === "/") {
      return send(res, 200, readFileSync(join(here, "public", "index.html"), "utf8"), "text/html");
    }
    if (req.method === "GET" && url.pathname === "/stream") {
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-store", Connection: "keep-alive" });
      res.write(": connected\n\n");
      streams.add(res);
      req.on("close", () => streams.delete(res));
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/state") {
      return send(res, 200, {
        hackflow_url: config.hackflowUrl,
        public_url: config.publicUrl,
        event_id: config.eventId,
        me: state.me,
        key_fingerprint: state.trustedKey ? state.trustedKey.slice(0, 12) : null,
        events: state.events.map((e) => ({ id: e.id, name: e.name, slug: e.slug })),
        feed: state.feed,
        rejected: state.rejected,
        last_error: state.lastError,
      });
    }
    if (req.method === "GET" && url.pathname === "/api/snapshot") {
      const eventId = Number(url.searchParams.get("event_id") || config.eventId);
      const [gallery, results] = await Promise.allSettled([client.gallery(eventId), client.results(eventId)]);
      return send(res, 200, {
        gallery: gallery.status === "fulfilled" ? gallery.value : { error: gallery.reason.message },
        results: results.status === "fulfilled" ? results.value : { error: results.reason.message },
      });
    }
    if (req.method === "POST" && url.pathname.startsWith("/actions/")) {
      return await handleAction(url.pathname.slice("/actions/".length), req, res);
    }
    return send(res, 404, { error: "not found" });
  } catch (e) {
    console.error(`[relay] ${req.method} ${url.pathname}: ${e.message}`);
    return send(res, e.status && e.status < 600 ? e.status : 502, { error: e.message });
  }
});

// ---------------------------------------------------------------------------

function loadFeed() {
  try {
    return existsSync(config.dataFile) ? JSON.parse(readFileSync(config.dataFile, "utf8")) : [];
  } catch {
    return [];
  }
}

function loadDotEnv(path) {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  server.listen(config.port, config.host, () => {
    console.log(`[relay] dashboard on http://localhost:${config.port}  webhook endpoint /webhooks/hackflow`);
    connect();
  });
}

export { server, state, config, connect };
