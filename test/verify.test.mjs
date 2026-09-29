// node --test. The fixture below was signed by HackFlow's own Python code
// (app.crypto.sign_record), so this proves the JS canonical JSON matches.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { canonicalJson, verifyDelivery } from "../lib/hackflow.mjs";
import fixture from "./fixture.json" with { type: "json" };

const FIXED_NOW = Date.parse(fixture.delivery.record.issued_at) + 1000;

test("canonical JSON matches Python's sort_keys + compact separators + ASCII escapes", () => {
  assert.equal(canonicalJson({ b: 1, a: "é", c: [true, null] }), '{"a":"\\u00e9","b":1,"c":[true,null]}');
  assert.equal(canonicalJson({ emoji: "🦖" }), '{"emoji":"\\ud83e\\udd96"}');
});

test("a delivery signed by HackFlow verifies", () => {
  const r = verifyDelivery(fixture.delivery, fixture.public_key, { now: FIXED_NOW });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.record.topic, fixture.delivery.record.topic);
});

test("a tampered record is rejected", () => {
  const forged = structuredClone(fixture.delivery);
  forged.record.event_id += 1;
  assert.equal(verifyDelivery(forged, fixture.public_key, { now: FIXED_NOW }).ok, false);
});

test("a delivery signed with the attacker's own key is rejected, even with that key in the body", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "jwk" }).x;
  const record = { ...fixture.delivery.record, topic: "event.results_revealed" };
  const forged = {
    record,
    signature: sign(null, Buffer.from(canonicalJson(record)), privateKey).toString("base64"),
    public_key: Buffer.from(raw, "base64url").toString("base64"),
    algorithm: "ed25519",
  };
  const r = verifyDelivery(forged, fixture.public_key, { now: FIXED_NOW });
  assert.equal(r.ok, false);
});

test("replays are rejected: stale, and repeated delivery ids", () => {
  const stale = verifyDelivery(fixture.delivery, fixture.public_key, { now: FIXED_NOW + 3600_000 });
  assert.equal(stale.ok, false);
  const seen = new Set();
  assert.equal(verifyDelivery(fixture.delivery, fixture.public_key, { now: FIXED_NOW, seen }).ok, true);
  assert.equal(verifyDelivery(fixture.delivery, fixture.public_key, { now: FIXED_NOW, seen }).ok, false);
});
