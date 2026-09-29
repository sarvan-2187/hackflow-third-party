// End-to-end walkthrough from the terminal: proves the API key works, pulls
// data, registers this app's webhook and asks HackFlow for a signed test ping.
//
//   HACKFLOW_URL=http://localhost:8000 HACKFLOW_API_KEY=hf_... PUBLIC_URL=http://host:4000 node scripts/demo.mjs

import { HackFlowClient } from "../lib/hackflow.mjs";

const client = new HackFlowClient({ baseUrl: process.env.HACKFLOW_URL || "http://localhost:8000", apiKey: process.env.HACKFLOW_API_KEY });
const step = (n, text) => console.log(`\n${n}. ${text}`);

step(1, "Who does this key act as?");
const me = await client.me();
console.log(`   ${me.name} <${me.email}>, role ${me.role}`);

step(2, "HackFlow's webhook signing key (pin this; never trust the key inside a delivery)");
const { public_key } = await client.publicKey();
console.log(`   ed25519 ${public_key}`);

step(3, "Events visible to this key");
const events = await client.events();
for (const e of events) console.log(`   #${e.id}  ${e.slug.padEnd(24)} ${e.name}`);
const eventId = Number(process.env.HACKFLOW_EVENT_ID || events[0]?.id);

step(4, `Public gallery and normalised standings for event #${eventId}`);
const gallery = await client.gallery(eventId);
console.log(`   ${gallery.length} projects in the gallery`);
try {
  const results = await client.results(eventId);
  for (const r of results.slice(0, 5)) {
    console.log(`   ${String(r.rank).padStart(2)}. ${r.submission_title.padEnd(28)} z=${r.z_bar.toFixed(3)}  judges ${r.judges}/${r.assigned_judges}`);
  }
  if (!results.length) console.log("   (no scores yet)");
} catch (e) {
  console.log(`   results: ${e.message}`);
}

if (process.env.PUBLIC_URL) {
  step(5, "Subscribe this app to the event's webhooks and fire a test ping");
  const url = `${process.env.PUBLIC_URL.replace(/\/+$/, "")}/webhooks/hackflow`;
  const hook = (await client.listWebhooks(eventId)).find((w) => w.url === url) || (await client.createWebhook(eventId, url));
  const ping = await client.testWebhook(eventId, hook.id);
  console.log(`   webhook #${hook.id} -> ${url}: test ${ping.last_status}`);
} else {
  step(5, "Set PUBLIC_URL to also register this app's webhook (skipped)");
}
console.log("\nDone.");
