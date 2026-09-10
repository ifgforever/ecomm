// functions/api/checkin.js
//
// PUBLIC endpoint behind /checkin — the page a customer opens on their own
// phone from the counter's NFC sticker or QR card (no login; it's their
// phone). Deliberately does very little: validate an email, drop it into
// the two-minute pairing buffer the register polls, done.
//
// Why public is acceptable:
//   - Writing here grants nothing: an entry only ever pre-fills the email
//     box on the register, visibly, when that box is empty — staff see it
//     land and can clear it. No sale, no customer record, no credit is
//     created until staff complete a sale.
//   - Entries expire after two minutes and the buffer is capped, so junk
//     POSTs age out on their own and can't grow the table.
//   - No data ever comes back out: the response reveals nothing, and
//     reading the buffer stays admin-only (/api/pos/kiosk).

import { json, posError, requireDb, normalizeEmail } from "../_lib/pos.js";

const MAX_PENDING = 25;

export async function onRequestPost(context) {
  const { request, env } = context;
  const dbMissing = requireDb(env);
  if (dbMissing) return dbMissing;

  let body;
  try {
    body = await request.json();
  } catch {
    return posError("Invalid request", 400);
  }

  const email = normalizeEmail(body?.email);
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return posError("That email doesn't look right — please check it.", 400);
  }

  await env.DB.prepare(
    "INSERT INTO kiosk_entries (email, name, created_at) VALUES (?, ?, ?)"
  ).bind(email, String(body?.name || "").trim().slice(0, 80), new Date().toISOString()).run();

  // Cap the pending buffer so a burst of junk can't grow the table.
  await env.DB.prepare(
    `DELETE FROM kiosk_entries WHERE consumed = 0 AND id NOT IN
       (SELECT id FROM kiosk_entries WHERE consumed = 0 ORDER BY id DESC LIMIT ?)`
  ).bind(MAX_PENDING).run();

  return json({ ok: true });
}
