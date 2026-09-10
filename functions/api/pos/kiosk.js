// functions/api/pos/kiosk.js
//
// Register side of customer check-in. GET fetches-and-consumes the newest
// check-in from the last two minutes (older ones are an earlier customer,
// not the person now paying). Admin-gated like all of /api/pos/.
//
// Entries are written by POST /api/checkin — the PUBLIC endpoint behind
// the /checkin page that customers open from the counter's NFC sticker or
// QR card on their own phone (or on the shop's tablet). See
// functions/api/checkin.js for why public is safe there.
//
// One row is consumed exactly once, so a second poll doesn't re-fill a
// field staff cleared, and the table cleans itself up on every read.

import { json, requireDb } from "../../_lib/pos.js";

const FRESH_MS = 2 * 60 * 1000;

export async function onRequestGet(context) {
  const { env } = context;
  const dbMissing = requireDb(env);
  if (dbMissing) return dbMissing;

  const cutoff = new Date(Date.now() - FRESH_MS).toISOString();
  const row = await env.DB.prepare(
    "SELECT * FROM kiosk_entries WHERE consumed = 0 AND created_at > ? ORDER BY id DESC LIMIT 1"
  ).bind(cutoff).first();

  if (row) {
    await env.DB.prepare("UPDATE kiosk_entries SET consumed = 1 WHERE id = ?")
      .bind(row.id)
      .run();
  }
  // Housekeeping: drop consumed and stale rows so the table stays tiny.
  await env.DB.prepare(
    "DELETE FROM kiosk_entries WHERE consumed = 1 OR created_at <= ?"
  ).bind(cutoff).run();

  return json({
    ok: true,
    entry: row ? { email: row.email, name: row.name } : null,
  });
}
