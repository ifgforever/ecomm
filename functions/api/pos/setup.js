// functions/api/pos/setup.js
//
// One-stop initialization for the POS database. Safe to open repeatedly:
//   1. Creates every table that doesn't exist yet (CREATE ... IF NOT EXISTS)
//   2. Copies the PRODUCTS_KV "products" array into the D1 items table —
//      but only if the items table is empty. Once D1 has rows it is the
//      live catalogue and re-copying would resurrect sold items, so the
//      copy refuses to run twice.
//
// Visit /api/pos/setup in a browser (logged in as admin — the whole
// /api/pos/ prefix is gated by _middleware.js) after binding the D1
// database as DB in Pages > Settings > Bindings.

import { ensureSchema, migrateFromKv } from "../../_lib/store.js";
import { json, posError, requireDb } from "../../_lib/pos.js";

export async function onRequest(context) {
  const { env } = context;
  const dbMissing = requireDb(env);
  if (dbMissing) return dbMissing;

  try {
    await ensureSchema(env.DB);
    const migration = await migrateFromKv(env);
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM items").first();
    return json({
      ok: true,
      schema: "ready",
      migration,
      itemsInD1: Number(count?.n) || 0,
      note: migration.skipped
        ? "Items table already had rows, so the KV copy was skipped — D1 is the live catalogue."
        : "KV products copied into D1. The site now reads and writes D1.",
    });
  } catch (err) {
    return posError(`Setup failed: ${err.message}`, 500);
  }
}
