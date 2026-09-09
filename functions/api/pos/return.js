// functions/api/pos/return.js
//
// POST — return items from a recorded sale. The money changes hands at the
// counter in whatever form the customer paid; this endpoint's job is the
// LEDGER — stock back up (which puts the item back on jinkittys.com on the
// next read), sale lines marked returned, spent store credit restored to
// the customer's balance, and a label reprint link so the item can go back
// on the shelf with a fresh tag.
//
// Body: { saleId: 123, items: [{ saleItemId: 456, qty: 1 }] }
//
// Punches are deliberately not clawed back on a return — the card lives in
// the customer's mind as "I came in ten times", and disputing that over a
// $22 return costs more goodwill than it saves. Store credit spent on the
// sale is returned to the customer's balance proportionally to what came
// back.

import { getProduct, updateProduct } from "../../_lib/store.js";
import { json, posError, requireDb, centsToStr } from "../../_lib/pos.js";

export async function onRequestPost(context) {
  const { request, env } = context;
  const dbMissing = requireDb(env);
  if (dbMissing) return dbMissing;
  const db = env.DB;

  let body;
  try {
    body = await request.json();
  } catch {
    return posError("Invalid JSON body", 400);
  }

  const saleId = Number(body?.saleId);
  if (!Number.isFinite(saleId)) return posError("Missing saleId", 400);

  const sale = await db.prepare("SELECT * FROM sales WHERE id = ?").bind(saleId).first();
  if (!sale) return posError(`Sale #${saleId} not found`, 404);

  const requests = Array.isArray(body?.items) ? body.items : [];
  if (!requests.length) return posError("Nothing to return", 400);

  const { results: saleItems } = await db
    .prepare("SELECT * FROM sale_items WHERE sale_id = ?")
    .bind(saleId)
    .all();
  const byId = new Map((saleItems || []).map((i) => [i.id, i]));

  // Validate the whole return before writing any of it.
  const applied = [];
  for (const req of requests) {
    const line = byId.get(Number(req?.saleItemId));
    if (!line) return posError(`Sale item ${req?.saleItemId} isn't on sale #${saleId}`, 400);
    const qty = Math.max(1, Math.floor(Number(req?.qty)) || 1);
    const returnable = line.qty - line.returned_qty;
    if (qty > returnable) {
      return posError(`Only ${returnable} of "${line.name}" can still be returned`, 400);
    }
    applied.push({ line, qty });
  }

  // Restock. Manual checkout records restock too — the item now exists in
  // inventory, so a return puts it on the site; staff can reprint a label
  // for it and shelve it like anything else.
  const restocked = [];
  for (const { line, qty } of applied) {
    if (!line.item_id) continue;
    const product = await getProduct(env, line.item_id);
    if (!product) continue; // deleted from admin since — nothing to restock
    product.quantity = (Number(product.quantity) || 0) + qty;
    product.inStock = true;
    await updateProduct(env, product);
    restocked.push({
      id: product.id,
      name: product.name,
      labelUrl: `/pos-label?id=${encodeURIComponent(product.id)}`,
    });
  }

  // Credit refund: the share of spent credit belonging to the returned
  // goods, in cents, rounded down — the shop keeps the rounding penny.
  let creditBackCents = 0;
  if (sale.credit_used_cents > 0 && sale.customer_id && sale.subtotal_cents > 0) {
    const returnedValue = applied.reduce((s, { line, qty }) => s + line.price_cents * qty, 0);
    creditBackCents = Math.floor(
      (sale.credit_used_cents * returnedValue) / sale.subtotal_cents
    );
  }

  const nowIso = new Date().toISOString();
  const statements = applied.map(({ line, qty }) =>
    db
      .prepare("UPDATE sale_items SET returned_qty = returned_qty + ? WHERE id = ?")
      .bind(qty, line.id)
  );

  // Recompute status from what the lines will look like after this update.
  const futureReturned = new Map(applied.map(({ line, qty }) => [line.id, line.returned_qty + qty]));
  const allReturned = (saleItems || []).every(
    (l) => (futureReturned.get(l.id) ?? l.returned_qty) >= l.qty
  );
  statements.push(
    db
      .prepare("UPDATE sales SET status = ? WHERE id = ?")
      .bind(allReturned ? "returned" : "partial_return", saleId)
  );

  if (creditBackCents > 0) {
    statements.push(
      db
        .prepare("UPDATE customers SET credit_cents = credit_cents + ? WHERE id = ?")
        .bind(creditBackCents, sale.customer_id)
    );
    statements.push(
      db
        .prepare(
          "INSERT INTO loyalty_events (customer_id, sale_id, type, amount_cents, note, created_at) VALUES (?, ?, 'credit_refund', ?, 'return', ?)"
        )
        .bind(sale.customer_id, saleId, creditBackCents, nowIso)
    );
  }

  await db.batch(statements);

  const refundValueCents = applied.reduce((s, { line, qty }) => s + line.price_cents * qty, 0);
  const refundTaxCents = Math.round(
    Math.max(0, refundValueCents - creditBackCents) * sale.tax_rate
  );

  return json({
    ok: true,
    saleId,
    status: allReturned ? "returned" : "partial_return",
    restocked,
    refund: {
      value: centsToStr(refundValueCents),
      creditBack: centsToStr(creditBackCents),
      tax: centsToStr(refundTaxCents),
      cashOrCard: centsToStr(refundValueCents - creditBackCents + refundTaxCents),
    },
  });
}
