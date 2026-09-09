// functions/api/pos/sale.js
//
// POST — ring up a sale. This is the one write that ties the whole system
// together: it decrements stock (which removes the item from jinkittys.com,
// the feeds and the sitemap on their next read), records the sale, and
// applies the punch-card rules from the shop's loyalty card.
//
// Body:
//   {
//     items: [
//       // Scanned or looked-up (labeled) items. `price` is what was
//       // actually charged — checkout lets staff override for haggling;
//       // the listing's own price is recorded alongside as originalPrice.
//       { id: "SKU-1042", price: 12.00, qty: 1 },
//       // Unlabeled items (most of the existing ~800 for a while). These
//       // create a real inventory record, already marked sold, so the sale
//       // is never invisible — the original problem this system exists for.
//       { manual: true, category: "Vintage Toys", price: 8.00, qty: 1, name?: "..." }
//     ],
//     payment: "Cash" | "Card" | "Zelle",   // Card is run on the separate
//                                            // terminal; only recorded here
//     customerEmail?: "x@y.com",
//     customerName?: "...", customerBirthday?: "MM-DD",
//     useCreditCents?: 500,                 // store credit to apply
//     birthdayGift?: true                   // staff pressed the birthday
//                                            // button for a regular
//   }
//
// Loyalty (see _lib/pos.js for the constants, taken off the printed card):
//   - a visit with a $20+ pre-tax purchase earns one punch — at most one
//     punch per Chicago calendar day, because the card counts VISITS
//   - 10 punches convert to $20 store credit and the card resets
//   - 10 lifetime punched visits makes the customer a regular
//   - regulars get a $50 credit once per calendar year via the birthday
//     button (staff-triggered so the gift is a moment at the counter, not
//     silent math)
//
// Tax: Chicago general merchandise, computed on the subtotal after store
// credit — credit granted by the shop works like a discount.
//
// GET — recent sales, newest first, items included (the returns screen and
// the day's tally read this): /api/pos/sale?limit=20 or ?id=123

import { getProduct, insertProduct, updateProduct, nextSku } from "../../_lib/store.js";
import {
  TAX_RATE,
  PUNCH_MIN_CENTS,
  PUNCHES_FOR_CREDIT,
  PUNCH_REWARD_CENTS,
  REGULAR_AFTER_VISITS,
  BIRTHDAY_GIFT_CENTS,
  PAYMENT_TYPES,
  chicagoDay,
  toCents,
  centsToStr,
  json,
  posError,
  requireDb,
  normalizeEmail,
  getOrCreateCustomer,
  findCustomerByEmail,
  customerSummary,
} from "../../_lib/pos.js";

const MANUAL_CATEGORIES = new Set([
  "Labubu & Pop Mart",
  "Hello Kitty & Sanrio",
  "Retro Video Games",
  "Vintage Toys",
  "Funko Pop",
  "Monster High",
  "Other",
]);

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

  const payment = String(body?.payment || "");
  if (!PAYMENT_TYPES.has(payment)) {
    return posError('payment must be "Cash", "Card" or "Zelle"', 400);
  }

  const rawItems = Array.isArray(body?.items) ? body.items : [];
  if (!rawItems.length) return posError("The sale has no items", 400);
  if (rawItems.length > 100) return posError("Too many items in one sale", 400);

  // -------------------------------------------------------------------
  // Resolve every line before writing anything, so a bad line rejects the
  // whole sale instead of half-recording it.
  // -------------------------------------------------------------------
  const lines = [];
  const stockUpdates = []; // existing items whose quantity changes
  const newRecords = [];   // manual items that need an inventory record

  for (const raw of rawItems) {
    const qty = Math.max(1, Math.floor(Number(raw?.qty)) || 1);
    const priceCents = toCents(raw?.price);
    if (!Number.isFinite(priceCents) || priceCents < 0) {
      return posError("Every item needs a valid price", 400);
    }

    if (raw?.manual) {
      const category = MANUAL_CATEGORIES.has(raw?.category) ? raw.category : "Other";
      newRecords.push({
        category,
        name: String(raw?.name || "").trim() || `${category} — unlabeled item`,
        priceCents,
        qty,
      });
      lines.push({
        itemId: null, // filled in once the record is created
        name: String(raw?.name || "").trim() || `${category} — unlabeled item`,
        category,
        priceCents,
        originalPriceCents: priceCents,
        qty,
        manualIndex: newRecords.length - 1,
      });
      continue;
    }

    const id = String(raw?.id || "").trim().toUpperCase();
    if (!id) return posError("An item line is missing its id", 400);
    const product = await getProduct(env, id);
    if (!product) return posError(`${id} isn't in inventory.`, 404);

    lines.push({
      itemId: product.id,
      name: product.name,
      category: product.category || "",
      priceCents,
      originalPriceCents: toCents(product.price),
      qty,
    });
    stockUpdates.push({ product, qty });
  }

  const subtotalCents = lines.reduce((sum, l) => sum + l.priceCents * l.qty, 0);

  // -------------------------------------------------------------------
  // Customer + store credit
  // -------------------------------------------------------------------
  const email = normalizeEmail(body?.customerEmail);
  let customer = null;
  if (email) {
    if (!email.includes("@")) return posError("That customer email doesn't look valid", 400);
    customer = await getOrCreateCustomer(db, email);

    const name = body?.customerName !== undefined
      ? String(body.customerName).trim()
      : customer.name;
    const birthday = /^\d{2}-\d{2}$/.test(String(body?.customerBirthday || ""))
      ? String(body.customerBirthday)
      : customer.birthday;
    if (name !== customer.name || birthday !== customer.birthday) {
      await db.prepare("UPDATE customers SET name = ?, birthday = ? WHERE id = ?")
        .bind(name, birthday, customer.id)
        .run();
      customer = await findCustomerByEmail(db, email);
    }
  }

  const now = new Date();
  const nowIso = now.toISOString();
  const today = chicagoDay(now);
  const thisYear = Number(today.slice(0, 4));
  const loyaltyNotes = [];

  // The $50 birthday gift — staff-triggered, regulars only, once a year.
  // Granted BEFORE credit is applied so it can pay for this very sale.
  let birthdayGiftCents = 0;
  if (body?.birthdayGift) {
    if (!customer) return posError("Add the customer's email before the birthday gift", 400);
    if (customer.lifetime_visits < REGULAR_AFTER_VISITS) {
      return posError("The birthday gift is for regulars (10 punched visits)", 400);
    }
    if (Number(customer.last_birthday_gift_year) === thisYear) {
      return posError("This year's birthday gift was already given", 400);
    }
    birthdayGiftCents = BIRTHDAY_GIFT_CENTS;
    loyaltyNotes.push(`🎂 $${centsToStr(BIRTHDAY_GIFT_CENTS)} birthday gift added`);
  }

  const availableCredit = (customer ? customer.credit_cents : 0) + birthdayGiftCents;
  let creditUsedCents = Math.max(0, Math.floor(Number(body?.useCreditCents) || 0));
  if (creditUsedCents > 0 && !customer) {
    return posError("Store credit needs the customer's email", 400);
  }
  creditUsedCents = Math.min(creditUsedCents, availableCredit, subtotalCents);

  const taxableCents = subtotalCents - creditUsedCents;
  const taxCents = Math.round(taxableCents * TAX_RATE);
  const totalCents = taxableCents + taxCents;

  // -------------------------------------------------------------------
  // Punch-card math
  // -------------------------------------------------------------------
  let punches = customer ? customer.punches : 0;
  let lifetimeVisits = customer ? customer.lifetime_visits : 0;
  let lastPunchDay = customer ? customer.last_punch_day : "";
  let earnedPunch = false;
  let earnedCardReward = false;

  if (customer && subtotalCents >= PUNCH_MIN_CENTS && lastPunchDay !== today) {
    earnedPunch = true;
    punches += 1;
    lifetimeVisits += 1;
    lastPunchDay = today;
    loyaltyNotes.push(`Punch ${punches}/${PUNCHES_FOR_CREDIT}`);
    if (punches >= PUNCHES_FOR_CREDIT) {
      earnedCardReward = true;
      punches -= PUNCHES_FOR_CREDIT;
      loyaltyNotes.push(`🎉 Card complete — $${centsToStr(PUNCH_REWARD_CENTS)} store credit earned`);
    }
    if (lifetimeVisits === REGULAR_AFTER_VISITS) {
      loyaltyNotes.push("⭐ Now a regular customer");
    }
  }

  const newCreditCents = customer
    ? customer.credit_cents
      + birthdayGiftCents
      + (earnedCardReward ? PUNCH_REWARD_CENTS : 0)
      - creditUsedCents
    : 0;

  // -------------------------------------------------------------------
  // Create inventory records for the manual (unlabeled) items first, so
  // their sale lines can reference a real SKU. quantity 0 / inStock false:
  // the record exists, the sale points at it, and it never shows on the
  // site as available.
  // -------------------------------------------------------------------
  for (let i = 0; i < newRecords.length; i++) {
    const rec = newRecords[i];
    const sku = await nextSku(env);
    await insertProduct(env, {
      id: sku,
      name: rec.name,
      price: rec.priceCents / 100,
      category: rec.category,
      quantity: 0,
      inStock: false,
      image: "",
      rotation: 0,
      description: "",
      featured: false,
      pickNote: "",
      createdAt: nowIso,
      posManual: true, // lands in `extra`; marks records created at checkout
    });
    for (const line of lines) {
      if (line.manualIndex === i) line.itemId = sku;
    }
  }

  // Decrement stock on the labeled items. Floor at zero — a scan of
  // something the system thinks is sold still rings up (the shelf is the
  // truth), it just can't go negative.
  for (const { product, qty } of stockUpdates) {
    const newQty = Math.max(0, (Number(product.quantity) || 0) - qty);
    product.quantity = newQty;
    product.inStock = newQty > 0;
    await updateProduct(env, product);
  }

  // -------------------------------------------------------------------
  // Record the sale, its lines, and the loyalty movements in one batch —
  // D1 batches are transactional, so the ledger can't half-write.
  // -------------------------------------------------------------------
  const saleResult = await db
    .prepare(
      `INSERT INTO sales (created_at, subtotal_cents, tax_rate, tax_cents,
        credit_used_cents, total_cents, payment, customer_id, customer_email,
        status, note)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?)`
    )
    .bind(
      nowIso,
      subtotalCents,
      TAX_RATE,
      taxCents,
      creditUsedCents,
      totalCents,
      payment,
      customer ? customer.id : null,
      email,
      String(body?.note || "")
    )
    .run();
  const saleId = saleResult.meta.last_row_id;

  const statements = lines.map((l) =>
    db
      .prepare(
        `INSERT INTO sale_items (sale_id, item_id, name, category, price_cents,
          original_price_cents, qty) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(saleId, l.itemId || "", l.name, l.category, l.priceCents, l.originalPriceCents, l.qty)
  );

  if (customer) {
    statements.push(
      db
        .prepare(
          `UPDATE customers SET punches = ?, lifetime_visits = ?,
            last_punch_day = ?, credit_cents = ?, last_birthday_gift_year = ?
           WHERE id = ?`
        )
        .bind(
          punches,
          lifetimeVisits,
          lastPunchDay,
          newCreditCents,
          birthdayGiftCents ? thisYear : customer.last_birthday_gift_year,
          customer.id
        )
    );
    const event = (type, amount, note = "") =>
      db
        .prepare(
          "INSERT INTO loyalty_events (customer_id, sale_id, type, amount_cents, note, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(customer.id, saleId, type, amount, note, nowIso);
    if (earnedPunch) statements.push(event("punch", 0, `visit ${lifetimeVisits}`));
    if (earnedCardReward) statements.push(event("card_reward", PUNCH_REWARD_CENTS));
    if (birthdayGiftCents) statements.push(event("birthday_gift", birthdayGiftCents));
    if (creditUsedCents) statements.push(event("credit_used", -creditUsedCents));
  }

  await db.batch(statements);

  const updatedCustomer = customer ? await findCustomerByEmail(db, email) : null;

  return json({
    ok: true,
    sale: {
      id: saleId,
      createdAt: nowIso,
      subtotal: centsToStr(subtotalCents),
      creditUsed: centsToStr(creditUsedCents),
      taxRate: TAX_RATE,
      tax: centsToStr(taxCents),
      total: centsToStr(totalCents),
      payment,
      items: lines.map((l) => ({
        id: l.itemId,
        name: l.name,
        category: l.category,
        price: centsToStr(l.priceCents),
        qty: l.qty,
      })),
    },
    loyalty: loyaltyNotes,
    customer: customerSummary(updatedCustomer),
  });
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const dbMissing = requireDb(env);
  if (dbMissing) return dbMissing;
  const db = env.DB;

  const url = new URL(request.url);
  const id = url.searchParams.get("id");

  if (id) {
    const sale = await db.prepare("SELECT * FROM sales WHERE id = ?").bind(Number(id)).first();
    if (!sale) return posError(`Sale #${id} not found`, 404);
    const { results } = await db
      .prepare("SELECT * FROM sale_items WHERE sale_id = ?")
      .bind(sale.id)
      .all();
    return json({ ok: true, sale: saleJson(sale, results || []) });
  }

  const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit")) || 20));
  const { results: sales } = await db
    .prepare("SELECT * FROM sales ORDER BY id DESC LIMIT ?")
    .bind(limit)
    .all();

  const out = [];
  for (const sale of sales || []) {
    const { results } = await db
      .prepare("SELECT * FROM sale_items WHERE sale_id = ?")
      .bind(sale.id)
      .all();
    out.push(saleJson(sale, results || []));
  }
  return json({ ok: true, sales: out });
}

function saleJson(sale, items) {
  return {
    id: sale.id,
    createdAt: sale.created_at,
    subtotal: centsToStr(sale.subtotal_cents),
    creditUsed: centsToStr(sale.credit_used_cents),
    tax: centsToStr(sale.tax_cents),
    total: centsToStr(sale.total_cents),
    payment: sale.payment,
    customerEmail: sale.customer_email || "",
    status: sale.status,
    items: items.map((i) => ({
      saleItemId: i.id,
      id: i.item_id,
      name: i.name,
      category: i.category,
      price: centsToStr(i.price_cents),
      originalPrice: centsToStr(i.original_price_cents),
      qty: i.qty,
      returnedQty: i.returned_qty,
    })),
  };
}
