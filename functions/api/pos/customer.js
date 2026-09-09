// functions/api/pos/customer.js
//
// GET  /api/pos/customer?email=... — loyalty status for the checkout screen
//      (punches, store credit, regular status, whether the birthday gift is
//      still unclaimed this year).
// POST /api/pos/customer — update name/birthday, e.g. when a regular tells
//      the shop their birthday. Body: { email, name?, birthday? } with
//      birthday as "MM-DD".
//
//      Also takes punches, lifetimeVisits and credit (dollars) so existing
//      paper punch cards and Notes-app balances can be typed straight in —
//      the pos-customers.html screen. Loyalty balances are money, so every
//      manual change is written to loyalty_events as an "adjust" with the
//      before/after values.

import {
  json,
  posError,
  requireDb,
  normalizeEmail,
  findCustomerByEmail,
  getOrCreateCustomer,
  customerSummary,
} from "../../_lib/pos.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const dbMissing = requireDb(env);
  if (dbMissing) return dbMissing;

  const url = new URL(request.url);
  const email = normalizeEmail(url.searchParams.get("email"));
  if (!email) return posError("Missing email", 400);

  const customer = await findCustomerByEmail(env.DB, email);
  return json({ ok: true, customer: customerSummary(customer) });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const dbMissing = requireDb(env);
  if (dbMissing) return dbMissing;

  let body;
  try {
    body = await request.json();
  } catch {
    return posError("Invalid JSON body", 400);
  }

  const email = normalizeEmail(body?.email);
  if (!email || !email.includes("@")) return posError("A valid email is required", 400);

  const birthday = String(body?.birthday || "").trim();
  if (birthday && !/^\d{2}-\d{2}$/.test(birthday)) {
    return posError('Birthday must be "MM-DD"', 400);
  }

  const customer = await getOrCreateCustomer(env.DB, email);
  const name = body?.name !== undefined ? String(body.name).trim() : customer.name;
  const bday = birthday || customer.birthday;

  // Optional balance fields — absent means "leave alone", so the plain
  // name/birthday save from checkout never touches balances.
  const clampInt = (v, max) => Math.max(0, Math.min(max, Math.floor(Number(v))));
  const punches = body?.punches !== undefined && Number.isFinite(Number(body.punches))
    ? clampInt(body.punches, 9) // 10 punches would already be a completed card — enter 9 + let the next visit finish it, or add $20 credit instead
    : customer.punches;
  const lifetimeVisits = body?.lifetimeVisits !== undefined && Number.isFinite(Number(body.lifetimeVisits))
    ? clampInt(body.lifetimeVisits, 100000)
    : customer.lifetime_visits;
  const creditCents = body?.credit !== undefined && Number.isFinite(Number(body.credit))
    ? clampInt(Number(body.credit) * 100, 100000000)
    : customer.credit_cents;

  const statements = [
    env.DB.prepare(
      "UPDATE customers SET name = ?, birthday = ?, punches = ?, lifetime_visits = ?, credit_cents = ? WHERE id = ?"
    ).bind(name, bday, punches, lifetimeVisits, creditCents, customer.id),
  ];

  if (
    punches !== customer.punches ||
    lifetimeVisits !== customer.lifetime_visits ||
    creditCents !== customer.credit_cents
  ) {
    statements.push(
      env.DB.prepare(
        "INSERT INTO loyalty_events (customer_id, sale_id, type, amount_cents, note, created_at) VALUES (?, NULL, 'adjust', ?, ?, ?)"
      ).bind(
        customer.id,
        creditCents - customer.credit_cents,
        `punches ${customer.punches}→${punches}, visits ${customer.lifetime_visits}→${lifetimeVisits}, credit ${customer.credit_cents}→${creditCents}¢`,
        new Date().toISOString()
      )
    );
  }

  await env.DB.batch(statements);

  const updated = await findCustomerByEmail(env.DB, email);
  return json({ ok: true, customer: customerSummary(updated) });
}
