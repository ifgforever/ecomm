// functions/api/pos/customer.js
//
// GET  /api/pos/customer?email=... — loyalty status for the checkout screen
//      (punches, store credit, regular status, whether the birthday gift is
//      still unclaimed this year).
// POST /api/pos/customer — update name/birthday, e.g. when a regular tells
//      the shop their birthday. Body: { email, name?, birthday? } with
//      birthday as "MM-DD".

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

  await env.DB.prepare("UPDATE customers SET name = ?, birthday = ? WHERE id = ?")
    .bind(name, bday, customer.id)
    .run();

  const updated = await findCustomerByEmail(env.DB, email);
  return json({ ok: true, customer: customerSummary(updated) });
}
