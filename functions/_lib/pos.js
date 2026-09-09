// functions/_lib/pos.js
//
// Business rules for the point of sale, in one place so the sale and return
// endpoints can't drift apart.

// Chicago general merchandise rate (IL 6.25 + Cook 1.75 + Chicago 1.25 +
// RTA 1.00). Stored on every sale row at the rate in effect that day, so a
// future rate change never rewrites history.
export const TAX_RATE = 0.1025;

// Loyalty, straight off the punch card:
//   "Spend $20 or more ... after purchasing 10 times, receive $20 store
//    credit ... after 10 visits you become a regular customer and get an
//    extra $50 gift on your birthday."
export const PUNCH_MIN_CENTS = 2000;      // $20+ pre-tax earns the visit its punch
export const PUNCHES_FOR_CREDIT = 10;     // 10 punches -> $20 credit, card resets
export const PUNCH_REWARD_CENTS = 2000;
export const REGULAR_AFTER_VISITS = 10;   // lifetime qualifying visits
export const BIRTHDAY_GIFT_CENTS = 5000;  // once per calendar year, regulars only

export const PAYMENT_TYPES = new Set(["Cash", "Card", "Zelle"]);

// The card counts VISITS, not transactions — two sales rung up back-to-back
// are one trip to the store. Chicago local time decides what "same day" means.
export function chicagoDay(date = new Date()) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Chicago",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

export function toCents(dollars) {
  return Math.round(Number(dollars) * 100);
}

export function centsToStr(cents) {
  return (Number(cents || 0) / 100).toFixed(2);
}

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export function posError(message, status) {
  return json({ error: message }, status);
}

export function requireDb(env) {
  if (!env.DB) {
    return posError(
      "The POS needs the D1 database. Bind a D1 database as DB in Pages > Settings > Bindings, then open /api/pos/setup.",
      503
    );
  }
  return null;
}

export function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

export async function findCustomerByEmail(db, email) {
  return db.prepare("SELECT * FROM customers WHERE email = ?").bind(email).first();
}

export async function getOrCreateCustomer(db, email) {
  const existing = await findCustomerByEmail(db, email);
  if (existing) return existing;
  await db
    .prepare("INSERT INTO customers (email, created_at) VALUES (?, ?)")
    .bind(email, new Date().toISOString())
    .run();
  return findCustomerByEmail(db, email);
}

// Everything a checkout screen wants to show about a customer, derived
// fields included.
export function customerSummary(c) {
  if (!c) return null;
  return {
    id: c.id,
    email: c.email,
    name: c.name || "",
    birthday: c.birthday || "",
    punches: c.punches,
    punchesForCredit: PUNCHES_FOR_CREDIT,
    lifetimeVisits: c.lifetime_visits,
    isRegular: c.lifetime_visits >= REGULAR_AFTER_VISITS,
    creditCents: c.credit_cents,
    credit: centsToStr(c.credit_cents),
    lastBirthdayGiftYear: c.last_birthday_gift_year || 0,
  };
}
