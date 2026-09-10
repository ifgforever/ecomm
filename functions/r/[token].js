// functions/r/[token].js
//
// The customer-facing receipt. Deliberately PUBLIC (no admin cookie): the
// customer opens it from a link the register shared with them. Access
// control is the token itself — 32 random hex characters minted per sale
// and given to no one else. It shows this one sale and, when the sale has
// a customer attached, their punch-card status; it never lists other
// sales, other customers, or anything staff-only.

import { centsToStr, PUNCHES_FOR_CREDIT, REGULAR_AFTER_VISITS } from "../_lib/pos.js";

const SHOP_NAME = "Jojin's Kitty Thrift Shop";
const SHOP_ADDR = "4100 N Pulaski Rd, Chicago";
const SHOP_PHONE = "(312) 610-0321";

export async function onRequestGet(context) {
  const { params, env } = context;
  if (!env.DB && env.jdb) env.DB = env.jdb;
  if (!env.DB) return notFound();

  const token = String(params.token || "");
  if (!/^[0-9a-f]{32}$/.test(token)) return notFound();

  const sale = await env.DB.prepare("SELECT * FROM sales WHERE receipt_token = ?")
    .bind(token)
    .first();
  if (!sale) return notFound();

  const { results: items } = await env.DB.prepare(
    "SELECT * FROM sale_items WHERE sale_id = ?"
  ).bind(sale.id).all();

  let customer = null;
  if (sale.customer_id) {
    customer = await env.DB.prepare("SELECT * FROM customers WHERE id = ?")
      .bind(sale.customer_id)
      .first();
  }

  const when = new Date(sale.created_at).toLocaleString("en-US", {
    timeZone: "America/Chicago",
    month: "long", day: "numeric", year: "numeric",
    hour: "numeric", minute: "2-digit",
  });

  const rows = (items || []).map((i) => `
      <tr>
        <td>${i.qty > 1 ? i.qty + "× " : ""}${esc(i.name)}${i.returned_qty > 0 ? ' <span class="ret">(returned)</span>' : ""}</td>
        <td class="num">$${centsToStr(i.price_cents * i.qty)}</td>
      </tr>`).join("");

  const creditRow = sale.credit_used_cents > 0
    ? `<tr><td>Store credit</td><td class="num">−$${centsToStr(sale.credit_used_cents)}</td></tr>`
    : "";

  let loyalty = "";
  if (customer) {
    const filled = "●".repeat(customer.punches);
    const open = "○".repeat(Math.max(0, PUNCHES_FOR_CREDIT - customer.punches));
    loyalty = `
    <div class="loyal">
      <h2>Your punch card</h2>
      <div class="punches">${filled}${open}</div>
      <p>${customer.punches}/${PUNCHES_FOR_CREDIT} punches ·
         ${customer.lifetime_visits >= REGULAR_AFTER_VISITS ? "⭐ regular customer" : customer.lifetime_visits + " visit" + (customer.lifetime_visits === 1 ? "" : "s")} ·
         $${centsToStr(customer.credit_cents)} store credit</p>
    </div>`;
  }

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta name="robots" content="noindex, nofollow" />
<title>Receipt — ${esc(SHOP_NAME)}</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><text y='32' font-size='32'>🧾</text></svg>">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700;900&family=Karla:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  body { margin:0; background:#f7f2eb; color:#1c1610; font-family:'Karla',system-ui,sans-serif; }
  .wrap { max-width:420px; margin:0 auto; padding:28px 20px 50px; }
  .card { background:#fff; border:1.5px solid #d4c4a8; border-radius:4px; padding:24px; box-shadow:5px 5px 0 #c8863a; }
  h1 { font-family:'Playfair Display',Georgia,serif; font-size:24px; font-weight:900; margin:0; text-align:center; }
  h1 em { font-style:italic; color:#a06820; }
  .meta { text-align:center; font-size:12.5px; color:#6b5d4f; margin:6px 0 18px; line-height:1.6; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  td { padding:6px 0; border-bottom:1px solid #f0e9de; }
  td.num { text-align:right; white-space:nowrap; }
  .ret { color:#b8522a; font-style:italic; font-size:12px; }
  .totals td { border-bottom:none; padding:3px 0; font-size:14px; }
  .totals tr.grand td { font-size:18px; font-weight:700; border-top:2px solid #1c1610; padding-top:8px; }
  .pay { text-align:center; font-size:13px; color:#6b5d4f; margin-top:12px; }
  .loyal { margin-top:18px; background:#f0e9de; border-radius:4px; padding:12px 14px; text-align:center; }
  .loyal h2 { font-family:'Playfair Display',Georgia,serif; font-size:15px; margin:0 0 6px; }
  .loyal .punches { font-size:18px; letter-spacing:3px; }
  .loyal p { font-size:12.5px; color:#6b5d4f; margin:6px 0 0; }
  .foot { text-align:center; font-size:12px; color:#6b5d4f; margin-top:20px; }
  .foot a { color:#3d7a6e; font-weight:700; text-decoration:none; }
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Jojin's <em>Kitty Thrift</em></h1>
      <div class="meta">${esc(SHOP_ADDR)} · ${esc(SHOP_PHONE)}<br>Sale #${sale.id} · ${esc(when)}</div>
      <table>${rows}</table>
      <table class="totals">
        <tr><td>Subtotal</td><td class="num">$${centsToStr(sale.subtotal_cents)}</td></tr>
        ${creditRow}
        <tr><td>Tax (${(sale.tax_rate * 100).toFixed(2)}%)</td><td class="num">$${centsToStr(sale.tax_cents)}</td></tr>
        <tr class="grand"><td>Total</td><td class="num">$${centsToStr(sale.total_cents)}</td></tr>
      </table>
      <div class="pay">Paid by ${esc(sale.payment)}${sale.status !== "completed" ? " · " + esc(sale.status.replace("_", " ")) : ""}</div>
      ${loyalty}
    </div>
    <p class="foot">Everything is one-of-a-kind and sold as-is.<br>Thanks for thrifting with us! 🐾 <a href="https://jinkittys.com">jinkittys.com</a></p>
  </div>
</body>
</html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "private, no-store",
    },
  });
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function notFound() {
  return new Response("Receipt not found.", { status: 404 });
}
