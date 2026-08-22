// functions/feeds/excluded.txt.js
//
// Everything in stock that is NOT being sent to Google, and why. Served at
// https://jinkittys.com/feeds/excluded.txt
//
// This exists because the two feeds are quiet about what they leave out. An
// item can be missing from Google for three completely different reasons --
// a restricted brand, a dead photo, or incomplete data -- and from the
// Merchant Center side all three look identical: the item simply isn't
// there. Without this page the only way to find out is to diff 600 products
// by hand.
//
// It also keeps the brand exclusion honest. Some of the restricted terms are
// ordinary words, and a filter nobody can audit is one that quietly eats
// inventory for months. If something shows up here that shouldn't, the term
// that caught it is named on the row.
//
// Nothing here is private -- the whole catalogue is already public at
// /api/products -- so this needs no login, same as the feeds.

import {
  loadProducts,
  isAvailable,
  feedable,
  feedImage,
  restrictedReason,
  EXCLUDE_RESTRICTED_BRANDS,
} from "../_lib/catalog.js";

export async function onRequestGet(context) {
  const { env } = context;

  const products = await loadProducts(env);
  const inStock = products.filter(isAvailable);

  const rows = [];
  for (const p of inStock) {
    const reason = reasonFor(p);
    if (reason) rows.push([p.id || "(no id)", reason, p.name || "(no name)"]);
  }

  // Group by reason so the shape of the problem is visible at a glance --
  // forty items sharing one cause is a different afternoon's work than forty
  // separate ones.
  rows.sort((a, b) => a[1].localeCompare(b[1]) || String(a[0]).localeCompare(String(b[0])));

  const counts = new Map();
  for (const [, reason] of rows) {
    const key = reason.split(":")[0];
    counts.set(key, (counts.get(key) || 0) + 1);
  }

  const summary = [
    `in stock:        ${inStock.length}`,
    `sent to Google:  ${inStock.length - rows.length}`,
    `held back:       ${rows.length}`,
    "",
    ...[...counts.entries()].map(([k, n]) => `  ${k}: ${n}`),
    "",
    EXCLUDE_RESTRICTED_BRANDS
      ? "restricted-brand filter: ON  (EXCLUDE_RESTRICTED_BRANDS in functions/_lib/catalog.js)"
      : "restricted-brand filter: OFF",
    "",
    "id\treason\tname",
  ].join("\n");

  const body =
    summary + "\n" + rows.map((r) => r.map(cell).join("\t")).join("\n") + "\n";

  return new Response(body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

// Order matters: report the brand hold first even when the item also has a
// dead photo, because that is the decision worth revisiting rather than a
// data problem to go and fix.
function reasonFor(p) {
  const restricted = restrictedReason(p);
  if (restricted) return `restricted-brand: matched "${restricted}"`;
  if (feedable(p)) return "";
  if (!feedImage(p)) {
    return String(p.image || "").trim()
      ? "no-usable-image: relative path into the retired /images/ folder"
      : "no-usable-image: no photo on the product";
  }
  if (!String(p.name || "").trim()) return "incomplete: no name";
  if (!(Number(p.price) > 0)) return "incomplete: no price";
  if (!String(p.id || "").trim()) return "incomplete: no id";
  return "incomplete";
}

function cell(value) {
  return String(value ?? "").replace(/[\t\r\n]+/g, " ").trim();
}
