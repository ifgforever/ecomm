// functions/feeds/google-local-inventory.txt.js
//
// Local product inventory feed for Google Merchant Center, served at
// https://jinkittys.com/feeds/google-local-inventory.txt
//
// Registered separately from the primary feed, under
// Data sources > Product sources > Supplemental sources > Add local
// inventory, with the type "Local product inventory". It has to be that
// type: a generic supplemental source will accept the file and then not
// power any local surface.
//
// The primary feed (google-products.xml) says what each item IS. This one
// says which shop it is sitting in and whether it is still on the shelf.
// Local listings need both -- the catalogue on its own has no store attached
// to it, and every item reports "Missing inventory data".
//
// Tab-separated with a header row. Column names are the spec's attribute
// names verbatim, because Merchant Center matches on the header text.

import {
  loadProducts,
  feedProducts,
  priceString,
  STORE_CODE,
} from "../_lib/catalog.js";

// Deliberately four columns, and deliberately NOT quantity or pickup_method:
//
//   quantity -- Google reads local stock levels as a band, where 1-2 units
//     means "limited availability" rather than "in stock", and when both
//     quantity and availability are sent the more conservative of the two
//     wins. Every item in this shop is a single unit, so sending quantity
//     would quietly file the entire catalogue under limited availability.
//     Google's own guidance is that quantity is no longer required and that
//     availability alone is the thing to submit.
//
//   pickup_method -- optional since September 2024 and explicitly not
//     recommended. Its accepted values describe kinds of buy-online-collect-
//     in-store that this shop does not offer; there is no value that means
//     "just come in", and sending a wrong one earns an inconsistent-value
//     error. Absent, it says nothing, which is accurate.
const COLUMNS = ["store_code", "id", "price", "availability"];

export async function onRequestGet(context) {
  const { env } = context;

  const products = feedProducts(await loadProducts(env));

  const rows = products.map((p) =>
    [
      // The join key back to the location on the linked Google Business
      // Profile, and the single most common thing to get wrong: it is case
      // sensitive, and a mismatch parks every row against a store that does
      // not exist while the feed still reports a successful fetch.
      STORE_CODE,
      // Must be byte-identical to <g:id> in the primary feed -- the other
      // half of the join, and just as silent when it doesn't line up.
      p.id,
      priceString(p),
      "in_stock",
    ]
      .map(tsv)
      .join("\t")
  );

  const body = [COLUMNS.join("\t"), ...rows].join("\n") + "\n";

  return new Response(body, {
    headers: {
      "Content-Type": "text/tab-separated-values; charset=utf-8",
      // Google pulls this on its own schedule, so a long cache only delays
      // a sold item leaving the feed. Nothing gained, freshness lost.
      "Cache-Control": "public, max-age=300",
      // Not part of the format; it is just the first number worth having
      // when Merchant Center reports a count that doesn't match, and a HEAD
      // request is enough to read it.
      "X-Feed-Item-Count": String(products.length),
    },
  });
}

// A stray tab or newline inside a value shifts every column after it on that
// row, so the row fails against whichever attribute it lands on -- an error
// that reads as nonsense from the Merchant Center side. clean() already
// handles the free-text fields; this covers the rest.
function tsv(value) {
  return String(value ?? "").replace(/[\t\r\n]+/g, " ").trim();
}
