// functions/feeds/local-inventory.txt.js
//
// The local product inventory feed — the other half of free local listings.
// feeds/products.txt says what each item is; this says what is actually on
// the shelf at the shop, and it is the file that makes an item show up as
// "available nearby" on the Shopping tab and in Maps.
//
// Upload this in Merchant Center as data source type "Local product
// inventory". It is NOT a supplemental data source, and picking the wrong
// type is the usual reason a correct-looking file does nothing.
//
// store_code has to match the code on the store in the linked Google
// Business Profile exactly. It is set here from an environment variable so
// it can be corrected on the Pages project without a deploy — but the
// default below is what it will use until that variable exists.
//
// No pickup_method / pickup_sla columns. Those are only for buy-online-
// pickup-in-store, which is a different program with its own fulfilment
// promises; a shop where people walk in and buy off the shelf does not
// need them, and pickup_sla is required as soon as one is declared.

const DEFAULT_STORE_CODE = "jinkittys-pulaski";

const COLUMNS = ["store_code", "id", "availability", "price", "quantity"];

export async function onRequestGet(context) {
  const { env } = context;
  const storeCode = env.MERCHANT_STORE_CODE || DEFAULT_STORE_CODE;

  let products = [];
  try {
    if (env.PRODUCTS_KV) {
      const raw = await env.PRODUCTS_KV.get("products");
      products = raw ? JSON.parse(raw) : [];
    }
  } catch {
    products = [];
  }

  const rows = [];
  for (const p of products) {
    if (!p || !p.id || !p.name) continue;

    // Held back for the same reason as the primary feed: an inventory row
    // for an id that never made it into the product feed is an error in
    // Merchant Center, not a no-op. The two files have to agree.
    if (!/^https:\/\//i.test(p.image || "")) continue;

    const available = !!p.inStock && (p.quantity ?? 1) > 0;

    rows.push([
      storeCode,
      p.id,
      available ? "in_stock" : "out_of_stock",
      `${Number(p.price || 0).toFixed(2)} USD`,
      // Nearly everything here is a single thrifted piece, so the honest
      // default is 1 rather than a blank. Sold items report 0 to match the
      // out_of_stock above; disagreeing with yourself across these two
      // columns is its own disapproval.
      available ? String(Math.max(1, Number(p.quantity ?? 1))) : "0",
    ]);
  }

  const body =
    [COLUMNS.join("\t"), ...rows.map((r) => r.map(tsv).join("\t"))].join("\n") + "\n";

  return new Response(body, {
    headers: {
      "Content-Type": "text/tab-separated-values; charset=utf-8",
      "Cache-Control": "public, max-age=600",
      "X-Feed-Items": String(rows.length),
      "X-Feed-Store-Code": storeCode,
    },
  });
}

function tsv(value) {
  return String(value ?? "")
    .replace(/[\t\r\n]+/g, " ")
    .trim();
}
