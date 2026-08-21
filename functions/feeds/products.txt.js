// functions/feeds/products.txt.js
//
// The primary product feed for Google Merchant Center, built from
// PRODUCTS_KV at request time in the same spirit as sitemap.xml.js: nothing
// is generated when an item is added, and Merchant Center pulls a current
// copy on its own schedule.
//
// This is half of what free local listings need. This file describes what
// each item IS (title, photo, price, condition); feeds/local-inventory.txt
// describes what is on the shelf at the store. Merchant Center wants both,
// as two separate data sources.
//
// Tab-separated, because Merchant Center accepts .txt/.tsv/.xml but not
// .csv — and a comma-delimited file is the classic way to lose a listing
// whose title contains a comma.
//
// No shipping attributes here on purpose. Shipping is required for the
// online free-listings program; local listings are bought and collected in
// the shop, so Google does not ask for it.

const SITE = "https://jinkittys.com";

// Every item is secondhand and one of a kind: no barcode, no manufacturer
// part number, and "brand" on a thrifted Sanrio plush is not the kind of
// brand Google means. Sending identifier_exists=no is the documented way to
// say so — without it Merchant Center flags the whole feed for missing GTINs.
const CONDITION = "used";

const COLUMNS = [
  "id",
  "title",
  "description",
  "link",
  "image_link",
  "availability",
  "price",
  "condition",
  "identifier_exists",
  "product_type",
];

export async function onRequestGet(context) {
  const { env } = context;

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
  let skippedNoImage = 0;
  let skippedIncomplete = 0;

  for (const p of products) {
    if (!p || !p.id || !p.name) {
      skippedIncomplete++;
      continue;
    }

    // image_link is required, and it must be an absolute URL Google can
    // fetch. Older records point into the legacy /images/ folder that no
    // longer exists; sending those guarantees a disapproval, so they are
    // held back until the item gets a real photo. The count comes back in a
    // response header so this stays visible instead of silently shrinking
    // the feed.
    const image = /^https:\/\//i.test(p.image || "") ? p.image : "";
    if (!image) {
      skippedNoImage++;
      continue;
    }

    rows.push([
      p.id,
      clamp(p.name, 150),
      clamp(p.description || p.pickNote || fallbackBlurb(p), 5000),
      `${SITE}/p/${slugFor(p)}`,
      image,
      isAvailable(p) ? "in_stock" : "out_of_stock",
      `${Number(p.price || 0).toFixed(2)} USD`,
      CONDITION,
      "no",
      p.category || "Misc",
    ]);
  }

  const body =
    [COLUMNS.join("\t"), ...rows.map((r) => r.map(tsv).join("\t"))].join("\n") + "\n";

  return new Response(body, {
    headers: {
      "Content-Type": "text/tab-separated-values; charset=utf-8",
      // Merchant Center fetches this on a schedule measured in hours, so a
      // short shared cache costs nothing and protects KV if the feed URL
      // ever gets hit repeatedly.
      "Cache-Control": "public, max-age=600",
      "X-Feed-Items": String(rows.length),
      "X-Feed-Skipped-No-Image": String(skippedNoImage),
      "X-Feed-Skipped-Incomplete": String(skippedIncomplete),
    },
  });
}

// Sold items keep their entry, marked out_of_stock, rather than vanishing.
// It matches what /p/[slug] already does for the same reason: the page still
// exists, and an item that disappears and reappears in a feed reads to
// Google as a brand new product each time.
function isAvailable(p) {
  return !!p.inStock && (p.quantity ?? 1) > 0;
}

function fallbackBlurb(p) {
  return `${p.name} — a one-of-a-kind secondhand find at Jojin's Kitty Thrift Shop in Chicago.`;
}

// Must stay in sync with slugFor() in functions/p/[slug].js, sitemap.xml.js
// and index.html.
function slugFor(product) {
  const id = String(product.id || "").toLowerCase();
  const name = String(product.name || "")
    .toLowerCase()
    .replace(/['’]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return name ? `${id}-${name}` : id;
}

function clamp(s, max) {
  const t = String(s ?? "").trim();
  return t.length > max ? t.slice(0, max - 1).trimEnd() + "…" : t;
}

// A stray tab or newline inside a field shifts every following column on
// that row, which is how one bad description quietly corrupts a feed.
function tsv(value) {
  return String(value ?? "")
    .replace(/[\t\r\n]+/g, " ")
    .trim();
}
