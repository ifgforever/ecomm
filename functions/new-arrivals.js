// functions/new-arrivals.js
//
// The newest 100 in-stock items as plain server-rendered HTML links.
//
// This page exists for crawlers as much as for people: the category grids
// are drawn client-side from /api/products, so without it there is no HTML
// path from any static page into the ~900 /p/ product pages — the whole
// catalogue was sitemap-only ("orphaned" in audit terms). This page is the
// crawlable way in; the seeded related-items links on each product page
// carry a crawler onward through the rest.
//
// Only the first 24 items get image cards. The rest are text links — a
// hundred thumbnails is the kind of page weight that tanked the homepage's
// Lighthouse score when it rendered the full catalogue.

const SITE = "https://jinkittys.com";
const SHOP_NAME = "Jojin's Kitty Thrift Shop";
const STORE_PHONE = "+13126100321";

export async function onRequestGet(context) {
  const { env } = context;

  // Same resilience posture as sitemap.xml.js: a KV blip renders an honest
  // empty page, never an error.
  let products = [];
  try {
    if (env.PRODUCTS_KV) {
      const raw = await env.PRODUCTS_KV.get("products");
      products = raw ? JSON.parse(raw) : [];
    }
  } catch {
    products = [];
  }

  const items = products
    .filter((p) => p && p.id && isAvailable(p))
    .sort((a, b) => newness(b) - newness(a) || skuNum(b) - skuNum(a))
    .slice(0, 100);

  return new Response(renderPage(items), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      // Same posture as /api/products and the product pages.
      "Cache-Control": "public, max-age=60, stale-while-revalidate=600",
    },
  });
}

function newness(p) {
  const t = new Date(p.createdAt || 0).getTime();
  return isNaN(t) ? 0 : t;
}

// Quick Add assigns SKUs in ascending order, so the numeric part is a
// reliable tiebreaker for older items that predate createdAt.
function skuNum(p) {
  const m = /(\d+)/.exec(String(p.id || ""));
  return m ? Number(m[1]) : 0;
}

// Must stay in sync with slugFor() in functions/p/[slug].js and index.html.
function slugFor(product) {
  const id = String(product.id || "").toLowerCase();
  const name = String(product.name || "")
    .toLowerCase()
    .replace(/['’]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return name ? `${id}-${name}` : id;
}

function isAvailable(p) {
  return !!p.inStock && (p.quantity ?? 1) > 0;
}

function money(n) {
  return `$${Number(n || 0).toFixed(2).replace(/\.00$/, "")}`;
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Same resize route the homepage cards use (index.html renderCard).
function thumb(url) {
  if (!/^https:\/\//i.test(url || "")) return "";
  return `/cdn-cgi/image/width=400,height=400,quality=75,format=auto,fit=cover/${url}`;
}

function renderPage(items) {
  const url = `${SITE}/new-arrivals`;
  const cards = items.slice(0, 24);
  const rest = items.slice(24);

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "ItemList",
    name: "New arrivals at Jojin's Kitty Thrift",
    itemListElement: items.map((p, i) => ({
      "@type": "ListItem",
      position: i + 1,
      url: `${SITE}/p/${slugFor(p)}`,
    })),
  };

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>New Arrivals — Jojin's Kitty Thrift</title>
<meta name="description" content="The newest secondhand finds at Jojin's Kitty Thrift in Chicago — toys, Sanrio, retro games and collectibles, added most days. Everything is one-of-a-kind." />
<link rel="canonical" href="${url}" />
<meta property="og:type" content="website" />
<meta property="og:site_name" content="${esc(SHOP_NAME)}" />
<meta property="og:url" content="${url}" />
<meta property="og:title" content="New Arrivals — ${esc(SHOP_NAME)}" />
<meta property="og:description" content="The newest one-of-a-kind finds in the shop, added most days." />
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><text y='32' font-size='32'>🐾</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700;900&family=Karla:wght@400;500;600;700&display=swap" rel="stylesheet">
<script type="application/ld+json">${JSON.stringify(jsonLd)}</script>
<style>
  :root{--ink:#2f2a24;--paper:#faf7f2;--card:#fff;--line:rgba(180,155,120,.32);--teal:#397367;--rust:#a8471f;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);font-family:Karla,system-ui,sans-serif;line-height:1.6}
  .wrap{max-width:900px;margin:0 auto;padding:20px 18px 64px}
  .crumb{font-size:13px;margin-bottom:18px}
  .crumb a{color:var(--teal)}
  h1{font-family:'Playfair Display',Georgia,serif;font-size:clamp(26px,5vw,38px);margin:.1em 0 .2em}
  .sub{margin:0 0 22px;color:#6a6055}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:14px}
  .mini{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;text-decoration:none;color:inherit;display:block}
  .mini img{width:100%;aspect-ratio:1/1;object-fit:cover;display:block;background:#f2ece3}
  .mini .t{padding:9px 10px;font-size:13px;font-weight:600;line-height:1.3}
  .mini .p{padding:0 10px 10px;font-size:13px;color:var(--teal);font-weight:700}
  h2.more{font-family:'Playfair Display',Georgia,serif;font-size:22px;margin:38px 0 10px}
  .list{list-style:none;margin:0;padding:0;columns:2;column-gap:24px}
  @media(max-width:560px){.list{columns:1}}
  .list li{break-inside:avoid;padding:6px 0;border-bottom:1px dashed var(--line);font-size:14px}
  .list a{color:inherit;text-decoration:none;font-weight:600}
  .list a:hover{color:var(--teal)}
  .list .lp{color:var(--teal);font-weight:700;white-space:nowrap;margin-left:6px}
  .empty{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px}
</style>
</head>
<body>
<div class="wrap">
  <div class="crumb"><a href="/">← Back to the shop</a></div>
  <h1>New Arrivals</h1>
  <p class="sub">Fresh finds straight from intake, newest first. Everything here is one-of-a-kind — call <a href="tel:${STORE_PHONE}" style="color:var(--teal)">+1 (312) 610-0321</a> to claim something before it's gone.</p>

  ${cards.length
    ? `<div class="grid">
        ${cards
          .map((p) => {
            const img = thumb(p.image);
            return `<a class="mini" href="/p/${esc(slugFor(p))}">
              ${img ? `<img src="${esc(img)}" alt="${esc(p.name || "")}" loading="lazy" width="400" height="400">` : ""}
              <div class="t">${esc(p.name || "Unnamed item")}</div>
              <div class="p">${esc(money(p.price))}</div>
            </a>`;
          })
          .join("")}
      </div>`
    : `<div class="empty">New finds land most days — check back soon, or come say hi at 4100 N. Pulaski Rd., Chicago.</div>`}

  ${rest.length
    ? `<h2 class="more">Also just in</h2>
      <ul class="list">
        ${rest
          .map(
            (p) => `<li><a href="/p/${esc(slugFor(p))}">${esc(p.name || "Unnamed item")}</a><span class="lp">${esc(money(p.price))}</span></li>`
          )
          .join("")}
      </ul>`
    : ""}
</div>
</body>
</html>`;
}
