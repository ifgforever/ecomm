// functions/p/[slug].js
//
// One route that serves a page for every product, present and future.
// Nothing is generated when an item is added: Quick Add writes the product
// into PRODUCTS_KV with a permanent SKU, and this reads it back out at
// request time. A new item is live at its own URL the moment it saves.
//
// Slug format: sku-1042-hello-kitty-plush
// Only the leading SKU is matched, so renaming an item in admin doesn't
// break links that are already out in the world — the old slug 301s to the
// current one.
//
// Sold items deliberately keep their page (marked OutOfStock, with other
// items shown underneath) rather than 404ing. Inventory here turns over
// constantly; deleting the URL every time something sells would generate a
// steady stream of dead links and throw away the visitor who searched for it.

const SITE = "https://jinkittys.com";
const SHOP_NAME = "Jojin's Kitty Thrift Shop";
const STORE_PHONE = "+13126100321";

export async function onRequestGet(context) {
  const { params, env } = context;
  const slug = String(params.slug || "");

  if (!env.PRODUCTS_KV) return notFound("Inventory is unavailable right now.");

  const skuMatch = /^(sku-\d+)/i.exec(slug);
  if (!skuMatch) return notFound();

  const sku = skuMatch[1].toUpperCase();

  let products;
  try {
    const raw = await env.PRODUCTS_KV.get("products");
    products = raw ? JSON.parse(raw) : [];
  } catch {
    return notFound("Inventory is unavailable right now.");
  }

  const product = products.find((p) => String(p.id || "").toUpperCase() === sku);
  if (!product) return notFound();

  // Keep one canonical spelling of the URL.
  const canonicalSlug = slugFor(product);
  if (slug !== canonicalSlug) {
    return Response.redirect(`${SITE}/p/${canonicalSlug}`, 301);
  }

  // Related picks are seeded on this product's SKU: stable for crawlers and
  // the cache, but different on every page, so the catalogue cross-links as
  // one connected mesh instead of every page in a category pointing at the
  // same first four items. Categories are small and free-form, so when one
  // runs short the remaining slots fill from the whole catalogue — that
  // spillover is what ties the tiny categories into the rest of the shop.
  const candidates = products.filter((p) => p.id !== product.id && isAvailable(p));
  const sameCategory = candidates.filter(
    (p) => (p.category || "") === (product.category || "")
  );
  const elsewhere = candidates.filter(
    (p) => (p.category || "") !== (product.category || "")
  );
  const related = seededPicks(sameCategory, product.id, 4);
  if (related.length < 4) {
    related.push(...seededPicks(elsewhere, product.id, 4 - related.length));
  }

  return new Response(renderPage(product, related, canonicalSlug), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      // Same posture as /api/products: brief shared cache, revalidate behind
      // it, so a price or sold-flag edit in admin shows up quickly.
      "Cache-Control": "public, max-age=60, stale-while-revalidate=600",
    },
  });
}

// Must stay in sync with slugFor() in index.html.
export function slugFor(product) {
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

// Deterministic "random" selection: score every candidate by a hash of this
// page's SKU plus the candidate's, sort, take the first n. Per-request
// randomness would show crawlers different links on every visit; this stays
// put until inventory itself changes.
function seededPicks(candidates, seed, n) {
  return candidates
    .map((p) => ({ p, score: fnv1a(`${seed}::${p.id}`) }))
    .sort((a, b) => a.score - b.score)
    .slice(0, n)
    .map(({ p }) => p);
}

function fnv1a(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
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

function renderPage(product, related, slug) {
  const url = `${SITE}/p/${slug}`;
  const available = isAvailable(product);
  const price = Number(product.price || 0);
  const name = product.name || "Untitled item";
  const category = product.category || "Misc";

  // The AI intake writes description and pickNote; between them there is
  // usually real copy to work with. Fall back to something honest if not.
  const blurb =
    product.description ||
    product.pickNote ||
    `A one-of-a-kind secondhand find at ${SHOP_NAME} in Chicago.`;

  const shareText = `${name} — ${money(price)} at ${SHOP_NAME}`;
  // og:image has to be absolute — Facebook and Google fetch it from outside.
  // Older products store a relative path into the legacy /images/ folder that
  // no longer exists, so those are dropped rather than emitted as a dead tag.
  const ogImage = /^https:\/\//i.test(product.image || "") ? product.image : "";

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "Product",
    name,
    description: blurb,
    sku: product.id,
    category,
    ...(ogImage ? { image: [ogImage] } : {}),
    offers: {
      "@type": "Offer",
      url,
      priceCurrency: "USD",
      price: price.toFixed(2),
      availability: available
        ? "https://schema.org/InStock"
        : "https://schema.org/SoldOut",
      itemCondition: "https://schema.org/UsedCondition",
      seller: {
        "@type": "Store",
        name: SHOP_NAME,
        // Store is a LocalBusiness subtype, and LocalBusiness validation
        // requires an address — without it every product page fails
        // structured-data checks.
        address: {
          "@type": "PostalAddress",
          streetAddress: "4100 N Pulaski Rd",
          addressLocality: "Chicago",
          addressRegion: "IL",
          postalCode: "60641",
          addressCountry: "US",
        },
      },
    },
  };

  const breadcrumbs = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Shop", item: `${SITE}/` },
      { "@type": "ListItem", position: 2, name, item: url },
    ],
  };

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>${esc(name)} — ${esc(money(price))} | ${esc(SHOP_NAME)}</title>
<meta name="description" content="${esc(blurb.slice(0, 300))}" />
<link rel="canonical" href="${esc(url)}" />
<meta property="og:type" content="product" />
<meta property="og:site_name" content="${esc(SHOP_NAME)}" />
<meta property="og:url" content="${esc(url)}" />
<meta property="og:title" content="${esc(shareText)}" />
<meta property="og:description" content="${esc(blurb.slice(0, 300))}" />
${ogImage ? `<meta property="og:image" content="${esc(ogImage)}" />
<meta property="og:image:alt" content="${esc(name)}" />` : ""}
<meta property="product:price:amount" content="${price.toFixed(2)}" />
<meta property="product:price:currency" content="USD" />
<meta property="product:availability" content="${available ? "in stock" : "out of stock"}" />
<meta name="twitter:card" content="summary_large_image" />
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><text y='32' font-size='32'>🐾</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700;900&family=Karla:wght@400;500;600;700&display=swap" rel="stylesheet">
<script type="application/ld+json">${JSON.stringify(jsonLd)}</script>
<script type="application/ld+json">${JSON.stringify(breadcrumbs)}</script>
<style>
  :root{--ink:#2f2a24;--paper:#faf7f2;--card:#fff;--line:rgba(180,155,120,.32);--teal:#397367;--rust:#a8471f;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);font-family:Karla,system-ui,sans-serif;line-height:1.6}
  .wrap{max-width:900px;margin:0 auto;padding:20px 18px 64px}
  .crumb{font-size:13px;margin-bottom:18px}
  .crumb a{color:var(--teal)}
  .item{display:grid;grid-template-columns:1fr;gap:24px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px}
  @media(min-width:720px){.item{grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:32px;padding:26px}}
  .photo{background:#f2ece3;border-radius:10px;overflow:hidden;aspect-ratio:1/1;display:flex;align-items:center;justify-content:center}
  .photo img{width:100%;height:100%;object-fit:cover;display:block}
  .noimg{color:#9a8f80;font-size:14px}
  h1{font-family:'Playfair Display',Georgia,serif;font-size:clamp(24px,4.4vw,34px);margin:.1em 0 .3em;line-height:1.18}
  .tag{display:inline-block;font-size:11px;letter-spacing:.09em;text-transform:uppercase;font-weight:700;color:var(--teal);background:rgba(57,115,103,.09);padding:4px 10px;border-radius:999px}
  .price{font-family:'Playfair Display',Georgia,serif;font-size:30px;font-weight:900;margin:10px 0 4px}
  .stock{font-size:14px;font-weight:600}
  .in{color:var(--teal)} .out{color:var(--rust)}
  .desc{margin:14px 0}
  .pick{border-left:3px solid var(--line);padding-left:12px;font-style:italic;color:#6a6055;margin:14px 0}
  .sku{font-size:12px;color:#8a8175;margin-top:14px}
  .actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:20px}
  .btn{display:inline-flex;align-items:center;gap:7px;padding:12px 18px;border-radius:8px;text-decoration:none;font-weight:700;font-size:14px;border:1px solid transparent;cursor:pointer;font-family:inherit}
  .btn-primary{background:var(--teal);color:#fff}
  .btn-ghost{background:transparent;border-color:var(--line);color:var(--ink)}
  .sold-note{background:rgba(168,71,31,.07);border:1px solid rgba(168,71,31,.25);border-radius:8px;padding:12px 14px;margin-top:16px;font-size:14px}
  h2.more{font-family:'Playfair Display',Georgia,serif;font-size:22px;margin:38px 0 14px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:14px}
  .mini{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;text-decoration:none;color:inherit;display:block}
  .mini img{width:100%;aspect-ratio:1/1;object-fit:cover;display:block}
  .mini .t{padding:9px 10px;font-size:13px;font-weight:600;line-height:1.3}
  .mini .p{padding:0 10px 10px;font-size:13px;color:var(--teal);font-weight:700}
</style>
</head>
<body>
<div class="wrap">
  <div class="crumb"><a href="/">← Back to the shop</a></div>

  <article class="item">
    <div class="photo">
      ${ogImage
        ? `<img src="${esc(ogImage)}" alt="${esc(name)}" width="800" height="800">`
        : `<div class="noimg">No photo yet</div>`}
    </div>
    <div>
      <span class="tag">${esc(category)}</span>
      <h1>${esc(name)}</h1>
      <div class="price">${esc(money(price))}</div>
      <div class="stock ${available ? "in" : "out"}">${available ? `✓ In stock — ${(Number(product.quantity) || 1) > 1 ? `${Number(product.quantity)} available` : "one available"}` : "Sold"}</div>

      ${product.description ? `<p class="desc">${esc(product.description)}</p>` : ""}
      ${product.pickNote ? `<p class="pick">${esc(product.pickNote)}</p>` : ""}

      ${available
        ? `<div class="actions">
             <a class="btn btn-primary" href="tel:${STORE_PHONE}">📞 Call to claim it</a>
             <button type="button" class="btn btn-ghost" id="shareBtn">📤 Share</button>
             <button type="button" class="btn btn-ghost" id="copyBtn">Copy link</button>
           </div>`
        : `<div class="sold-note">This one found a home. Everything here is one-of-a-kind, so it won't be restocked — but new finds land most days.</div>
           <div class="actions">
             <a class="btn btn-primary" href="/">Browse what's in stock</a>
             <button type="button" class="btn btn-ghost" id="shareBtn">📤 Share</button>
           </div>`}

      <div class="sku">SKU ${esc(product.id || "—")} · Pickup at 4100 N Pulaski Rd, Chicago</div>
    </div>
  </article>

  ${related.length
    ? `<h2 class="more">${related.every((p) => (p.category || "") === (product.category || "")) ? `More in ${esc(category)}` : "More from the shop"}</h2>
       <div class="grid">
         ${related
           .map(
             (p) => `<a class="mini" href="/p/${esc(slugFor(p))}">
               ${p.image ? `<img src="${esc(p.image)}" alt="${esc(p.name || "")}" loading="lazy">` : ""}
               <div class="t">${esc(p.name || "Unnamed item")}</div>
               <div class="p">${esc(money(p.price))}</div>
             </a>`
           )
           .join("")}
       </div>`
    : ""}
</div>
<script>
  // <-escaped so a product name can never break out of this script tag.
  var shareData = ${JSON.stringify({ title: name, text: shareText, url }).replace(/</g, "\\u003c")};
  var shareBtn = document.getElementById('shareBtn');
  if (shareBtn) {
    shareBtn.addEventListener('click', async function () {
      if (navigator.share) {
        try {
          await navigator.share(shareData);
        } catch (e) {
          // Closing the share sheet rejects with AbortError — that's a
          // cancel, not a failure.
        }
      } else {
        // No native share (mostly desktop Firefox): fall back to copying.
        try {
          await navigator.clipboard.writeText(shareData.url);
          shareBtn.textContent = 'Link copied!';
          setTimeout(function () { shareBtn.textContent = '📤 Share'; }, 2000);
        } catch (e) {
          shareBtn.textContent = 'Copy failed';
        }
      }
    });
  }
  var copyBtn = document.getElementById('copyBtn');
  if (copyBtn) {
    copyBtn.addEventListener('click', async function () {
      try {
        await navigator.clipboard.writeText(window.location.href);
        copyBtn.textContent = 'Link copied!';
        setTimeout(function () { copyBtn.textContent = 'Copy link'; }, 2000);
      } catch (e) {
        copyBtn.textContent = 'Copy failed';
      }
    });
  }
</script>
</body>
</html>`;
}

function notFound(message) {
  const body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta name="robots" content="noindex" />
<title>Item not found — ${SHOP_NAME}</title>
<style>body{font-family:system-ui,sans-serif;background:#faf7f2;color:#2f2a24;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center;padding:24px}a{color:#397367}</style>
</head><body><div>
<h1>We couldn't find that item</h1>
<p>${esc(message || "It may have sold and been removed from the shop.")}</p>
<p><a href="/">← Browse what's in stock</a></p>
</div></body></html>`;
  return new Response(body, {
    status: 404,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
