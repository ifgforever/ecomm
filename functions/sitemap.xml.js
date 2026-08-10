// functions/sitemap.xml.js
//
// Replaces the old hand-maintained sitemap.xml. Products turn over constantly,
// so the list is built from PRODUCTS_KV at request time — a new item appears
// here on its own, and nothing has to be edited when inventory changes.
//
// If KV is unreachable this still returns the static pages rather than an
// error, so a blip never leaves the site with no sitemap at all.

const SITE = "https://jinkittys.com";

const STATIC_PAGES = [
  { path: "/", priority: "1.0" },
  // Category landing pages. These are the pages built to rank for the
  // searches people actually make ("labubu store chicago", "sanrio store
  // chicago", "vintage video game store chicago") -- the homepage alone
  // gave Google nothing to match those against. Priority sits above the
  // individual products below because they are the entry points.
  { path: "/labubu", priority: "0.8" },
  { path: "/hello-kitty", priority: "0.8" },
  { path: "/retro-video-games", priority: "0.8" },
  { path: "/toys", priority: "0.8" },
  { path: "/funko-pop", priority: "0.8" },
  { path: "/gallery-submit", priority: "0.6" },
  { path: "/community-sell", priority: "0.6" },
  { path: "/terms", priority: "0.3" },
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

  const urls = STATIC_PAGES.map(
    (p) => `  <url>
    <loc>${SITE}${p.path}</loc>
    <priority>${p.priority}</priority>
  </url>`
  );

  for (const p of products) {
    if (!p || !p.id) continue;
    const lastmod = isoDate(p.createdAt);
    urls.push(`  <url>
    <loc>${SITE}/p/${xml(slugFor(p))}</loc>${lastmod ? `
    <lastmod>${lastmod}</lastmod>` : ""}
    <priority>0.5</priority>
  </url>`);
  }

  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join("\n")}
</urlset>
`;

  return new Response(body, {
    headers: {
      "Content-Type": "application/xml; charset=utf-8",
      "Cache-Control": "public, max-age=600",
    },
  });
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

function isoDate(value) {
  if (!value) return "";
  const d = new Date(value);
  return isNaN(d.getTime()) ? "" : d.toISOString().slice(0, 10);
}

function xml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
