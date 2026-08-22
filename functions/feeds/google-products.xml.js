// functions/feeds/google-products.xml.js
//
// Primary product feed for Google Merchant Center, served at
// https://jinkittys.com/feeds/google-products.xml
//
// Registered in Merchant Center as a SCHEDULED FETCH, not an upload: Google
// pulls this URL on a schedule and re-reads the whole catalogue each time.
// That is what makes 600 items a one-time setup instead of 600 forms --
// adding an item in Quick Add puts it in KV, and it is in the feed on the
// next pull with nothing else touched.
//
// Format is RSS 2.0 with Google's g: namespace, which the fetch path accepts
// directly.
//
// THE DESTINATION SCOPING IS LOAD-BEARING. This shop has no online checkout
// -- terms.html says so plainly, and every product page says "call to claim
// it". Offered to the ordinary online destinations, all 600 items would be
// disapproved for having no way to buy them. excluded_destination keeps them
// out of those surfaces; the local destinations are the ones that describe
// what this actually is: inventory sitting on a shelf at 4100 N Pulaski.

import {
  loadProducts,
  feedProducts,
  productUrl,
  feedImage,
  feedTitle,
  feedDescription,
  priceString,
  googleCategory,
  SITE,
  SHOP_NAME,
  SCOPE_DESTINATIONS,
  EXCLUDED_DESTINATIONS,
  INCLUDED_DESTINATIONS,
} from "../_lib/catalog.js";

const DESTINATIONS = SCOPE_DESTINATIONS
  ? EXCLUDED_DESTINATIONS.map((d) => `    <g:excluded_destination>${d}</g:excluded_destination>`)
      .concat(INCLUDED_DESTINATIONS.map((d) => `    <g:included_destination>${d}</g:included_destination>`))
      .join("\n") + "\n"
  : "";

export async function onRequestGet(context) {
  const { env } = context;

  const products = feedProducts(await loadProducts(env));

  const items = products.map((p) => {
    const category = googleCategory(p);
    return `  <item>
    <g:id>${xml(p.id)}</g:id>
    <title>${xml(feedTitle(p))}</title>
    <description>${xml(feedDescription(p))}</description>
    <link>${xml(productUrl(p))}</link>
    <g:image_link>${xml(feedImage(p))}</g:image_link>
    <g:availability>in_stock</g:availability>
    <g:price>${xml(priceString(p))}</g:price>
    <g:condition>used</g:condition>
${category ? `    <g:google_product_category>${xml(category)}</g:google_product_category>\n` : ""}${p.category ? `    <g:product_type>${xml(p.category)}</g:product_type>\n` : ""}    <g:identifier_exists>no</g:identifier_exists>
${DESTINATIONS}  </item>`;
  });

  const body = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:g="http://base.google.com/ns/1.0">
<channel>
  <title>${xml(SHOP_NAME)}</title>
  <link>${SITE}</link>
  <description>Secondhand toys, collectibles and retro games, in stock at 4100 N Pulaski Rd, Chicago.</description>
${items.join("\n")}
</channel>
</rss>
`;

  return new Response(body, {
    headers: {
      "Content-Type": "application/xml; charset=utf-8",
      // Google fetches this on its own schedule, so there is nothing to gain
      // from a long cache and something to lose: a price or sold-flag edit in
      // admin should be visible to the next pull, not to the one after it.
      "Cache-Control": "public, max-age=300",
      // The row count is not part of the feed format, but it is the first
      // thing worth knowing when Merchant Center reports a number that
      // doesn't match -- readable with a HEAD request, no parsing.
      "X-Feed-Item-Count": String(products.length),
    },
  });
}

// Image note: Google raises the image_link minimum to 500x500 px on
// 30 September 2026. Uploads through admin.html are re-encoded to 1000px by
// api/upload-image.js, so current stock clears that comfortably -- but any
// item whose photo predates that resize step is worth spot-checking.
//
// identifier_exists=no is what tells Google to stop looking for a GTIN.
// Thrift inventory has no barcodes worth trusting -- a loose figure out of a
// bin has no packaging and no MPN, and guessing one would be worse than
// declaring there isn't one. Without this the whole feed fails validation on
// missing identifiers.

// Belt and braces alongside clean(): values that never pass through
// feedTitle/feedDescription (ids, categories, URLs) reach the document too,
// and any one of them carrying a control character would invalidate it.
function xml(s) {
  return String(s ?? "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}
