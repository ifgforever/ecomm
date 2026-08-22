// functions/_lib/catalog.js
//
// Shared catalogue helpers for the Google Merchant Center feeds. Everything
// here reads the same PRODUCTS_KV "products" array that /api/products,
// /p/[slug] and /sitemap.xml already read, so a feed can never disagree with
// the product page Google's crawler lands on -- an availability mismatch
// between the two is one of the most common causes of item disapproval.
//
// Nothing is generated or stored when an item is added. Quick Add writes the
// product into KV and the next feed fetch picks it up. That is the whole
// point: 600 items, and no one types anything into Merchant Center.

export const SITE = "https://jinkittys.com";
export const SHOP_NAME = "Jojin's Kitty Thrift Shop";

// Must match the store code on the location in the linked Google Business
// Profile. Merchant Center joins the local inventory feed to a physical shop
// on this string alone -- if it doesn't match, every local row is orphaned
// and silently dropped, with no error that names the cause.
export const STORE_CODE = "jojins-kitty-pulaski";

export const CURRENCY = "USD";

// This shop takes no money online -- terms.html says so outright and every
// product page says "call to claim it". Offered to the ordinary online
// destinations, all 600 items would be disapproved for having no way to buy
// them; the local destinations are the ones that describe what this actually
// is, which is inventory sitting on a shelf at 4100 N Pulaski.
//
// The same scoping can be set per data source in the Merchant Center UI. It
// is done here as well because the feed is the thing under version control:
// a destination toggled in a dashboard eighteen months ago is invisible when
// something later goes wrong.
//
// IF MERCHANT CENTER REJECTS THESE as unknown values, that means the
// destination names have been renamed on Google's side. Set SCOPE_DESTINATIONS
// to false, redeploy, and set the destinations on the data source in the UI
// instead -- the feed is still correct, it just stops asserting this itself.
export const SCOPE_DESTINATIONS = true;
export const EXCLUDED_DESTINATIONS = ["Shopping_ads", "Free_listings"];
export const INCLUDED_DESTINATIONS = ["Free_local_listings", "Local_inventory_ads"];

// Google's taxonomy is optional -- left off, Google classifies the item
// itself, which for thrift inventory is usually as good as a guess we'd make
// from a free-form category string. These are the cases where the shop's own
// category is unambiguous enough to beat that inference. Anything not listed
// is deliberately sent with no google_product_category rather than a wrong
// one, which is worse than none.
//
// Matched as lowercase substrings against the product's category AND name,
// first hit wins, so order matters: put the specific before the general.
const CATEGORY_MAP = [
  [["video game", "videogame", "retro game", "nintendo", "playstation", "sega", "xbox", "gameboy", "game boy"], "Software > Video Game Software"],
  [["console"], "Electronics > Video Game Consoles"],
  [["labubu", "funko", "pop mart", "popmart", "action figure", "figurine", "figure"], "Toys & Games > Toys > Dolls, Playsets & Toy Figures"],
  [["doll", "monster high", "barbie"], "Toys & Games > Toys > Dolls, Playsets & Toy Figures"],
  [["plush", "stuffed"], "Toys & Games > Toys > Stuffed Animals"],
  [["keychain", "bag charm", "charm"], "Luggage & Bags > Bag & Luggage Accessories"],
  [["book", "manga", "comic"], "Media > Books"],
  [["dvd", "vhs", "blu-ray", "bluray"], "Media > DVDs & Videos"],
  [["cd", "vinyl", "record"], "Media > Music & Sound Recordings"],
  [["shirt", "hoodie", "jacket", "apparel", "clothing"], "Apparel & Accessories > Clothing"],
  [["mug", "cup", "plate", "bowl"], "Home & Garden > Kitchen & Dining > Tableware"],
  [["toy", "sanrio", "hello kitty", "anime"], "Toys & Games > Toys"],
  [["collectible", "vintage"], "Arts & Entertainment > Hobbies & Creative Arts > Collectibles"],
];

// ---------------------------------------------------------------------------
// Restricted brands
// ---------------------------------------------------------------------------
//
// Pop Mart items are held out of the Google feeds. Not because anything in
// this shop is fake -- it isn't -- but because of how Google enforces if it
// ever decides otherwise.
//
// Counterfeit is classed as an EGREGIOUS violation: suspension on detection,
// no warning email, none of the 7-or-28-day window ordinary violations get,
// and the consequence is stated as permanent. It lands on the ACCOUNT, not
// the item. So the exposure is not "a Labubu gets rejected" -- it is all 600
// listings going dark at once, over one item, with no chance to fix it first.
//
// The other side of it is that Pop Mart is enforcing hard right now and has a
// direct reporting pipeline into Google. They won a restraining order against
// 7-Eleven FRANCHISEES in September 2025 -- being a reseller of genuine stock
// is not a defence there, which is the part that matters here.
//
// Weighed against that, the cost of this switch is a handful of items not
// appearing on Google. They still sell in the shop, still have their own
// product page, and still show up in the sitemap and on /labubu.
//
// Set EXCLUDE_RESTRICTED_BRANDS to false to feed them again -- worth
// revisiting once the account has a clean history behind it.
export const EXCLUDE_RESTRICTED_BRANDS = true;

// Matched on whole words, against category + name + description, so an item
// called "blind box figure" whose description mentions the series is caught
// too. Deliberately wider than the Labubu line itself: the enforcement risk
// attaches to the Pop Mart brand, not to one character.
//
// A false positive here costs one item not being listed on Google, which is
// recoverable and visible at /feeds/excluded.txt. A false negative costs the
// account. Erring wide is the cheap direction -- but check that page rather
// than assuming, since some of these are ordinary words.
const RESTRICTED_TERMS = [
  "labubu", "pop mart", "popmart", "popmarts",
  "the monsters", "zimomo", "mokoko", "tycoco",
  "skullpanda", "skull panda", "dimoo", "crybaby", "cry baby",
  "hirono", "pucky", "instinctoy", "hacipupu",
];

const RESTRICTED_RE = new RegExp(
  `\\b(${RESTRICTED_TERMS.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})\\b`,
  "i"
);

// Returns the term that matched, so /feeds/excluded.txt can show WHY an item
// is being held back -- an exclusion you cannot see the reason for is one
// nobody will ever trust enough to narrow.
export function restrictedReason(p) {
  if (!EXCLUDE_RESTRICTED_BRANDS) return "";
  const hay = `${p.category || ""} ${p.name || ""} ${p.description || ""}`;
  const m = RESTRICTED_RE.exec(hay);
  return m ? m[1].toLowerCase() : "";
}

export async function loadProducts(env) {
  if (!env.PRODUCTS_KV) return [];
  try {
    const raw = await env.PRODUCTS_KV.get("products");
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

// Must stay in sync with slugFor() in functions/p/[slug].js, functions/
// sitemap.xml.js and index.html. A feed link that 404s or redirects is a
// disapproval, so this has to produce the canonical URL, not merely a
// working one.
export function slugFor(product) {
  const id = String(product.id || "").toLowerCase();
  const name = String(product.name || "")
    .toLowerCase()
    .replace(/['’]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return name ? `${id}-${name}` : id;
}

export function productUrl(product) {
  return `${SITE}/p/${slugFor(product)}`;
}

export function isAvailable(p) {
  return !!p.inStock && (Number(p.quantity ?? 1) || 0) > 0;
}

// Older products store a relative path into an /images/ folder that no longer
// exists. /p/[slug] already drops those rather than emitting a dead og:image;
// the feed has to be stricter still, because image_link is required and a
// broken one disapproves the item instead of merely rendering badly.
export function feedImage(p) {
  const src = String(p.image || "");
  return /^https:\/\//i.test(src) ? src : "";
}

// An item only belongs in the feed if it satisfies every hard requirement.
// Sending a row we know Google will reject buys nothing: it shows up as a
// disapproval against the account, and a steady rate of those is what turns
// into a suspension review.
export function feedable(p) {
  return !!(
    p &&
    String(p.id || "").trim() &&
    String(p.name || "").trim() &&
    Number(p.price) > 0 &&
    feedImage(p)
  );
}

// Only in-stock items are fed. Everything here is one-of-a-kind and never
// restocks, so a sold item has no future in the feed -- carrying it as
// out_of_stock forever would grow the file without end and dilute the
// account with items that can never be bought. When something sells it
// simply stops appearing on the next fetch.
export function feedProducts(products) {
  return products.filter(
    (p) => feedable(p) && isAvailable(p) && !restrictedReason(p)
  );
}

export function priceString(p) {
  return `${Number(p.price).toFixed(2)} ${CURRENCY}`;
}

// Google truncates past these; doing it here keeps what shows up in a result
// under our control rather than cut mid-word by them.
export function feedTitle(p) {
  return clamp(clean(p.name), 150);
}

export function feedDescription(p) {
  const text =
    clean(p.description) ||
    clean(p.pickNote) ||
    `A one-of-a-kind secondhand find at ${SHOP_NAME}, 4100 N Pulaski Rd, Chicago. Everything here is sold as-is and in person -- when it's gone, it's gone.`;
  return clamp(text, 5000);
}

export function googleCategory(p) {
  const hay = `${p.category || ""} ${p.name || ""}`.toLowerCase();
  for (const [needles, category] of CATEGORY_MAP) {
    if (needles.some((n) => hay.includes(n))) return category;
  }
  return "";
}

function clamp(s, max) {
  return s.length <= max ? s : s.slice(0, max - 1).trimEnd() + "…";
}

// Product names and notes are free text typed on a phone or pasted in from a
// listing somewhere else, so they arrive with tabs, hard line breaks and the
// occasional stray control character. Two separate reasons to scrub them:
//
//   - A raw control character is not representable in XML 1.0 at all. One of
//     them anywhere in 600 items makes the whole document unparseable, and
//     Google rejects the ENTIRE feed rather than the one bad row -- the shop
//     would drop off the local surfaces completely over a single title.
//   - A tab or newline inside a value shifts every column after it in the
//     TSV feed, so the row fails against whichever attribute it lands on.
//
// Collapsing to single spaces fixes both, and titles read better for it.
export function clean(value) {
  return String(value ?? "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}
