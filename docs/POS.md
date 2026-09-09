# Jojin's Register — inventory & point of sale

One entry feeds everything: intake creates the inventory record, the product
page on jinkittys.com, the Google feed row, and the shelf label. Selling it
removes it from all of them; returning it puts it back.

## The screens (all behind the admin login)

| URL | What it's for |
| --- | --- |
| `/quick-add` | Intake: photo → price → category chip → **Add It** → **Print label**. AI drafts the listing text. ~10 seconds per item. |
| `/pos` | Checkout: scan QR labels or add unlabeled items, price override, Cash/Card/Zelle, loyalty, tax. Second tab is Returns. |
| `/pos-label` | Make/reprint a label for any item (newest first when opened with no item). |

`/quick-add` itself stays login-free (as before); `/pos`, `/pos-label`, and
every `/api/pos/*` endpoint require the admin cookie from `/admin-login`.

## One-time setup

The D1 database **`jinkittys-pos`** already exists in the Cloudflare account
(id `9a03a289-bba7-4388-aeeb-0a2d5d81f17e`) with the schema created. Two
steps remain, in this order:

1. **Bind it**: Cloudflare dashboard → Workers & Pages → the jinkittys.com
   Pages project → Settings → Bindings → Add → **D1 database** →
   variable name `DB` → database `jinkittys-pos`. Redeploy.
2. **Migrate**: log in at `/admin-login`, then open `/api/pos/setup` in the
   browser. It copies the ~800 KV products into D1, once. It refuses to run
   twice, so re-opening it later is harmless.

Until both steps happen the site keeps running exactly as before on
PRODUCTS_KV — every reader and writer falls back automatically. After the
migration, D1 is the single source of truth and KV is left as a frozen
backup of the pre-migration catalogue.

### Printer (Brother QL-810W + 62 mm continuous rolls)

Install **Brother iPrint&Label** (free) on the intake/checkout phone, add
the QL-810W over the shop Wi-Fi, and pick the 62 mm continuous roll once.
The **Print label** button renders the label as a 696-px-wide PNG (the
printer's exact dot width at 300 dpi) and opens the share sheet — share to
iPrint&Label and print, "fit to tape". The QR encodes the product-page URL
(`jinkittys.com/p/sku-…`), so a customer scanning a shelf tag sees the
listing, while the register scanner reads the SKU out of the same code.

## How selling removes items from the site

Checkout decrements the item's `quantity`; at zero it drops out of
`/api/products` availability, the Google feeds, and new-arrivals on their
next read — the same rule the site has always used (`inStock` +
`quantity > 0`). The product page stays up marked sold, as before.

Unlabeled items (most of the existing ~800 until they're relabeled) are rung
up with a price + category; the sale creates a real inventory record
(already marked sold, tagged `posManual`) so no sale is ever invisible.

## Loyalty (from the punch card)

- A visit with a $20+ purchase (pre-tax) = 1 punch — at most one punch per
  Chicago calendar day, because the card counts *visits*.
- 10 punches → $20 store credit, card resets.
- 10 lifetime punched visits → regular customer.
- Regulars: $50 birthday credit, once per calendar year, granted by the
  staff tapping the 🎂 button at checkout.
- Store credit is applied at checkout (tax is charged on the after-credit
  amount) and refunded proportionally when a credit-paid sale is returned.

Customers are keyed by email; entering it at checkout is optional.

## Tax

Chicago general merchandise, 10.25%, added at checkout and stored per sale
(`tax_rate` on the row), so a future rate change is one constant in
`functions/_lib/pos.js` and history stays correct. Card payments are still
run on the separate terminal — the app records the total to charge.

## Data model (D1)

- `items` — the catalogue (what KV held, one row per product; unknown
  legacy fields ride along in `extra` JSON).
- `sales` / `sale_items` — every transaction, line by line, with the
  charged and original price (so haggling is visible) and returned counts.
- `customers` / `loyalty_events` — punch card state and an audit trail of
  every punch, reward, birthday gift, and credit movement.
