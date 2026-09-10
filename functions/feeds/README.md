# Google Merchant Center feeds

Two endpoints put the whole shop into Google's local surfaces without anyone
typing a product into Merchant Center:

| URL | What it is | Registered in Merchant Center as |
|---|---|---|
| `/feeds/google-products.xml` | The catalogue. RSS 2.0 + `g:` namespace. | Primary product data source, **scheduled fetch** |
| `/feeds/google-local-inventory.txt` | Per-store stock. Tab-separated. | Supplemental source, type **Local product inventory**, **scheduled fetch** |
| `/feeds/excluded.txt` | Everything in stock that is *not* being sent, and why. | Nothing — it is for us, not Google |

Both read the same product list that `/api/products`, `/p/[slug]` and
`/sitemap.xml` already read, through `loadProducts()` in `_lib/catalog.js` →
`listProducts()` in `_lib/store.js`. That resolves to the D1 `items` table
when a `DB` (or `jdb`) binding exists, and falls back to the original
`PRODUCTS_KV` `"products"` array when it does not. Either way the feeds do
not care: add an item in Quick Add or sell one at the register and it is in
both feeds on the next pull, with nothing else touched. That is the entire
point: ~1,230 items and climbing, no data entry.

Neither endpoint needs auth. `functions/_middleware.js` only gates non-GET
requests to a fixed list of API paths, so these are public GETs like the
sitemap — which is what Google needs, since its fetcher does not log in.

## Why local listings and not ordinary Shopping

`terms.html` says it plainly: *"This website does not process purchases or
payments — all purchases of shop inventory happen in person, at the store."*

Ordinary free listings and Shopping ads assume an online checkout. Offered
there, all 600 items would be disapproved for having no way to buy them.
Free local listings are the surface built for exactly this: inventory sitting
on a shelf that someone drives to. They are free, and they do not need a
Google Ads account. (Local *inventory ads* are the paid version of the same
pipeline and do need one — same feeds, so that door stays open.)

`catalog.js` asserts this scoping per item via `excluded_destination` /
`included_destination`. See `SCOPE_DESTINATIONS` there if Merchant Center
ever rejects those values.

## Setup, in order

Steps 1–3 are the part that cannot be automated. Do them in this order —
several of them silently do nothing if run early.

1. **Google Business Profile, verified.** The location at 4100 N Pulaski Rd
   must exist and be *verified*. Stores typed straight into Merchant Center
   are not eligible for local listings — the location has to arrive from a
   linked Business Profile.

2. **Match the store code Google assigned.** Do NOT invent one. Google
   auto-assigns a store code to a verified location; read it from the
   **Store code** column at business.google.com/locations and put that exact
   string in `STORE_CODE` in `functions/_lib/catalog.js`. For 4100 N Pulaski
   that is `14376355877054648957`.

   Picking a code instead is what broke the first attempt: the local
   inventory source fetched cleanly and recognised every attribute name, then
   rejected all 1,113 rows as *[Business Profile] Invalid store code*. Nor is
   renaming the store a way out — the field is only editable for profiles
   inside a location group, and this one is standalone.

   **It is case sensitive**, and a mismatch is the worst-behaved failure
   here: the fetch succeeds, and the listings simply never appear.

3. **Link Business Profile to Merchant Center.** Settings → Access and
   services → Apps and services → Add service → Google Business Profile.
   **Then wait 24 hours** before uploading inventory — locations take that
   long to sync, and inventory submitted earlier lands against a store
   Merchant Center cannot see yet.

4. **Turn on the add-on AND finish the country wizard.** Settings → Add-ons →
   "Your add-ons" → Free local listings → Go to Free local listings → Add
   country → United States.

   **Adding the country is not the same as finishing setup, and this is the
   step that cost weeks.** The country row then reads "Continue setup" and
   the program does not serve until every sub-step is done. Nothing warns
   you: no banner, no error, no product disapproval. Open the row (it later
   reads "Review setup status") and work all of it:

   - **Add stores** → the verified Business Profile location.
   - **Your in-store product availability** → you provide inventory per
     store, not ship-to-store.
   - **Your product page experience** → see the section below. This is the
     one that gets skipped.
   - **Your pick-up experience** → genuinely optional, and skipping it is
     correct here; the shop runs no pickup service.
   - **Add inventory** → sits at "In progress", which is just the local
     inventory feed doing its nightly job.

   Ignore the Google Ads linking prompt. That is for local inventory ads.

5. **Register the primary feed.** Data sources → Add product source →
   scheduled fetch → `https://jinkittys.com/feeds/google-products.xml`.
   Daily is the default and the maximum without asking Google for more.

6. **Register the local inventory feed.** Data sources → Product sources →
   Supplemental sources → **Add local inventory** →
   `https://jinkittys.com/feeds/google-local-inventory.txt`. The type matters:
   a generic supplemental source accepts the file and then powers nothing.

7. **Opt the primary source into the local marketing method.** Data sources →
   Primary sources → PRODUCTS SOURCE 1 → Data source setup → "How the data
   will be used" → Marketing methods → tick **Free local listings**.

   Products inherit marketing methods from the source that created them. The
   per-item `included_destination` in the feed cannot rescue this: it can
   re-include a product within destinations the account and source already
   have, but it cannot create one they are not enrolled in. Until this is
   ticked the tag is a no-op.

8. **Wait 24–48h** for first processing.

## Your product page experience — the step that blocks everything

Three options, and the choice has real consequences:

| Option | Requires | Audit |
|---|---|---|
| Product pages with in-store availability | Page shows in-store availability + store location | **No** |
| Store-specific product pages | `link_template` with a `{store_code}` placeholder | No |
| Product pages without in-store availability | Nothing — Google hosts it | **Yes** |

**Use the first one.** Google's implementation guide recommends it for
single-store merchants showing in-store availability.

The second would disapprove the entire catalogue on day one: it needs a
`link_template` attribute carrying `{store_code}`, and `google-products.xml.js`
emits a plain `<link>`.

The third is the only one that mandates in-store inventory verification — a
roughly two-hour store visit sampling 100 feed-listed products and
photographing their price tags, with "Ineligible" as the failure verdict. For
one-of-a-kind stock at quantity 1 that turns over daily, that is 100 chances
to hit something that sold since Google's last pull. Avoid it.

**`/p/[slug]` is written to satisfy option one and must stay that way.** It
renders "In stock in store", an "Available at this store" block with the shop
name, full address, hours and phone, and a schema.org `Store` seller carrying
address, telephone, openingHours and geo. Before that wording existed the page
said only "In stock — one available", which reads as *online* stock, with the
address in 12px grey text. If someone ever simplifies that block away, this
setup step silently stops qualifying.

Submit a **multi-quantity** item as the example URL. Everything here is
one-of-one, and if the sample sells during the week-long review Google crawls
a "Sold" page. `/api/products` has a few dozen items with `quantity > 1`; pick
the highest.

## Pop Mart is held back on purpose

Everything in this shop is genuine secondhand, Labubu included. The filter is
not about that. It is about how Google enforces if it ever decides otherwise.

Counterfeit is an **egregious** violation: suspension on detection, no warning
email, none of the 7-or-28-day window ordinary violations get, and the stated
consequence is permanent. It lands on the **account**, not the item. So the
exposure is not one figure being rejected -- it is all 600 listings going dark
at once, with no chance to fix it first. Pop Mart is enforcing hard and has a
direct reporting pipeline into Google; the September 2025 restraining order
went against 7-Eleven *franchisees*, so reselling genuine stock was not a
defence there.

Against that, the cost of the filter is a handful of items not appearing on
Google. They still sell in the shop, still have a product page, still show up
in the sitemap and on `/labubu`.

`EXCLUDE_RESTRICTED_BRANDS` in `_lib/catalog.js` turns it off in one line.
Worth revisiting once the account has a clean history behind it — the
argument for turning it back on gets stronger the longer nothing has gone
wrong, and stronger again because used, own-photographed, visibly pre-owned
pieces are a weak counterfeit signal compared with the sealed boxes that
enforcement actually targets.

Check `/feeds/excluded.txt` before assuming the filter is behaving. Some of
the terms it matches are ordinary words.

## What to check when something is wrong

**Start by asking whether the program is even live**, because for a long time
it was not, and every data-side check came back green the whole while. The
tell is inverted and easy to miss: Google *hides* Products → "Sales channels"
and the "Add products to stores" button from accounts enrolled in free local
listings. If you can see that tab and the manual store picker works, the
program is **not** running, and no amount of feed debugging will change it.
Go back to steps 4 and 7. Never use that manual picker — it caps at 50 items,
it cannot enrol the account, and manually associated stores are not eligible
for free local listings anyway.

Both endpoints send `X-Feed-Item-Count`, so one request each is enough to
compare what the shop is publishing against what Merchant Center says it
received. **Use GET, not HEAD** — both functions export only `onRequestGet`,
so `curl -I` returns 404 and looks alarming for no reason:

    curl -s -D - -o /dev/null https://jinkittys.com/feeds/google-products.xml | grep -i item-count
    curl -s -D - -o /dev/null https://jinkittys.com/feeds/google-local-inventory.txt | grep -i item-count

If those two disagree with each other, something is wrong here. If they agree
with each other but not with Merchant Center, the problem is on Google's side
of the fetch — usually the store code.

**"Matched products: 1,232" on the local inventory source proves less than it
looks.** It means Google joined the inventory rows to the primary feed on the
`id` column. It does not validate the store code, does not test eligibility,
and does not mean the account is enrolled. A green "no issues found" there is
compatible with nothing serving at all.

Likewise a clean **Needs attention** tab. With no live destination there is
nothing to evaluate, so silence means "not assessed", not "approved". Expect
real issues to appear once the program goes live — that is progress, not a
regression.

And **"Not showing on Google: 1.2K"** under the *Free listings* filter is
permanent and correct. The feed excludes that destination on purpose. Judge
by the *Free local listings* filter instead.

For anything missing from the feeds, `/feeds/excluded.txt` answers it
directly — every in-stock item that is not being sent, the reason, and a
count per reason:

    curl -s https://jinkittys.com/feeds/excluded.txt

Three reasons show up there. `restricted-brand` is the Pop Mart hold above,
and names the term that matched. `no-usable-image` is an item whose photo is
missing or still points at the retired `/images/` folder — `image_link` is
required, so feeding those would collect disapprovals instead of listings;
re-uploading the photo in admin fixes them permanently. `incomplete` is a
missing name, price or id.

## Condition

Every item is sent as `condition: used`, hardcoded. The shop resells used
pieces only and stocks nothing new, so there is no case to branch on.

This is worth keeping right. Google cross-checks `condition` against the
landing page, and a mismatch there is the most likely disapproval this shop
would ever see. `/p/[slug]` already emits `schema.org/UsedCondition` in its
product markup, so the feed and the page agree by construction. If a sealed,
never-opened item is ever stocked, `condition` becomes a real per-item
decision rather than a constant — Google only counts unopened original
packaging as `new`.

## Two known gaps, both needing data the products don't carry

Neither is fixable in the feed code. Both are the most likely source of
disapprovals once this is live, so they are worth knowing about before
Merchant Center tells you.

**No `brand`.** Google wants `brand` on anything that has one. A product in
KV has no brand field, so the feed omits it. For genuinely unbranded thrift
(a loose 80s figure out of a bin) that is correct and allowed. For a boxed
Nintendo game or a Funko it is a gap. Fixing it means adding a brand field
to the product record and backfilling.

**`identifier_exists` is `no` for everything.** The exemption actually turns
on whether the item was ever *assigned* an identifier -- not on whether it is
secondhand. A loose vintage piece with no packaging genuinely has none, and
`no` is right. A current mass-produced product still in print does have a
GTIN on its box, and Google can match the offer to its catalogue entry and
know one exists; those can come back as "Incorrect product identifier". With
no gtin field on the product there is nothing better to send, and inventing
one would be worse. If disapprovals cluster here, the fix is a `gtin` field
populated for the items that still have their box.

## Apparel is left uncategorised on purpose

If clothing is ever a real category here, note that declaring Apparel &
Accessories in the US makes `color`, `gender` and `age_group` required, and
`size` required on clothing and shoes. None of those exist on a product in
KV, so naming the category would opt every tee into a validation tier the
data cannot satisfy. `_lib/catalog.js` deliberately has no apparel mapping
and lets Google classify those itself.

## The part that stays imperfect

Google fetches once a day. Everything in this shop is one of one. So for up
to 24 hours after something sells, Google can still be showing it.

That is not a bug in these feeds and no feed schedule fixes it — daily is the
ceiling for scheduled fetch without a special request. It is tolerable here
because the landing page tells the truth the moment it sells: `/p/[slug]`
reads the same KV and renders "Sold" with other items underneath, so the
worst case is a wasted click that lands somewhere useful, not a customer
driving over for something that is gone.

Closing the gap properly means pushing sell-through events to the **Merchant
API** as they happen. Two things to know before going that way: the older
Content API for Shopping was **sunset on 18 August 2026**, so the Merchant API
is the only API path now; and products can only be updated through a data
source of type API — a source that is fetched from a file cannot also be
patched. So it is one or the other, not both on the same source.

Worth doing when the daily lag actually costs something. Not before.
