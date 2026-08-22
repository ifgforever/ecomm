# Google Merchant Center feeds

Two endpoints put the whole shop into Google's local surfaces without anyone
typing a product into Merchant Center:

| URL | What it is | Registered in Merchant Center as |
|---|---|---|
| `/feeds/google-products.xml` | The catalogue. RSS 2.0 + `g:` namespace. | Primary product data source, **scheduled fetch** |
| `/feeds/google-local-inventory.txt` | Per-store stock. Tab-separated. | Supplemental source, type **Local product inventory**, **scheduled fetch** |
| `/feeds/excluded.txt` | Everything in stock that is *not* being sent, and why. | Nothing — it is for us, not Google |

Both read the same `PRODUCTS_KV` `"products"` array that `/api/products`,
`/p/[slug]` and `/sitemap.xml` already read. Add an item in Quick Add and it
is in both feeds on the next pull, with nothing else touched. That is the
entire point: 600 items, no data entry.

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

2. **Set a store code on that location** and write the same string into
   `STORE_CODE` in `functions/_lib/catalog.js`. **It is case sensitive.** A
   mismatch is the single most common failure here, and the worst-behaved:
   the feed fetches successfully, reports no error, and shows nothing.

3. **Link Business Profile to Merchant Center.** Settings → Access and
   services → Apps and services → Add service → Google Business Profile.
   **Then wait 24 hours** before uploading inventory — locations take that
   long to sync, and inventory submitted earlier lands against a store
   Merchant Center cannot see yet.

4. **Turn on the add-on.** Settings → Add-ons → Free local listings → add
   country (United States) → Continue setup. When asked, say you know
   per-store inventory.

5. **Register the primary feed.** Data sources → Add product source →
   scheduled fetch → `https://jinkittys.com/feeds/google-products.xml`.
   Daily is the default and the maximum without asking Google for more.

6. **Register the local inventory feed.** Data sources → Product sources →
   Supplemental sources → **Add local inventory** →
   `https://jinkittys.com/feeds/google-local-inventory.txt`. The type matters:
   a generic supplemental source accepts the file and then powers nothing.

7. **Wait 24–48h** for first processing.

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

Both endpoints send `X-Feed-Item-Count`, so a `curl -I` is enough to compare
what the shop is publishing against what Merchant Center says it received:

    curl -sI https://jinkittys.com/feeds/google-products.xml | grep -i item-count
    curl -sI https://jinkittys.com/feeds/google-local-inventory.txt | grep -i item-count

If those two disagree with each other, something is wrong here. If they agree
with each other but not with Merchant Center, the problem is on Google's side
of the fetch — usually the store code.

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
