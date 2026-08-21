# Free local listings (Google Merchant Center)

Goal: the shop's items show up on the Google Shopping tab and in Maps with
their price and "available nearby", and people come into the store to buy
them. **Nothing ships.** Google calls this *free local listings*, and it is a
different program from the one the Search Console email was advertising —
that one is for products bought online and posted out, and it does require
shipping settings.

The site feeds it from `PRODUCTS_KV`, the same place the storefront and
sitemap already read from. Nothing extra to maintain: when Quick Add saves an
item or something is marked sold, the feeds change with it.

## What the site now serves

| URL | Merchant Center data source type | What it says |
| --- | --- | --- |
| `https://jinkittys.com/feeds/products.txt` | Primary product data source | What each item is — title, photo, price, condition |
| `https://jinkittys.com/feeds/local-inventory.txt` | **Local product inventory** | What is on the shelf at the store |

Both are tab-separated, rebuilt per request, and cached for 10 minutes.

Free local listings need **both**. The second one is what makes an item show
as available nearby, and it must be added as data source type *Local product
inventory* — not "Supplemental". Choosing the wrong type is the usual reason
a correct-looking file appears to do nothing.

## Setup, in order

1. **Google Business Profile** — the shop needs a verified profile at
   4100 N Pulaski Rd with real staffed hours. Customers must be able to walk
   in, look at the item and buy it; that is Google's actual requirement for
   this program.
2. **Give the store a store code** in the Business Profile, then set the same
   value on the Pages project as the environment variable
   `MERCHANT_STORE_CODE`. Until that variable exists the feed sends
   `jinkittys-pulaski`. **The two must match exactly** or every inventory row
   is rejected.
3. **Link Business Profile to Merchant Center**, then wait ~24 hours before
   uploading inventory — store locations take that long to sync, and an
   inventory file that arrives first fails against stores Google cannot see
   yet.
4. **Add the two data sources** by URL (scheduled fetch), using the table
   above. Let Google fetch them; there is nothing to upload by hand.
5. **Opt in to free local listings** in Merchant Center. Local inventory ads
   are the paid version of the same data — the free listings are the ones
   that cost nothing, and you can run both later off these same files.

## Decisions baked into the feeds, and why

- **`condition: used`** on everything. It is a thrift shop.
- **`identifier_exists: no`** on everything. Secondhand one-offs have no
  barcode or manufacturer part number. Without this, Merchant Center flags
  the whole feed for missing GTINs.
- **No shipping attributes.** Not required for local listings, because the
  purchase happens in the shop.
- **No `pickup_method` / `pickup_sla`.** Those declare buy-online-pickup-in-
  store, a separate programme with its own fulfilment promise. Walk-in
  browsing does not need them.
- **No `google_product_category`.** Google auto-assigns it, and a wrong guess
  is worse than none. `product_type` carries the shop's own category instead.
- **Items with no real photo are held back from both feeds.** `image_link` is
  required and must be fetchable; older records point at the legacy
  `/images/` folder that no longer exists, and sending those guarantees
  disapproval. They rejoin automatically once the item gets a photo.
- **Sold items stay in, marked `out_of_stock` with quantity `0`**, matching
  what `/p/[slug]` already does. An item that vanishes and returns reads to
  Google as a brand new product.

## Checking it

    curl -sSI https://jinkittys.com/feeds/products.txt | grep -i x-feed
    curl -sSI https://jinkittys.com/feeds/local-inventory.txt | grep -i x-feed

`X-Feed-Items` is how many rows went out, `X-Feed-Skipped-No-Image` is how
many items are being held back for want of a photo, and `X-Feed-Store-Code`
is the code actually being sent — check that one against the Business Profile
if inventory rows are being rejected.

## The part that actually takes work

Setup is once; accuracy is forever. Merchant Center suspends feeds whose
prices and availability do not match what a shopper finds, and with stock
this size that is where these setups fail. The upside is that it is already
handled here — because both feeds read live from the same KV the storefront
serves, a price edit or a sold flag in admin is reflected the next time
Google fetches. Keep admin honest and the feeds stay honest.
