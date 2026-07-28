// functions/api/refresh-nearby-stores.js
//
// Admin-only (protected by _middleware.js). Calls Google's Places API (New)
// Nearby Search once, centered on the shop, and caches the results in KV.
// The public site reads from that cache via api/nearby-stores.js — Google
// only gets called when you click "Refresh Nearby Stores" in admin.html,
// not on every page load.

const SHOP_LOCATION = { latitude: 41.9556017, longitude: -87.7278817 };
const SEARCH_RADIUS_METERS = 800; // roughly half a mile — a walkable neighborhood radius

const INCLUDED_TYPES = [
  "clothing_store", "shoe_store", "jewelry_store", "book_store",
  "furniture_store", "home_goods_store", "gift_shop", "bicycle_store",
  "florist", "pet_store", "department_store", "discount_store",
];

export async function onRequestPost(context) {
  try {
    const { env } = context;

    if (!env.GOOGLE_PLACES_API_KEY) {
      return error("Server is missing GOOGLE_PLACES_API_KEY. Add it in Pages > Settings > Variables and Secrets.", 500);
    }
    if (!env.PRODUCTS_KV) {
      return error("Server is missing the PRODUCTS_KV binding.", 500);
    }

    const res = await fetch("https://places.googleapis.com/v1/places:searchNearby", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": env.GOOGLE_PLACES_API_KEY,
        "X-Goog-FieldMask": "places.id,places.displayName,places.formattedAddress,places.location,places.types,places.googleMapsUri,places.websiteUri,places.nationalPhoneNumber",
      },
      body: JSON.stringify({
        includedTypes: INCLUDED_TYPES,
        maxResultCount: 20,
        locationRestriction: {
          circle: {
            center: SHOP_LOCATION,
            radius: SEARCH_RADIUS_METERS,
          },
        },
      }),
    });

    const data = await res.json();
    if (!res.ok) {
      return error(data?.error?.message || `Google Places API error (${res.status})`, res.status);
    }

    const places = (data.places || []).map((p) => ({
      id: p.id,
      name: p.displayName?.text || "Unnamed store",
      address: p.formattedAddress || "",
      types: p.types || [],
      mapsUrl: p.googleMapsUri || "",
      website: p.websiteUri || "",
      phone: p.nationalPhoneNumber || "",
    }));

    const cached = {
      stores: places,
      refreshedAt: new Date().toISOString(),
    };

    await env.PRODUCTS_KV.put("nearby-stores", JSON.stringify(cached));

    return new Response(JSON.stringify({ ok: true, count: places.length }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    return error(`Unexpected server error: ${err.message}`, 500);
  }
}

function error(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
