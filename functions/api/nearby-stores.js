// functions/api/nearby-stores.js
//
// Public, read-only. Returns whatever was cached the last time someone
// clicked "Refresh Nearby Stores" in admin.html. Never calls Google itself —
// that only happens from refresh-nearby-stores.js.

export async function onRequestGet(context) {
  const { env } = context;

  if (!env.PRODUCTS_KV) {
    return new Response(JSON.stringify({ stores: [], refreshedAt: null }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  const raw = await env.PRODUCTS_KV.get("nearby-stores");
  const data = raw ? JSON.parse(raw) : { stores: [], refreshedAt: null };

  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
