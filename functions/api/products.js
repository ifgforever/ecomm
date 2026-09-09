// functions/api/products.js
//
// The catalogue read/write endpoint. Storage lives behind _lib/store.js:
// D1 (items table) once a DB binding exists, the original PRODUCTS_KV
// array until then. The JSON shape over the wire is unchanged — the
// storefront and every admin page keep working either way.

import { listProducts, replaceAllProducts, usingD1 } from "../_lib/store.js";

export async function onRequest(context) {
  const { request, env } = context;

  // CORS (optional, but handy for admin page)
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,PUT,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  if (!usingD1(env) && !env.PRODUCTS_KV) {
    return new Response(JSON.stringify({ error: "No product storage: bind D1 as DB or KV as PRODUCTS_KV" }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  if (request.method === "GET") {
    const data = await listProducts(env);
    return new Response(JSON.stringify(data), {
      headers: {
        "Content-Type": "application/json",
        // Storefront visitors can reuse this for a minute (and show a stale
        // copy while revalidating) instead of re-downloading the full
        // catalog on every page view. Admin pages fetch with
        // { cache: "no-store" }, which bypasses this, so editing always
        // sees the latest data.
        "Cache-Control": "public, max-age=60, stale-while-revalidate=600",
        ...corsHeaders,
      },
    });
  }

  if (request.method === "PUT") {
    const body = await request.json(); // expects an array
    if (!Array.isArray(body)) {
      return new Response(JSON.stringify({ error: "Expected a JSON array" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }
    await replaceAllProducts(env, body);
    return new Response(JSON.stringify({ ok: true, count: body.length }), {
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
}
