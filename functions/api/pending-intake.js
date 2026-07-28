// functions/api/pending-intake.js
//
// Same pattern as gallery.js / community-listings.js. GET returns the
// current queue of quick-added items waiting to be finished in admin.
// PUT (protected) replaces the queue — used when an item is claimed to be
// finished or removed.

export async function onRequest(context) {
  const { request, env } = context;
  const KEY = "pending-intake";

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,PUT,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  if (!env.PRODUCTS_KV) {
    return new Response(JSON.stringify({ error: "KV binding PRODUCTS_KV missing" }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  if (request.method === "GET") {
    const raw = await env.PRODUCTS_KV.get(KEY);
    const data = raw ? JSON.parse(raw) : [];
    return new Response(JSON.stringify(data), {
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  if (request.method === "PUT") {
    const body = await request.json(); // expects an array
    await env.PRODUCTS_KV.put(KEY, JSON.stringify(body));
    return new Response(JSON.stringify({ ok: true, count: body.length }), {
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
}
