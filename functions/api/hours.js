// functions/api/hours.js
//
// Same read/write pattern as products.js and gallery.js, just for the
// store-hours text shown on the homepage. GET returns the current hours
// string (falls back to a sensible default if never set). PUT stores a
// new one — used by the Store Hours section in admin.html.

export async function onRequest(context) {
  const { request, env } = context;
  const KEY = "store-hours";
  const DEFAULT_HOURS = "Mon–Sat 11am–4pm";

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
    const hours = (await env.PRODUCTS_KV.get(KEY)) || DEFAULT_HOURS;
    return new Response(JSON.stringify({ hours }), {
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  if (request.method === "PUT") {
    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }

    const hours = (body?.hours || "").trim().slice(0, 200);
    if (!hours) {
      return new Response(JSON.stringify({ error: "Hours text is required" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }

    await env.PRODUCTS_KV.put(KEY, hours);
    return new Response(JSON.stringify({ ok: true, hours }), {
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }

  return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
}
