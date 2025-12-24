export async function onRequest(context) {
  const { request, env } = context;

  // Key where we store the full array
  const KEY = "products";

  // CORS (optional, but handy for admin page)
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
