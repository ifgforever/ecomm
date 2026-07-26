// functions/api/ai-assist.js
//
// Same-origin proxy for the AI buttons in admin.html (Generate listing draft,
// Refresh Handpicked Picks). admin.html posts { system, messages } here instead
// of calling api.anthropic.com directly, so your real Anthropic API key never
// has to sit in client-side code.
//
// Setup:
//   1. Get an API key from https://console.anthropic.com (Settings > API Keys).
//   2. In the Cloudflare Pages dashboard: Settings > Environment variables >
//      add ANTHROPIC_API_KEY as an encrypted/production variable.
//      (Or: wrangler pages secret put ANTHROPIC_API_KEY)
//   3. Redeploy — Pages Functions pick up env vars automatically after that.

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.ANTHROPIC_API_KEY) {
    return new Response(
      JSON.stringify({ error: "Server is missing ANTHROPIC_API_KEY. Add it in Pages > Settings > Environment variables." }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const { system, messages } = body || {};
  if (!messages) {
    return new Response(JSON.stringify({ error: "Missing 'messages' in request body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const anthropicRes = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": env.ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-5",
      max_tokens: 1000,
      system,
      messages,
    }),
  });

  const data = await anthropicRes.json();

  if (!anthropicRes.ok) {
    return new Response(
      JSON.stringify({ error: data?.error?.message || `Anthropic API error (${anthropicRes.status})` }),
      { status: anthropicRes.status, headers: { "Content-Type": "application/json" } }
    );
  }

  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
