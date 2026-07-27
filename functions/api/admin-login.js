// functions/api/admin-login.js
//
// Checks the submitted key against ADMIN_KEY and, if correct, sets a cookie
// that _middleware.js checks on every request to the protected admin pages
// and their write endpoints.
//
// Setup: in Cloudflare Pages > Settings > Variables and Secrets, add
// ADMIN_KEY as a Secret — any password/passphrase you want. Whoever has
// this can access admin.html, sold-check.html, gallery-review.html, and
// community-listings-review.html, and can approve/edit/delete through them.

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "Server is missing ADMIN_KEY. Add it in Pages > Settings > Variables and Secrets." }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid request" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (body?.password !== env.ADMIN_KEY) {
    return new Response(JSON.stringify({ error: "Incorrect key" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const headers = new Headers({ "Content-Type": "application/json" });
  // 30-day session. HttpOnly keeps it out of reach of any page JS; Secure
  // requires HTTPS (which Cloudflare Pages always is); SameSite=Lax is enough
  // since this is only ever submitted via same-site requests.
  headers.append(
    "Set-Cookie",
    `admin_auth=${env.ADMIN_KEY}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`
  );

  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}
