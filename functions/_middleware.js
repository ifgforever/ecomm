// functions/_middleware.js
//
// Runs on every request to the site. Gates two things behind the ADMIN_KEY
// cookie set by admin-login.html + api/admin-login.js:
//   1. The internal tool pages themselves (so browsing to the URL directly
//      redirects to the login page instead of showing the page).
//   2. The WRITE (non-GET) calls those pages make to shared API endpoints —
//      otherwise someone could skip the page entirely and just call the API
//      straight from a script. GET requests to these same endpoints stay
//      open, since the public homepage (index.html) needs to read them with
//      no login at all.
//
// Setup: Pages > Settings > Variables and Secrets > add ADMIN_KEY (Secret).

const PROTECTED_PAGES = new Set([
  "/admin.html",
  "/sold-check.html",
  "/gallery-review.html",
  "/community-listings-review.html",
]);

const PROTECTED_WRITE_PATHS = new Set([
  "/api/products",
  "/api/gallery",
  "/api/community-listings",
  "/api/hours",
]);

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  const isProtectedPage = PROTECTED_PAGES.has(path);
  const isProtectedWrite =
    PROTECTED_WRITE_PATHS.has(path) &&
    request.method !== "GET" &&
    request.method !== "OPTIONS" &&
    request.method !== "HEAD";

  if (!isProtectedPage && !isProtectedWrite) {
    return next();
  }

  if (!env.ADMIN_KEY) {
    // Fail closed: if the key isn't configured yet, block rather than
    // accidentally leaving everything open.
    return new Response("Admin access isn't configured yet.", { status: 503 });
  }

  const cookieHeader = request.headers.get("Cookie") || "";
  const authed = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .includes(`admin_auth=${env.ADMIN_KEY}`);

  if (authed) {
    return next();
  }

  if (isProtectedWrite) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  return Response.redirect(`${url.origin}/admin-login.html?next=${encodeURIComponent(path)}`, 302);
}
