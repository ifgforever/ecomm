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
  "/admin.html", "/admin",
  "/sold-check.html", "/sold-check",
  "/gallery-review.html", "/gallery-review",
  "/community-listings-review.html", "/community-listings-review",
  "/admin-price.html", "/admin-price",
  // One-shot dupe cleanup tool — remove alongside admin-fix-dupes.html.
  "/admin-fix-dupes.html", "/admin-fix-dupes",
  // Swipe-to-delete screen. quick-add.html stays open (adding is harmless),
  // but removing listings is admin-only, same as deleting from admin.html.
  "/quick-delete.html", "/quick-delete",
]);

const PROTECTED_WRITE_PATHS = new Set([
  "/api/products",
  "/api/gallery",
  "/api/community-listings",
  "/api/hours",
  "/api/refresh-nearby-stores",
  "/api/upload-image",
  "/api/pending-intake",
  "/api/ai-assist",
  "/api/quick-delete",
  // GET on this one is a dry-run preview and stays open; POST publishes to
  // the Facebook Page, so it must not be callable without the admin cookie.
  "/api/fb-post",
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

  return Response.redirect(`${url.origin}/admin-login?next=${encodeURIComponent(path)}`, 302);
}
