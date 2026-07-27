// functions/api/admin-logout.js
//
// Clears the admin_auth cookie and sends you back to the homepage.
// Linked from admin.html's quick-links bar.

export async function onRequestGet(context) {
  const headers = new Headers();
  headers.append("Set-Cookie", "admin_auth=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
  headers.set("Location", "/");
  return new Response(null, { status: 302, headers });
}
