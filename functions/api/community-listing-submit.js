// functions/api/community-listing-submit.js
//
// Called by community-sell.html. Uploads the photo to R2 (in a
// community/ folder, separate from shop inventory and gallery photos)
// and queues the listing for approval in KV. Nothing shows up on the
// site until approved via community-listings-review.html.

export async function onRequestPost(context) {
  try {
    const { request, env } = context;

    if (!env.IMAGES) return error("Server is missing the IMAGES R2 binding.", 500);
    if (!env.IMAGE_BASE_URL) return error("Server is missing IMAGE_BASE_URL.", 500);
    if (!env.PRODUCTS_KV) return error("Server is missing the PRODUCTS_KV binding.", 500);

    let body;
    try {
      body = await request.json();
    } catch {
      return error("Invalid JSON body", 400);
    }

    const { name, description, price, email, mediaType } = body || {};
    const base64 = (body?.base64 || "").replace(/\s/g, "");

    if (!name || !name.trim()) return error("Missing title", 400);
    if (!base64) return error("Missing photo data", 400);
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
      return error("Photo data doesn't look valid — try again.", 400);
    }

    let bytes;
    try {
      bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    } catch (err) {
      return error(`Couldn't decode photo data (${err.message}). Try again.`, 400);
    }

    const ext = extFromMediaType(mediaType);
    const key = `community/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;

    await env.IMAGES.put(key, bytes, {
      httpMetadata: { contentType: mediaType || "image/jpeg" },
    });

    const url = `${env.IMAGE_BASE_URL.replace(/\/$/, "")}/${key}`;

    const raw = await env.PRODUCTS_KV.get("community-listings");
    const listings = raw ? JSON.parse(raw) : [];

    listings.unshift({
      id: `COMM-${Date.now()}`,
      name: name.trim().slice(0, 100),
      description: (description || "").trim().slice(0, 500),
      price: price ? Number(price) : null,
      email: (email || "").trim().slice(0, 200),
      image: url,
      approved: false,
      submittedAt: new Date().toISOString(),
    });

    await env.PRODUCTS_KV.put("community-listings", JSON.stringify(listings));

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    return error(`Unexpected server error: ${err.message}`, 500);
  }
}

function extFromMediaType(mediaType) {
  const map = {
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "image/heic": "heic",
    "image/heif": "heif",
    "image/gif": "gif",
  };
  return map[mediaType] || "jpg";
}

function error(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
