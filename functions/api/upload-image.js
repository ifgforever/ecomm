// functions/api/upload-image.js
//
// Takes the photo picked in admin.html's AI-assist box and writes it straight
// to an R2 bucket, so there's no separate step of pushing the file to /images
// in the repo. Returns a public URL to store in the product's "image" field.
//
// Setup:
//   1. Cloudflare dashboard > R2 > Create bucket (e.g. "jkt-images").
//      First time using R2 may ask for a payment method on file, but stays
//      free under the usual limits (10GB storage / 1M writes / 10M reads
//      per month, at this shop's scale you won't get near it).
//   2. In the bucket's Settings > Public access > Custom Domains, connect a
//      subdomain you control, e.g. images.jinkittys.com (DNS is automatic
//      since the domain's already on Cloudflare).
//   3. In the Pages project > Settings > Bindings > Add > R2 bucket,
//      bind it with variable name IMAGES to the bucket you created.
//   4. In Settings > Variables and Secrets, add a plain variable
//      IMAGE_BASE_URL = "https://images.jinkittys.com" (no trailing slash).
//   5. Redeploy.

export async function onRequestPost(context) {
  // Everything is wrapped in one try/catch so a failure anywhere (R2, base64,
  // anything) always comes back as a clean JSON error instead of a raw,
  // unstructured response the client can't parse.
  try {
    const { request, env } = context;

    if (!env.IMAGES) {
      return error("Server is missing the IMAGES R2 binding. Add it in Pages > Settings > Bindings.", 500);
    }
    if (!env.IMAGE_BASE_URL) {
      return error("Server is missing IMAGE_BASE_URL. Add it in Pages > Settings > Variables and Secrets.", 500);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return error("Invalid JSON body", 400);
    }

    const { filename, mediaType } = body || {};
    // Strip whitespace/newlines defensively — some data-URL producers wrap
    // base64 output, and JS's atob() is strict about rejecting that.
    const base64 = (body?.base64 || "").replace(/\s/g, "");

    if (!filename || !base64) {
      return error("Missing filename or image data", 400);
    }
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
      return error("Image data doesn't look like valid base64 — try picking the photo again.", 400);
    }

    let bytes;
    try {
      bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    } catch (err) {
      return error(`Couldn't decode image data (${err.message}). Try picking the photo again.`, 400);
    }

    // Resize/re-encode before storing — full-res photos are way bigger than
    // a product photo needs to be. Falls back to the original bytes if the
    // transform ever fails, so an upload never gets blocked over it.
    let storeBytes = bytes;
    let contentType = mediaType || "image/jpeg";
    let resizedOk = false;
    if (env.IMAGE_TRANSFORM) {
      try {
        const resized = await env.IMAGE_TRANSFORM.input(new Response(bytes).body)
          .transform({ width: 1600, fit: "scale-down" })
          .output({ format: "image/webp", quality: 82 });
        storeBytes = await resized.response().arrayBuffer();
        contentType = "image/webp";
        resizedOk = true;
      } catch {
        // Fall back to the original, unresized bytes.
      }
    }

    // Strip any "images/" prefix left over from the old convention, and keep
    // the key safe (letters, numbers, dot, dash, underscore only).
    const cleanName = filename.replace(/^images\//, "").replace(/[^a-zA-Z0-9._-]/g, "-");
    const dot = cleanName.lastIndexOf(".");
    const base = dot > -1 ? cleanName.slice(0, dot) : cleanName;
    const ext = resizedOk ? ".webp" : (dot > -1 ? cleanName.slice(dot) : "");

    // R2 is the source of truth for uniqueness — check for a real collision
    // rather than trusting whatever the client already suggested.
    let key = `${base}${ext}`;
    let n = 2;
    while (await env.IMAGES.head(key)) {
      key = `${base}-${n}${ext}`;
      n++;
    }

    await env.IMAGES.put(key, storeBytes, {
      httpMetadata: { contentType },
    });

    const url = `${env.IMAGE_BASE_URL.replace(/\/$/, "")}/${key}`;
    return new Response(JSON.stringify({ url, key }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    return error(`Unexpected server error: ${err.message}`, 500);
  }
}

function error(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
