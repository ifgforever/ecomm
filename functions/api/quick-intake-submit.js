// functions/api/quick-intake-submit.js
//
// Called by quick-add.html. This does everything in one shot, server-side:
//   1. Uploads the photo to R2
//   2. Asks Claude to draft name/category/description/pick-note from the
//      photo alone (no note field on this form — it's photo + price only)
//   3. Writes a complete product straight into live inventory
//
// The submitted price is the source of truth and is NEVER touched by the AI
// — it's set once here and that's final, unless someone edits it later in
// admin.html by hand.

export async function onRequestPost(context) {
  try {
    const { env } = context;
    const { request } = context;

    if (!env.IMAGES) return error("Server is missing the IMAGES R2 binding.", 500);
    if (!env.IMAGE_BASE_URL) return error("Server is missing IMAGE_BASE_URL.", 500);
    if (!env.PRODUCTS_KV) return error("Server is missing the PRODUCTS_KV binding.", 500);
    if (!env.ANTHROPIC_API_KEY) return error("Server is missing ANTHROPIC_API_KEY.", 500);

    let body;
    try {
      body = await request.json();
    } catch {
      return error("Invalid JSON body", 400);
    }

    const { price, mediaType } = body || {};
    const base64 = (body?.base64 || "").replace(/\s/g, "");

    if (!price) return error("Missing price", 400);
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

    // 1. Resize/re-encode before storing — full-res phone photos are way
    // bigger than a product photo needs to be. Falls back to the original
    // bytes if the transform ever fails, so an upload never gets blocked
    // over an optimization step.
    let storeBytes = bytes;
    let contentType = mediaType || "image/jpeg";
    if (env.IMAGE_TRANSFORM) {
      try {
        const resized = await env.IMAGE_TRANSFORM.input(new Response(bytes).body)
          .transform({ width: 1600, fit: "scale-down" })
          .output({ format: "image/webp", quality: 82 });
        storeBytes = await resized.response().arrayBuffer();
        contentType = "image/webp";
      } catch {
        // Fall back to the original, unresized bytes.
      }
    }

    // 2. Upload the photo to R2
    const ext = contentType === "image/webp" ? "webp" : extFromMediaType(mediaType);
    const key = `intake/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
    await env.IMAGES.put(key, storeBytes, {
      httpMetadata: { contentType },
    });
    const imageUrl = `${env.IMAGE_BASE_URL.replace(/\/$/, "")}/${key}`;

    // 3. Ask Claude to draft the listing from the photo (using the ORIGINAL
    //    uploaded bytes, not re-fetched from the URL — more reliable)
    const systemPrompt = `You draft resale listings for Jojin's Kitty Thrift, a small curated secondhand shop in Chicago, based only on a photo of the item — no note from the seller this time, work entirely from what's visible in the image. Write:
- a short, honest, appealing product name (title case, no gimmicks)
- a one or two word category (e.g. "Outerwear", "Denim", "Electronics", "Toys")
- a 2-3 sentence description in a warm, honest voice — mention any visible condition issues, don't oversell
- a short one-sentence "pick note" in Jojin's own voice, the kind of personal blurb she'd write if featuring this item

Do NOT include a price — pricing is handled separately and is already final.

Respond with ONLY a raw JSON object — your entire reply must be the JSON object itself, starting with { and ending with }. No markdown fences, no preamble, no commentary. Shape:
{"name": "...", "category": "...", "description": "...", "pickNote": "..."}`;

    const aiRes = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-5",
        max_tokens: 1000,
        system: systemPrompt,
        messages: [
          {
            role: "user",
            content: [
              { type: "image", source: { type: "base64", media_type: mediaType || "image/jpeg", data: base64 } },
              { type: "text", text: "Draft the listing for this item." },
            ],
          },
        ],
      }),
    });

    const aiData = await aiRes.json();
    if (!aiRes.ok) {
      return error(aiData?.error?.message || `AI request failed (${aiRes.status})`, aiRes.status);
    }

    const textBlock = (aiData.content || []).find((b) => b.type === "text");
    if (!textBlock) return error("AI response had no usable text", 500);

    let draft;
    try {
      draft = JSON.parse(extractJson(textBlock.text));
    } catch {
      return error("Couldn't parse the AI's draft — try again.", 500);
    }

    // 4. Build the product and write it straight into live inventory
    const raw = await env.PRODUCTS_KV.get("products");
    const products = raw ? JSON.parse(raw) : [];

    const product = {
      id: nextSku(products),
      name: draft.name || "Untitled item",
      price: Number(price), // fixed — from the app, never from the AI
      category: draft.category || "",
      quantity: 1,
      inStock: true,
      image: imageUrl,
      rotation: 0,
      description: draft.description || "",
      featured: false,
      pickNote: draft.pickNote || "",
      createdAt: new Date().toISOString(),
    };

    products.unshift(product);
    await env.PRODUCTS_KV.put("products", JSON.stringify(products));

    return new Response(JSON.stringify({ ok: true, name: product.name, id: product.id }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    return error(`Unexpected server error: ${err.message}`, 500);
  }
}

function nextSku(products) {
  let maxNum = 1000;
  for (const p of products) {
    const match = /^SKU-(\d+)$/.exec(p.id || "");
    if (match) {
      const num = parseInt(match[1], 10);
      if (num > maxNum) maxNum = num;
    }
  }
  return `SKU-${maxNum + 1}`;
}

function extractJson(text) {
  const cleaned = text.replace(/```json|```/g, "").trim();
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  return start === -1 || end === -1 ? cleaned : cleaned.slice(start, end + 1);
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
