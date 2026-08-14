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
  let stage = "starting the request";

  try {
    const { env } = context;
    const { request } = context;

    if (!env.IMAGES) return error("Server is missing the IMAGES R2 binding.", 500);
    if (!env.IMAGE_BASE_URL) return error("Server is missing IMAGE_BASE_URL.", 500);
    if (!env.PRODUCTS_KV) return error("Server is missing the PRODUCTS_KV binding.", 500);
    if (!env.ANTHROPIC_API_KEY) return error("Server is missing ANTHROPIC_API_KEY.", 500);

    const anthropicApiKey = String(env.ANTHROPIC_API_KEY)
      .trim()
      .replace(/^['"]|['"]$/g, "");
    if (!anthropicApiKey) return error("Server has an empty ANTHROPIC_API_KEY.", 500);

    const imageBaseUrl = String(env.IMAGE_BASE_URL)
      .trim()
      .replace(/^['"]|['"]$/g, "")
      .replace(/\/$/, "");
    try {
      const parsedImageBaseUrl = new URL(imageBaseUrl);
      if (!["http:", "https:"].includes(parsedImageBaseUrl.protocol)) throw new Error();
    } catch {
      return error("Server has an invalid IMAGE_BASE_URL.", 500);
    }

    stage = "reading the submitted photo";
    let body;
    try {
      body = await request.json();
    } catch {
      return error("Invalid JSON body", 400);
    }

    const { price } = body || {};
    // How many copies came in — defaults to 1, floor of whatever was sent.
    const addQty = Math.max(1, Math.floor(Number(body?.quantity)) || 1);
    const mediaType = String(body?.mediaType || "image/jpeg").trim().toLowerCase();
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
    let contentType = mediaType;
    stage = "optimizing the photo";
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

    const supportedAiTypes = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);
    if (!supportedAiTypes.has(contentType)) {
      return error("This phone photo format could not be converted. Try taking a new photo or choose a JPEG/PNG image.", 400);
    }

    const aiBase64 = contentType === mediaType
      ? base64
      : bytesToBase64(new Uint8Array(storeBytes));

    // 2. Upload the photo to R2
    stage = "saving the photo";
    const ext = contentType === "image/webp" ? "webp" : extFromMediaType(mediaType);
    const key = `intake/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
    await env.IMAGES.put(key, storeBytes, {
      httpMetadata: { contentType },
    });
    const imageUrl = `${imageBaseUrl}/${key}`;

    // 3. Ask Claude to draft the listing from the prepared photo bytes rather
    //    than re-fetching the public URL. If the Images binding converted a
    //    phone-native format, send the resulting WebP to the AI as well.
    stage = "drafting the listing";
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
        "x-api-key": anthropicApiKey,
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
              { type: "image", source: { type: "base64", media_type: contentType, data: aiBase64 } },
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
    stage = "loading inventory";
    const raw = await env.PRODUCTS_KV.get("products");
    const products = raw ? JSON.parse(raw) : [];

    // If this item is already listed — same name once normalized, same price
    // — don't create a second listing (and a second, duplicate page for
    // search engines). Bump the existing listing's quantity instead. A match
    // against a sold-out listing revives it, which keeps the old URL and its
    // history. The just-uploaded photo of the extra copy stays unused in R2;
    // that's cheaper than another failure path here.
    stage = "checking for an existing listing";
    const dupe = products.find(
      (p) =>
        normalizeName(p.name) === normalizeName(draft.name) &&
        Number(p.price) === Number(price)
    );
    if (dupe) {
      dupe.quantity = (Number(dupe.quantity) || 0) + addQty;
      dupe.inStock = true;
      stage = "saving inventory";
      await env.PRODUCTS_KV.put("products", JSON.stringify(products));
      return new Response(
        JSON.stringify({ ok: true, merged: true, name: dupe.name, id: dupe.id, quantity: dupe.quantity }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }

    const product = {
      id: nextSku(products),
      name: draft.name || "Untitled item",
      price: Number(price), // fixed — from the app, never from the AI
      category: draft.category || "",
      quantity: addQty,
      inStock: true,
      image: imageUrl,
      rotation: 0,
      description: draft.description || "",
      featured: false,
      pickNote: draft.pickNote || "",
      createdAt: new Date().toISOString(),
    };

    products.unshift(product);
    stage = "saving inventory";
    await env.PRODUCTS_KV.put("products", JSON.stringify(products));

    return new Response(JSON.stringify({ ok: true, name: product.name, id: product.id }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    return error(`Quick Add failed while ${stage}: ${err.message}`, 500);
  }
}

// The AI names the same item slightly differently across photos ("And The"
// vs "and the"), so compare on letters and digits only.
function normalizeName(name) {
  return String(name || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
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

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function error(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
