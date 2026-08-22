// functions/api/quick-delete.js
//
// Called by quick-delete.html — the swipe-to-delete companion to quick-add.
//
// Deleting by id server-side (rather than having the page PUT the whole
// catalog back like admin.html does) matters here: this screen is used on a
// phone alongside Quick Add, so the array the page loaded goes stale the
// moment anything else adds an item. Read-modify-write inside one request
// means a swipe only ever removes the one listing it was aiming at.
//
// Two actions, both POST:
//   { id: "SKU-1042" }                        -> removes that listing
//   { restore: {...product}, index: 3 }       -> puts it back (Undo)

export async function onRequestPost(context) {
  const { env, request } = context;

  if (!env.PRODUCTS_KV) return error("Server is missing the PRODUCTS_KV binding.", 500);

  let body;
  try {
    body = await request.json();
  } catch {
    return error("Invalid JSON body", 400);
  }

  const raw = await env.PRODUCTS_KV.get("products");
  const products = raw ? JSON.parse(raw) : [];

  // --- Undo -----------------------------------------------------------
  if (body && body.restore) {
    const product = body.restore;
    if (!product.id) return error("Nothing to restore.", 400);

    // Already back (double-tapped Undo, or a retry after a flaky network) —
    // say ok rather than adding a second copy.
    if (products.some((p) => p.id === product.id)) {
      return json({ ok: true, restored: false, id: product.id });
    }

    const requested = Number(body.index);
    const index = Number.isFinite(requested)
      ? Math.min(Math.max(0, Math.floor(requested)), products.length)
      : products.length;

    products.splice(index, 0, product);
    await env.PRODUCTS_KV.put("products", JSON.stringify(products));
    return json({ ok: true, restored: true, id: product.id, index });
  }

  // --- Delete ---------------------------------------------------------
  const id = String((body && body.id) || "").trim();
  if (!id) return error("Missing product id", 400);

  const index = products.findIndex((p) => p.id === id);
  if (index === -1) return error(`${id} isn't in inventory anymore.`, 404);

  const [product] = products.splice(index, 1);
  await env.PRODUCTS_KV.put("products", JSON.stringify(products));

  // The photo stays in R2. It's a few KB, and keeping it is what makes Undo
  // able to put the listing back exactly as it was.
  return json({ ok: true, id, index, product, remaining: products.length });
}

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function error(message, status) {
  return json({ error: message }, status);
}
