// functions/api/quick-delete.js
//
// Called by quick-delete.html — the delete companion to quick-add.
//
// Deleting by id server-side (rather than having the page PUT the whole
// catalog back like admin.html does) matters here: this screen is used on a
// phone alongside Quick Add, so the array the page loaded goes stale the
// moment anything else adds an item. Read-modify-write inside one request
// means a delete only ever removes the listings it was aiming at.
//
// Two actions, both POST. Each takes one item or a batch:
//   { id: "SKU-1042" } / { ids: ["SKU-1042", "SKU-1043"] }
//   { restore: {...product}, index: 3 }
//   { restore: [{ product: {...}, index: 3 }, ...] }
//
// A batch is one KV read-modify-write, so the grid's "delete 12 selected"
// can't half-apply, and Undo puts all 12 back in one go.

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

  if (body && body.restore) return restore(env, products, body);
  return remove(env, products, body);
}

// --- Delete -----------------------------------------------------------

async function remove(env, products, body) {
  const ids = (Array.isArray(body?.ids) ? body.ids : [body?.id])
    .map((id) => String(id || "").trim())
    .filter(Boolean);

  if (!ids.length) return error("Missing product id", 400);

  const removed = [];
  const missing = [];

  for (const id of ids) {
    const index = products.findIndex((p) => p.id === id);
    if (index === -1) {
      // Already gone — someone deleted it from admin.html, or this is a
      // retry. Don't fail the whole batch over it.
      missing.push(id);
      continue;
    }
    const [product] = products.splice(index, 1);
    removed.push({ id, index, product });
  }

  if (!removed.length) {
    return error(
      ids.length === 1
        ? `${ids[0]} isn't in inventory anymore.`
        : "None of those are in inventory anymore.",
      404
    );
  }

  await env.PRODUCTS_KV.put("products", JSON.stringify(products));

  // Photos stay in R2. They're small, and keeping them is what lets Undo put
  // a listing back exactly as it was.
  return json({ ok: true, removed, missing, remaining: products.length });
}

// --- Undo -------------------------------------------------------------

async function restore(env, products, body) {
  // Accept a single product or a batch, and normalize to a list in the
  // order the items were deleted.
  const entries = (Array.isArray(body.restore)
    ? body.restore
    : [{ product: body.restore, index: body.index }]
  ).filter((entry) => entry && entry.product && entry.product.id);

  if (!entries.length) return error("Nothing to restore.", 400);

  // Reverse order: the last thing removed goes back first, so each
  // remembered index still means what it meant at deletion time.
  let restored = 0;
  for (const entry of entries.slice().reverse()) {
    // Already back (double-tapped Undo, or a retry after a flaky network) —
    // skip it rather than adding a second copy.
    if (products.some((p) => p.id === entry.product.id)) continue;

    const requested = Number(entry.index);
    const index = Number.isFinite(requested)
      ? Math.min(Math.max(0, Math.floor(requested)), products.length)
      : products.length;

    products.splice(index, 0, entry.product);
    restored += 1;
  }

  if (restored) await env.PRODUCTS_KV.put("products", JSON.stringify(products));

  return json({ ok: true, restored, total: products.length });
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
