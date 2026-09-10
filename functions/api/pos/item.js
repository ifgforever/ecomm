// functions/api/pos/item.js
//
// GET /api/pos/item?id=SKU-1042 — the checkout screen's lookup after a QR
// scan (or a typed SKU). Returns the product plus what checkout needs to
// warn about: already sold out, etc. Works against either backend via the
// store, so checkout functions even before the D1 cutover.

import { getProduct } from "../../_lib/store.js";
import { json, posError } from "../../_lib/pos.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const id = String(url.searchParams.get("id") || "").trim().toUpperCase();

  if (!id) return posError("Missing id", 400);

  const product = await getProduct(env, id);
  if (!product) return posError(`${id} isn't in inventory.`, 404);

  return json({
    ok: true,
    item: {
      id: product.id,
      name: product.name,
      price: product.price,
      category: product.category,
      quantity: Number(product.quantity ?? 0),
      inStock: !!product.inStock,
      image: product.image || "",
    },
  });
}
