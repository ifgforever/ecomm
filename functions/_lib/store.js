// functions/_lib/store.js
//
// One product store, two backends. Every reader and writer in the codebase
// goes through here, so the KV -> D1 migration is a binding change, not a
// rewrite:
//
//   - With a D1 binding named DB (and after /api/pos/setup has run), products
//     live as rows in the `items` table and this module reads/writes those.
//   - Without the binding, everything falls back to the original PRODUCTS_KV
//     "products" array, byte-for-byte compatible with what the site has
//     always stored. Nothing breaks while the D1 database is being created.
//
// The POS tables (sales, customers, loyalty) exist only in D1 — the POS
// endpoints check for env.DB themselves and return a clear error if it is
// missing, rather than pretending a sale can be recorded in KV.
//
// Product JSON shape is unchanged from the KV era:
//   { id, name, price, category, quantity, inStock, image, rotation,
//     description, featured, pickNote, createdAt, ... }
// Unknown fields (admin.html has grown a few over time) round-trip through
// the `extra` column so a full-array save from admin never loses data.

const KNOWN_FIELDS = new Set([
  "id", "name", "price", "category", "quantity", "inStock", "image",
  "rotation", "description", "featured", "pickNote", "createdAt",
]);

export function usingD1(env) {
  // The Pages project's dashboard already carries a D1 binding named `jdb`
  // (from an earlier experiment; nothing else reads it). Accept it as an
  // alias so the cutover needs no dashboard edits at all — a binding named
  // `DB` still wins if both exist.
  if (!env.DB && env.jdb) env.DB = env.jdb;
  return !!env.DB;
}

// ---------------------------------------------------------------------------
// Schema. CREATE TABLE IF NOT EXISTS throughout, so running it again is a
// no-op — /api/pos/setup calls this on every invocation.
// ---------------------------------------------------------------------------
export async function ensureSchema(db) {
  const statements = [
    `CREATE TABLE IF NOT EXISTS items (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL DEFAULT '',
      price REAL NOT NULL DEFAULT 0,
      category TEXT NOT NULL DEFAULT '',
      quantity INTEGER NOT NULL DEFAULT 1,
      in_stock INTEGER NOT NULL DEFAULT 1,
      image TEXT NOT NULL DEFAULT '',
      rotation REAL NOT NULL DEFAULT 0,
      description TEXT NOT NULL DEFAULT '',
      featured INTEGER NOT NULL DEFAULT 0,
      pick_note TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT '',
      extra TEXT NOT NULL DEFAULT '{}',
      sort_order INTEGER NOT NULL DEFAULT 0
    )`,
    `CREATE INDEX IF NOT EXISTS idx_items_sort ON items (sort_order)`,

    `CREATE TABLE IF NOT EXISTS customers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL DEFAULT '',
      birthday TEXT NOT NULL DEFAULT '',
      punches INTEGER NOT NULL DEFAULT 0,
      lifetime_visits INTEGER NOT NULL DEFAULT 0,
      credit_cents INTEGER NOT NULL DEFAULT 0,
      last_punch_day TEXT NOT NULL DEFAULT '',
      last_birthday_gift_year INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT ''
    )`,

    `CREATE TABLE IF NOT EXISTS sales (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT NOT NULL DEFAULT '',
      subtotal_cents INTEGER NOT NULL DEFAULT 0,
      tax_rate REAL NOT NULL DEFAULT 0,
      tax_cents INTEGER NOT NULL DEFAULT 0,
      credit_used_cents INTEGER NOT NULL DEFAULT 0,
      total_cents INTEGER NOT NULL DEFAULT 0,
      payment TEXT NOT NULL DEFAULT 'Cash',
      customer_id INTEGER,
      customer_email TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'completed',
      note TEXT NOT NULL DEFAULT '',
      receipt_token TEXT NOT NULL DEFAULT ''
    )`,
    `CREATE INDEX IF NOT EXISTS idx_sales_created ON sales (created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_sales_receipt ON sales (receipt_token)`,

    `CREATE TABLE IF NOT EXISTS sale_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sale_id INTEGER NOT NULL,
      item_id TEXT NOT NULL DEFAULT '',
      name TEXT NOT NULL DEFAULT '',
      category TEXT NOT NULL DEFAULT '',
      price_cents INTEGER NOT NULL DEFAULT 0,
      original_price_cents INTEGER NOT NULL DEFAULT 0,
      qty INTEGER NOT NULL DEFAULT 1,
      returned_qty INTEGER NOT NULL DEFAULT 0
    )`,
    `CREATE INDEX IF NOT EXISTS idx_sale_items_sale ON sale_items (sale_id)`,

    `CREATE TABLE IF NOT EXISTS loyalty_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_id INTEGER NOT NULL,
      sale_id INTEGER,
      type TEXT NOT NULL,
      amount_cents INTEGER NOT NULL DEFAULT 0,
      note TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT ''
    )`,
    `CREATE INDEX IF NOT EXISTS idx_loyalty_customer ON loyalty_events (customer_id)`,

    // The customer-facing kiosk drops typed emails here; the register polls
    // and consumes the newest one. Tiny and self-cleaning (consumed rows and
    // stale rows are deleted on read).
    `CREATE TABLE IF NOT EXISTS kiosk_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT '',
      consumed INTEGER NOT NULL DEFAULT 0
    )`,
  ];
  for (const sql of statements) {
    await db.prepare(sql).run();
  }

  // Columns added after the first release. ALTER TABLE has no IF NOT EXISTS,
  // so each is tried and an "already exists" failure is the normal case on
  // every run after the first.
  for (const sql of [
    "ALTER TABLE sales ADD COLUMN receipt_token TEXT NOT NULL DEFAULT ''",
  ]) {
    try {
      await db.prepare(sql).run();
    } catch {
      // Column already there.
    }
  }
}

// ---------------------------------------------------------------------------
// Row <-> product JSON
// ---------------------------------------------------------------------------
export function productFromRow(row) {
  let extra = {};
  try {
    extra = JSON.parse(row.extra || "{}");
  } catch {
    extra = {};
  }
  return {
    ...extra,
    id: row.id,
    name: row.name,
    price: row.price,
    category: row.category,
    quantity: row.quantity,
    inStock: !!row.in_stock,
    image: row.image,
    rotation: row.rotation,
    description: row.description,
    featured: !!row.featured,
    pickNote: row.pick_note,
    createdAt: row.created_at,
  };
}

export function rowValues(p, sortOrder) {
  const extra = {};
  for (const [k, v] of Object.entries(p || {})) {
    if (!KNOWN_FIELDS.has(k)) extra[k] = v;
  }
  return [
    String(p.id || ""),
    String(p.name || ""),
    Number(p.price) || 0,
    String(p.category || ""),
    Number.isFinite(Number(p.quantity)) ? Math.floor(Number(p.quantity)) : 1,
    p.inStock ? 1 : 0,
    String(p.image || ""),
    Number(p.rotation) || 0,
    String(p.description || ""),
    p.featured ? 1 : 0,
    String(p.pickNote || ""),
    String(p.createdAt || ""),
    JSON.stringify(extra),
    sortOrder,
  ];
}

const UPSERT_SQL = `INSERT INTO items
  (id, name, price, category, quantity, in_stock, image, rotation,
   description, featured, pick_note, created_at, extra, sort_order)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(id) DO UPDATE SET
    name=excluded.name, price=excluded.price, category=excluded.category,
    quantity=excluded.quantity, in_stock=excluded.in_stock,
    image=excluded.image, rotation=excluded.rotation,
    description=excluded.description, featured=excluded.featured,
    pick_note=excluded.pick_note, created_at=excluded.created_at,
    extra=excluded.extra, sort_order=excluded.sort_order`;

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------
export async function listProducts(env) {
  if (usingD1(env)) {
    const { results } = await env.DB.prepare(
      "SELECT * FROM items ORDER BY sort_order ASC, created_at DESC"
    ).all();
    return (results || []).map(productFromRow);
  }
  return loadKvProducts(env);
}

export async function getProduct(env, id) {
  if (usingD1(env)) {
    const row = await env.DB.prepare("SELECT * FROM items WHERE id = ?")
      .bind(String(id))
      .first();
    return row ? productFromRow(row) : null;
  }
  const products = await loadKvProducts(env);
  return products.find((p) => String(p.id) === String(id)) || null;
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

// Newest items sort first, like the old array's unshift().
export async function insertProduct(env, product) {
  if (usingD1(env)) {
    const row = await env.DB.prepare(
      "SELECT COALESCE(MIN(sort_order), 0) AS m FROM items"
    ).first();
    const sortOrder = (Number(row?.m) || 0) - 1;
    await env.DB.prepare(UPSERT_SQL).bind(...rowValues(product, sortOrder)).run();
    return;
  }
  const products = await loadKvProducts(env);
  products.unshift(product);
  await env.PRODUCTS_KV.put("products", JSON.stringify(products));
}

export async function updateProduct(env, product) {
  if (usingD1(env)) {
    const existing = await env.DB.prepare("SELECT sort_order FROM items WHERE id = ?")
      .bind(String(product.id))
      .first();
    const sortOrder = existing ? existing.sort_order : 0;
    await env.DB.prepare(UPSERT_SQL).bind(...rowValues(product, sortOrder)).run();
    return;
  }
  const products = await loadKvProducts(env);
  const i = products.findIndex((p) => String(p.id) === String(product.id));
  if (i === -1) products.unshift(product);
  else products[i] = product;
  await env.PRODUCTS_KV.put("products", JSON.stringify(products));
}

// admin.html saves the entire catalogue as one array (its editing model since
// the KV days). Replace all rows, preserving the array's order as sort_order.
export async function replaceAllProducts(env, productsArray) {
  if (usingD1(env)) {
    const statements = [env.DB.prepare("DELETE FROM items")];
    productsArray.forEach((p, i) => {
      statements.push(env.DB.prepare(UPSERT_SQL).bind(...rowValues(p, i)));
    });
    // Chunked batches: each db.batch is transactional on its own, so the
    // delete+first-chunk can't half-apply; a failure in a later chunk is
    // recoverable by saving again from admin (it's a full rewrite anyway).
    for (let i = 0; i < statements.length; i += 100) {
      await env.DB.batch(statements.slice(i, i + 100));
    }
    return;
  }
  await env.PRODUCTS_KV.put("products", JSON.stringify(productsArray));
}

export async function deleteProducts(env, ids) {
  if (usingD1(env)) {
    const statements = ids.map((id) =>
      env.DB.prepare("DELETE FROM items WHERE id = ?").bind(String(id))
    );
    if (statements.length) await env.DB.batch(statements);
    return;
  }
  const products = await loadKvProducts(env);
  const drop = new Set(ids.map(String));
  const kept = products.filter((p) => !drop.has(String(p.id)));
  await env.PRODUCTS_KV.put("products", JSON.stringify(kept));
}

// Same numbering scheme quick-intake has always used: SKU-<n>, starting at
// SKU-1001, always one past the highest ever seen.
export async function nextSku(env) {
  if (usingD1(env)) {
    const { results } = await env.DB.prepare(
      "SELECT id FROM items WHERE id LIKE 'SKU-%'"
    ).all();
    return skuAfter((results || []).map((r) => r.id));
  }
  const products = await loadKvProducts(env);
  return skuAfter(products.map((p) => p.id));
}

function skuAfter(ids) {
  let maxNum = 1000;
  for (const id of ids) {
    const match = /^SKU-(\d+)$/.exec(id || "");
    if (match) {
      const num = parseInt(match[1], 10);
      if (num > maxNum) maxNum = num;
    }
  }
  return `SKU-${maxNum + 1}`;
}

async function loadKvProducts(env) {
  if (!env.PRODUCTS_KV) return [];
  try {
    const raw = await env.PRODUCTS_KV.get("products");
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

// One-time KV -> D1 copy, run by /api/pos/setup. Refuses to run twice (the
// items table already having rows means D1 is live and KV is stale — copying
// again would resurrect items sold since the cutover).
export async function migrateFromKv(env) {
  if (!usingD1(env)) throw new Error("No D1 binding (DB or jdb)");
  const existing = await env.DB.prepare("SELECT COUNT(*) AS n FROM items").first();
  if (Number(existing?.n) > 0) {
    return { migrated: 0, skipped: true, existing: Number(existing.n) };
  }
  const products = await loadKvProducts(env);
  const statements = products.map((p, i) =>
    env.DB.prepare(UPSERT_SQL).bind(...rowValues(p, i))
  );
  for (let i = 0; i < statements.length; i += 100) {
    await env.DB.batch(statements.slice(i, i + 100));
  }
  return { migrated: products.length, skipped: false };
}
