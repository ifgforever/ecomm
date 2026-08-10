// functions/api/fb-post.js
//
// Builds and publishes a multi-photo Facebook post from current inventory.
//
// Three things this has to get right:
//
//   1. FAIR ROTATION. Items are drawn only from those not yet used in the
//      current cycle, so nothing repeats until everything else has had a
//      turn. When the pool runs dry the cycle resets and starts over. The
//      cycle is stored in KV under "fb-post-cycle" alongside the id of every
//      item already used.
//
//   2. GROUPED BY CATEGORY. A post is all GameCube games, or all plushies —
//      never a shapeless mix. Only categories with enough unused in-stock
//      items qualify, and one is picked at random among those.
//
//   3. COPY WRITTEN FOR THE ACTUAL ITEMS. Claude gets the real names, prices
//      and category and writes the caption. If that call fails for any
//      reason the post still goes out on a plain template — a broken caption
//      should never block the post.
//
// GET  ?preview=1  builds everything and returns it WITHOUT publishing.
// POST              publishes. Admin-gated: the path is in the middleware's
//                   PROTECTED_WRITE_PATHS, so non-GET requires the admin cookie.

const GRAPH = "https://graph.facebook.com/v21.0";
const CYCLE_KEY = "fb-post-cycle";
const SITE = "https://jinkittys.com";
const DEFAULT_COUNT = 5;

// Two posts a day, morning and evening, so the only job of this gap is to
// stop a double-click or a retried cron run from posting twice in a row.
const MIN_HOURS_BETWEEN_POSTS = 6;

export async function onRequestGet(context) {
  return handle(context, { publish: false });
}

export async function onRequestPost(context) {
  return handle(context, { publish: true });
}

async function handle({ request, env }, { publish }) {
  try {
    for (const k of ["PRODUCTS_KV", "FB_PAGE_ID", "FB_PAGE_TOKEN"]) {
      if (!env[k]) return json({ ok: false, error: `Missing ${k}` }, 500);
    }

    const url = new URL(request.url);
    const count = clamp(parseInt(url.searchParams.get("count") || "", 10) || DEFAULT_COUNT, 2, 10);
    const wantCategory = (url.searchParams.get("category") || "").trim();

    const products = JSON.parse((await env.PRODUCTS_KV.get("products")) || "[]");
    const cycle = JSON.parse((await env.PRODUCTS_KV.get(CYCLE_KEY)) || '{"used":[],"started":null}');
    let used = new Set(cycle.used || []);

    // Two posts a day — morning and night — so the gap only has to stop a
    // double-click or an automated caller firing twice in a row. ?force=1
    // overrides for a deliberate extra post.
    if (publish && cycle.lastPostAt && url.searchParams.get("force") !== "1") {
      const hours = (Date.now() - new Date(cycle.lastPostAt).getTime()) / 36e5;
      if (hours < MIN_HOURS_BETWEEN_POSTS) {
        return json({
          ok: false,
          skipped: "already posted today",
          lastPostAt: cycle.lastPostAt,
          hoursSince: Math.round(hours * 10) / 10,
          hint: "add ?force=1 to post anyway",
        }, 429);
      }
    }

    const eligible = (p) =>
      p && p.id && p.image && p.inStock && (p.quantity ?? 1) > 0 && (p.category || "").trim();

    let pool = products.filter((p) => eligible(p) && !used.has(p.id));

    // Cycle exhausted (or too thin to fill a post) — start a fresh one.
    let cycleReset = false;
    if (byCategory(pool, count, wantCategory).length === 0) {
      used = new Set();
      cycleReset = true;
      pool = products.filter(eligible);
    }

    const picked = byCategory(pool, count, wantCategory);
    if (picked.length === 0) {
      return json({
        ok: false,
        error: wantCategory
          ? `No category "${wantCategory}" has ${count} in-stock items with photos.`
          : `No category has ${count} in-stock items with photos.`,
      }, 400);
    }

    const category = picked[0].category;
    const message = await writeCaption(env, picked, category);

    if (!publish) {
      return json({
        ok: true,
        preview: true,
        category,
        cycleReset,
        remainingInCycle: pool.filter((p) => (p.category || "") === category && !picked.includes(p)).length,
        items: picked.map((p) => ({ id: p.id, name: p.name, price: p.price, image: p.image })),
        message,
      });
    }

    // Upload each photo unpublished to get a media id, then attach them all
    // to one feed post. This is the only way to get a true multi-photo post.
    const mediaIds = [];
    for (const p of picked) {
      const form = new URLSearchParams({
        url: p.image,
        published: "false",
        access_token: env.FB_PAGE_TOKEN,
      });
      const r = await fetch(`${GRAPH}/${env.FB_PAGE_ID}/photos`, { method: "POST", body: form });
      const b = await r.json();
      if (b.error) {
        return json({ ok: false, stage: "photo upload", item: p.id, error: b.error.message }, 502);
      }
      mediaIds.push(b.id);
    }

    const feed = new URLSearchParams({ message, access_token: env.FB_PAGE_TOKEN });
    mediaIds.forEach((id, i) => feed.append(`attached_media[${i}]`, JSON.stringify({ media_fbid: id })));

    const fr = await fetch(`${GRAPH}/${env.FB_PAGE_ID}/feed`, { method: "POST", body: feed });
    const fb = await fr.json();
    if (fb.error) return json({ ok: false, stage: "publish", error: fb.error.message }, 502);

    // Only mark items used once the post actually succeeded, so a failure
    // doesn't silently burn them out of the rotation.
    picked.forEach((p) => used.add(p.id));
    await env.PRODUCTS_KV.put(
      CYCLE_KEY,
      JSON.stringify({
        used: [...used],
        started: cycleReset || !cycle.started ? new Date().toISOString() : cycle.started,
        lastPostAt: new Date().toISOString(),
      })
    );

    return json({
      ok: true,
      postId: fb.id,
      permalink: `https://www.facebook.com/${fb.id}`,
      category,
      cycleReset,
      posted: picked.map((p) => ({ id: p.id, name: p.name })),
      usedThisCycle: used.size,
      message,
    });
  } catch (err) {
    return json({ ok: false, error: err.message }, 500);
  }
}

// Group the pool by category, keep only categories that can fill a post,
// then take a random one and a random sample from it.
function byCategory(pool, count, wantCategory) {
  const groups = new Map();
  for (const p of pool) {
    const c = (p.category || "").trim();
    if (!c) continue;
    if (wantCategory && c.toLowerCase() !== wantCategory.toLowerCase()) continue;
    if (!groups.has(c)) groups.set(c, []);
    groups.get(c).push(p);
  }
  const viable = [...groups.values()].filter((g) => g.length >= count);
  if (viable.length === 0) return [];
  const group = viable[Math.floor(Math.random() * viable.length)];
  return shuffle(group).slice(0, count);
}

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

function money(n) {
  return `$${Number(n || 0).toFixed(2).replace(/\.00$/, "")}`;
}

async function writeCaption(env, items, category) {
  const lines = items.map((p) => `- ${p.name} — ${money(p.price)}`).join("\n");
  const fallback =
    `Fresh ${category} finds just hit the shop 🐾\n\n${lines}\n\n` +
    `All one-of-a-kind, first come first served. 4100 N Pulaski Rd, Mon–Sat 10am–7pm.\n${SITE}`;

  if (!env.ANTHROPIC_API_KEY) return fallback;

  const prompt =
    `Write a short Facebook post for a Chicago secondhand thrift shop called Jojin's Kitty Thrift Shop.\n\n` +
    `The post shows photos of these ${items.length} ${category} items that are in stock right now:\n${lines}\n\n` +
    `Rules:\n` +
    `- 2 to 4 short sentences, warm and casual, like a small shop owner writing it\n` +
    `- Mention the category and a couple of the actual items by name\n` +
    `- Everything is one-of-a-kind secondhand, so urgency is honest, not hype\n` +
    `- No hashtag spam: at most 2, or none\n` +
    `- End with: 4100 N Pulaski Rd, Mon-Sat 10am-7pm and the link ${SITE}\n` +
    `- Plain text only. Return only the post text, nothing else.`;

  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": String(env.ANTHROPIC_API_KEY).trim(),
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-5",
        max_tokens: 400,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const b = await r.json();
    const text = b?.content?.[0]?.text?.trim();
    return text && text.length > 20 ? text : fallback;
  } catch {
    return fallback;
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 1), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
