// functions/api/fb-status.js
//
// Read-only check that the stored Facebook credentials actually work, so a
// broken token is found here rather than the first time someone tries to post.
//
// Deliberately returns only the Page's name, id and which permissions the
// token carries — never the token itself, and nothing that isn't already
// public on the Page. Safe to call unauthenticated.

export async function onRequestGet({ env }) {
  const out = {
    pageIdConfigured: !!env.FB_PAGE_ID,
    tokenConfigured: !!env.FB_PAGE_TOKEN,
  };

  if (!out.pageIdConfigured || !out.tokenConfigured) {
    out.ok = false;
    out.problem = "FB_PAGE_ID and/or FB_PAGE_TOKEN are not set on this environment.";
    return json(out, 200);
  }

  const base = "https://graph.facebook.com/v21.0";
  const token = env.FB_PAGE_TOKEN;

  try {
    const r = await fetch(
      `${base}/${encodeURIComponent(env.FB_PAGE_ID)}?fields=id,name` +
        `&access_token=${encodeURIComponent(token)}`
    );
    const body = await r.json();

    if (body.error) {
      out.ok = false;
      // Facebook's error text is descriptive and contains no secret.
      out.problem = body.error.message;
      out.errorCode = body.error.code;
      return json(out, 200);
    }

    out.pageName = body.name;
    out.pageId = body.id;
    out.idMatchesConfigured = String(body.id) === String(env.FB_PAGE_ID);

    // Which permissions does this token actually carry? This is the thing
    // that silently differs between a user token and a Page token.
    const dbg = await fetch(
      `${base}/debug_token?input_token=${encodeURIComponent(token)}` +
        `&access_token=${encodeURIComponent(token)}`
    ).then((x) => x.json()).catch(() => null);

    const d = dbg && dbg.data;
    if (d) {
      out.tokenType = d.type;                    // PAGE or USER
      out.scopes = d.scopes || [];
      out.expiresAt = d.expires_at === 0 ? "never" : d.expires_at;
      out.canPost = d.type === "PAGE" && (d.scopes || []).includes("pages_manage_posts");
    }

    out.ok = !!out.pageName && out.canPost !== false;
    return json(out, 200);
  } catch (err) {
    out.ok = false;
    out.problem = `Request to Facebook failed: ${err.message}`;
    return json(out, 200);
  }
}

function json(obj, status) {
  return new Response(JSON.stringify(obj, null, 1), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
