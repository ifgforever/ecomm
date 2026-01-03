// Jojin's Kitty Thrift Shop - Cloudflare Worker API
// Save this as your Worker (e.g., src/index.js or worker.js)

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*', // In production, set to your domain
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    };

    // Handle preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Helper to create JSON response
    const jsonResponse = (data, status = 200) => {
      return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    };

    try {
      // ==================
      // AUTH ROUTES
      // ==================

      // Register
      if (path === '/api/auth/register' && request.method === 'POST') {
        const { email, password, firstName } = await request.json();

        if (!email || !password) {
          return jsonResponse({ error: 'Email and password required' }, 400);
        }

        if (password.length < 6) {
          return jsonResponse({ error: 'Password must be at least 6 characters' }, 400);
        }

        // Check if user exists
        const existing = await env.DB.prepare(
          'SELECT id FROM users WHERE email = ?'
        ).bind(email.toLowerCase()).first();

        if (existing) {
          return jsonResponse({ error: 'Email already registered' }, 409);
        }

        // Hash password (using Web Crypto API)
        const passwordHash = await hashPassword(password);

        // Create user
        const result = await env.DB.prepare(
          'INSERT INTO users (email, password_hash, first_name) VALUES (?, ?, ?)'
        ).bind(email.toLowerCase(), passwordHash, firstName || null).run();

        const userId = result.meta.last_row_id;

        // Create session
        const token = await createSession(env.DB, userId);

        return jsonResponse({
          success: true,
          user: { id: userId, email: email.toLowerCase(), firstName },
          token,
        });
      }

      // Login
      if (path === '/api/auth/login' && request.method === 'POST') {
        const { email, password } = await request.json();

        if (!email || !password) {
          return jsonResponse({ error: 'Email and password required' }, 400);
        }

        // Find user
        const user = await env.DB.prepare(
          'SELECT id, email, password_hash, first_name FROM users WHERE email = ?'
        ).bind(email.toLowerCase()).first();

        if (!user) {
          return jsonResponse({ error: 'Invalid email or password' }, 401);
        }

        // Verify password
        const valid = await verifyPassword(password, user.password_hash);
        if (!valid) {
          return jsonResponse({ error: 'Invalid email or password' }, 401);
        }

        // Create session
        const token = await createSession(env.DB, user.id);

        return jsonResponse({
          success: true,
          user: { id: user.id, email: user.email, firstName: user.first_name },
          token,
        });
      }

      // Logout
      if (path === '/api/auth/logout' && request.method === 'POST') {
        const token = getTokenFromRequest(request);
        if (token) {
          await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
        }
        return jsonResponse({ success: true });
      }

      // Get current user
      if (path === '/api/auth/me' && request.method === 'GET') {
        const user = await authenticate(request, env.DB);
        if (!user) {
          return jsonResponse({ error: 'Not authenticated' }, 401);
        }
        return jsonResponse({
          user: { id: user.id, email: user.email, firstName: user.first_name },
        });
      }

      // ==================
      // WISHLIST ROUTES
      // ==================

      // Get saved items
      if (path === '/api/saved' && request.method === 'GET') {
        const user = await authenticate(request, env.DB);
        if (!user) {
          return jsonResponse({ error: 'Not authenticated' }, 401);
        }

        const items = await env.DB.prepare(
          'SELECT product_id, saved_at FROM saved_items WHERE user_id = ? ORDER BY saved_at DESC'
        ).bind(user.id).all();

        return jsonResponse({
          savedItems: items.results.map(i => i.product_id),
        });
      }

      // Save an item
      if (path === '/api/saved' && request.method === 'POST') {
        const user = await authenticate(request, env.DB);
        if (!user) {
          return jsonResponse({ error: 'Not authenticated' }, 401);
        }

        const { productId } = await request.json();
        if (!productId) {
          return jsonResponse({ error: 'Product ID required' }, 400);
        }

        try {
          await env.DB.prepare(
            'INSERT INTO saved_items (user_id, product_id) VALUES (?, ?)'
          ).bind(user.id, productId).run();
        } catch (e) {
          // Already saved (unique constraint), that's fine
          if (!e.message.includes('UNIQUE constraint')) {
            throw e;
          }
        }

        return jsonResponse({ success: true, productId });
      }

      // Unsave an item
      if (path.startsWith('/api/saved/') && request.method === 'DELETE') {
        const user = await authenticate(request, env.DB);
        if (!user) {
          return jsonResponse({ error: 'Not authenticated' }, 401);
        }

        const productId = decodeURIComponent(path.split('/api/saved/')[1]);
        if (!productId) {
          return jsonResponse({ error: 'Product ID required' }, 400);
        }

        await env.DB.prepare(
          'DELETE FROM saved_items WHERE user_id = ? AND product_id = ?'
        ).bind(user.id, productId).run();

        return jsonResponse({ success: true, productId });
      }

      // ==================
      // 404
      // ==================
      return jsonResponse({ error: 'Not found' }, 404);

    } catch (error) {
      console.error('API Error:', error);
      return jsonResponse({ error: 'Internal server error' }, 500);
    }
  },
};

// ==================
// HELPER FUNCTIONS
// ==================

// Hash password using PBKDF2
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const hash = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );
  // Store as salt:hash (both base64)
  const saltB64 = btoa(String.fromCharCode(...salt));
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
  return `${saltB64}:${hashB64}`;
}

// Verify password
async function verifyPassword(password, storedHash) {
  const [saltB64, hashB64] = storedHash.split(':');
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const hash = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );
  const hashB64Check = btoa(String.fromCharCode(...new Uint8Array(hash)));
  return hashB64 === hashB64Check;
}

// Create session token
async function createSession(db, userId) {
  const token = crypto.randomUUID() + '-' + crypto.randomUUID();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

  await db.prepare(
    'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)'
  ).bind(userId, token, expiresAt.toISOString()).run();

  // Clean up old sessions
  await db.prepare(
    'DELETE FROM sessions WHERE expires_at < datetime("now")'
  ).run();

  return token;
}

// Get token from Authorization header
function getTokenFromRequest(request) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return null;
}

// Authenticate request
async function authenticate(request, db) {
  const token = getTokenFromRequest(request);
  if (!token) return null;

  const session = await db.prepare(
    `SELECT s.user_id, u.id, u.email, u.first_name 
     FROM sessions s 
     JOIN users u ON s.user_id = u.id 
     WHERE s.token = ? AND s.expires_at > datetime("now")`
  ).bind(token).first();

  return session;
}
