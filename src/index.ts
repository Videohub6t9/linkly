import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';
import { createRemoteJWKSet, jwtVerify } from 'jose';

type Env = {
  LINKS: KVNamespace;
  DB: D1Database;
  ASSETS: Fetcher;
  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;
  ALLOWED_DOMAINS: string;
  ADMIN_TOKEN?: string;
};
type Vars = { user: { id: string; email: string } };
type Og = { t?: string; d?: string; i?: string };
type LinkValue = { id: string; u: string; e: number | null; og: Og | null };

const RESERVED = new Set(['api', 'dashboard', 'assets', 'favicon.ico', 'robots.txt']);
const BOT_RE = /bot|crawl|spider|facebookexternalhit|slackbot|twitterbot|whatsapp|telegram|discord|linkedin|preview/i;
const ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

const app = new Hono<{ Bindings: Env; Variables: Vars }>();

/* ---------- Auth: Admin token OR Cloudflare Access JWT ---------- */
let jwks: ReturnType<typeof createRemoteJWKSet> | undefined;

const auth = createMiddleware<{ Bindings: Env; Variables: Vars }>(async (c, next) => {
  let email: string;
  const bearer = c.req.header('Authorization')?.replace(/^Bearer\s+/i, '');

  if (c.env.ADMIN_TOKEN && bearer && bearer === c.env.ADMIN_TOKEN) {
    email = 'admin@local';
  } else {
    const token = c.req.header('Cf-Access-Jwt-Assertion');
    if (!token) return c.json({ error: 'Unauthorized' }, 401);
    try {
      const team = c.env.ACCESS_TEAM_DOMAIN;
      jwks ??= createRemoteJWKSet(new URL(`https://${team}/cdn-cgi/access/certs`));
      const { payload } = await jwtVerify(token, jwks, {
        issuer: `https://${team}`,
        audience: c.env.ACCESS_AUD,
      });
      email = String(payload.email);
    } catch {
      return c.json({ error: 'Unauthorized' }, 401);
    }
  }

  let row = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?')
    .bind(email).first<{ id: string }>();
  if (!row) {
    const id = crypto.randomUUID();
    await c.env.DB.prepare('INSERT INTO users (id, email) VALUES (?, ?)').bind(id, email).run();
    row = { id };
  }
  c.set('user', { id: row.id, email });
  await next();
});

/* ---------- Helpers ---------- */
const randomSlug = (len = 7) =>
  Array.from(crypto.getRandomValues(new Uint8Array(len)), (b) => ALPHABET[b % 62]).join('');

const esc = (s = '') =>
  s.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]!));

const isHttpUrl = (s: unknown): s is string => {
  try { return ['http:', 'https:'].includes(new URL(String(s)).protocol); } catch { return false; }
};

/* ---------- Create link (D1 first, then KV) ---------- */
app.post('/api/links', auth, async (c) => {
  const user = c.get('user');
  const body = await c.req.json().catch(() => null);
  if (!body || !isHttpUrl(body.url)) return c.json({ error: 'A valid http(s) url is required' }, 400);

  const host = new URL(c.req.url).host;
  const domain = String(body.domain ?? host).toLowerCase();
  const allowed = c.env.ALLOWED_DOMAINS.split(',').map((d) => d.trim().toLowerCase());
  if (!allowed.includes(domain)) return c.json({ error: 'Domain not allowed' }, 400);

  const custom: string | undefined = body.slug || undefined;
  if (custom && (!/^[a-zA-Z0-9_-]{1,64}$/.test(custom) || RESERVED.has(custom.toLowerCase()))) {
    return c.json({ error: 'Invalid or reserved slug' }, 400);
  }

  let expiresAt: number | null = null;
  if (body.expiresAt) {
    expiresAt = Date.parse(body.expiresAt);
    if (Number.isNaN(expiresAt) || expiresAt <= Date.now()) {
      return c.json({ error: 'expiresAt must be a future date' }, 400);
    }
  }
  if (body.image && !isHttpUrl(body.image)) return c.json({ error: 'image must be a URL' }, 400);

  const id = crypto.randomUUID();
  let slug = '';

  for (let attempt = 0; attempt < 3; attempt++) {
    slug = custom ?? randomSlug();
    try {
      await c.env.DB.prepare(
        `INSERT INTO links (id, user_id, domain, slug, url, title, description, image, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        id, user.id, domain, slug, body.url,
        body.title ?? null, body.description ?? null, body.image ?? null, expiresAt
      ).run();
      break;
    } catch (e) {
      if (!String(e).includes('UNIQUE')) throw e;
      if (custom) return c.json({ error: 'Slug already taken' }, 409);
      if (attempt === 2) return c.json({ error: 'Could not allocate slug, retry' }, 503);
    }
  }

  const og: Og | null =
    body.title || body.description || body.image
      ? { t: body.title, d: body.description, i: body.image }
      : null;
  const value: LinkValue = { id, u: body.url, e: expiresAt, og };
  const ttl = expiresAt ? Math.max(60, Math.ceil((expiresAt - Date.now()) / 1000)) : undefined;
  try {
    await c.env.LINKS.put(`${domain}/${slug}`, JSON.stringify(value), ttl ? { expirationTtl: ttl } : undefined);
  } catch (e) {
    console.error('KV put failed (will fall back to D1):', e);
  }

  return c.json({ id, slug, domain, shortUrl: `https://${domain}/${slug}`, url: body.url, expiresAt }, 201);
});

/* ---------- List / delete / stats ---------- */
app.get('/api/links', auth, async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT l.*, COALESCE(SUM(s.clicks), 0) AS clicks
     FROM links l LEFT JOIN click_stats s ON s.link_id = l.id
     WHERE l.user_id = ? GROUP BY l.id ORDER BY l.created_at DESC LIMIT 100`
  ).bind(c.get('user').id).all();
  return c.json(results);
});

app.delete('/api/links/:id', auth, async (c) => {
  const link = await c.env.DB.prepare('SELECT domain, slug FROM links WHERE id = ? AND user_id = ?')
    .bind(c.req.param('id'), c.get('user').id).first<{ domain: string; slug: string }>();
  if (!link) return c.json({ error: 'Not found' }, 404);
  await c.env.DB.prepare('DELETE FROM links WHERE id = ?').bind(c.req.param('id')).run();
  await c.env.LINKS.delete(`${link.domain}/${link.slug}`);
  return c.json({ ok: true });
});

app.get('/api/links/:id/stats', auth, async (c) => {
  const id = c.req.param('id');
  const own = await c.env.DB.prepare('SELECT 1 FROM links WHERE id = ? AND user_id = ?')
    .bind(id, c.get('user').id).first();
  if (!own) return c.json({ error: 'Not found' }, 404);
  const q = (col: string) =>
    c.env.DB.prepare(`SELECT ${col} AS key, SUM(clicks) AS clicks FROM click_stats
                      WHERE link_id = ? GROUP BY ${col} ORDER BY ${col === 'day' ? 'day DESC' : 'clicks DESC'} LIMIT 30`).bind(id);
  const [byDay, byCountry, byReferrer] = await c.env.DB.batch([q('day'), q('country'), q('referrer')]);
  return c.json({ byDay: byDay.results, byCountry: byCountry.results, byReferrer: byReferrer.results });
});

/* ---------- Redirect: Cache API -> KV -> D1 ---------- */
app.get('/', (c) => c.redirect('/dashboard/'));

app.get('/:slug', async (c) => {
  const slug = c.req.param('slug');
  const host = new URL(c.req.url).host.toLowerCase();
  const key = `${host}/${slug}`;

  const cache = caches.default;
  const cacheKey = new Request(`https://link-cache.internal/${key}`);

  let link: LinkValue | null;
  const hit = await cache.match(cacheKey);
  if (hit) {
    link = await hit.json<LinkValue | null>();
  } else {
    link = await c.env.LINKS.get<LinkValue>(key, { type: 'json', cacheTtl: 60 });
    if (!link) {
      const row = await c.env.DB.prepare(
        'SELECT id, url, title, description, image, expires_at FROM links WHERE domain = ? AND slug = ?'
      ).bind(host, slug).first<any>();
      if (row) {
        link = {
          id: row.id, u: row.url, e: row.expires_at,
          og: row.title || row.description || row.image
            ? { t: row.title, d: row.description, i: row.image } : null,
        };
      }
    }
    c.executionCtx.waitUntil(
      cache.put(cacheKey, new Response(JSON.stringify(link), {
        headers: { 'Cache-Control': `max-age=${link ? 60 : 30}` },
      }))
    );
  }

  if (!link) return c.text('Link not found', 404);
  if (link.e && link.e < Date.now()) return c.text('This link has expired', 410);

  const ua = c.req.header('user-agent') ?? '';
  const isBot = BOT_RE.test(ua);

  if (isBot && link.og) {
    const { t, d, i } = link.og;
    return c.html(`<!doctype html><html><head><meta charset="utf-8">
<title>${esc(t)}</title>
<meta property="og:title" content="${esc(t)}">
<meta property="og:description" content="${esc(d)}">
${i ? `<meta property="og:image" content="${esc(i)}"><meta name="twitter:card" content="summary_large_image">` : ''}
<meta property="og:url" content="https://${esc(key)}">
<meta http-equiv="refresh" content="0;url=${esc(link.u)}"></head><body></body></html>`);
  }

  if (!isBot) {
    const country = ((c.req.raw as any).cf?.country as string) ?? c.req.header('cf-ipcountry') ?? 'XX';
    let referrer = 'direct';
    try { const r = c.req.header('referer'); if (r) referrer = new URL(r).hostname || 'direct'; } catch {}
    const day = new Date().toISOString().slice(0, 10);
    c.executionCtx.waitUntil(
      c.env.DB.prepare(
        `INSERT INTO click_stats (link_id, day, country, referrer, clicks) VALUES (?, ?, ?, ?, 1)
         ON CONFLICT (link_id, day, country, referrer) DO UPDATE SET clicks = clicks + 1`
      ).bind(link.id, day, country, referrer).run().catch((e) => console.error('stats failed', e))
    );
  }

  return c.redirect(link.u, 302);
});

export default app;
