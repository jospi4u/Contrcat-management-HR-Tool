// Sign-in gate for the whole site, run by Vercel before any page is served.
// Nobody receives the app's HTML until they sign in, so it can't be bypassed from the browser.
//
// LOGINS live in the shared database (table app_users) and are managed in the Admin Portal
// at /admin: add people, change roles, reset passwords, deactivate or delete. Only a salted
// one-way fingerprint of each password is stored — never the password itself.
// Every sign-in attempt is recorded, and a login is paused for 15 minutes after 10 wrong tries.

export const config = { matcher: '/:path*' };

const ITERATIONS = 150000; // must match tools/new-login.ps1
const COOKIE = 'aw_session';
const SESSION_HOURS = 12;
const enc = new TextEncoder();
const hex = buf => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
const unhex = h => new Uint8Array((h.match(/../g) || []).map(x => parseInt(x, 16)));

// Password → session key (slow on purpose, to resist guessing)
async function deriveKey(password, saltHex) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations: ITERATIONS }, base, 256);
  return hex(bits);
}
const fingerprint = async keyHex => hex(await crypto.subtle.digest('SHA-256', enc.encode(keyHex)));
const newSalt = () => hex(crypto.getRandomValues(new Uint8Array(16)));

// ---------------------------------------------------------------------
// Shared database (Supabase). The publishable key is public by design: the tables are
// locked, and the database functions check each person's sign-in key and role themselves
// (see supabase/setup.sql). The sign-in key stays in the HttpOnly cookie; the browser's
// scripts never see it.
// ---------------------------------------------------------------------
const SUPABASE_URL = 'https://ciodjmejeazhsbmsnreg.supabase.co';
const SUPABASE_KEY = 'sb_publishable_1pFhbHwJ76v-Q6DnToJfoQ_k3KU8Ibf';

async function call(fn, args) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fn}`, {
    method: 'POST',
    headers: { apikey: SUPABASE_KEY, 'content-type': 'application/json' },
    body: JSON.stringify(args)
  });
  const text = await res.text();
  let data = null; try { data = JSON.parse(text); } catch (e) { data = text; }
  return { ok: res.ok, status: res.status, data, text };
}
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
// pass a database answer back to the page; database errors keep their message so the Admin Portal can show it
async function rpc(fn, args) {
  const r = await call(fn, args);
  if (r.ok) return new Response(r.text, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  const msg = r.data && typeof r.data === 'object' ? r.data.message : '';
  return json({ error: 'database', status: r.status, message: msg || '', detail: r.text.slice(0, 300) }, r.status === 403 || r.status === 401 ? 403 : 502);
}

// The session cookie carries the user ID and the key derived from their password.
function readCookie(req) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=([^;]+)'));
  if (!m) return null;
  const dot = m[1].lastIndexOf('.');
  if (dot < 1) return null;
  const user = decodeURIComponent(m[1].slice(0, dot)), key = m[1].slice(dot + 1);
  return /^[0-9a-f]{64}$/.test(key) ? { user, key } : null;
}
// …and the database confirms it is still valid (deactivated, deleted or reset logins stop working at once)
async function whoami(s) {
  if (!s) return null;
  const r = await call('cw_whoami', { p_user: s.user, p_key: s.key });
  return r.ok && r.data && r.data.user ? r.data : null;
}

const passwordProblem = p => (typeof p !== 'string' || p.length < 8) ? 'Passwords need at least 8 characters.'
  : (!/[A-Za-z]/.test(p) || !/[0-9]/.test(p)) ? 'Passwords need letters and numbers.' : '';

async function api(req, url, s) {
  const body = req.method === 'POST' ? await req.json().catch(() => null) : null;
  if (req.method === 'POST' && !body) return json({ error: 'bad request' }, 400);
  const who = { p_user: s.user, p_key: s.key };

  if (url.pathname === '/api/load' && req.method === 'GET') return rpc('cw_load', who);
  if (url.pathname === '/api/save' && req.method === 'POST') {
    return rpc('cw_save', Object.assign({}, who, {
      p_upserts: body.upserts || [], p_deletes: body.deletes || [], p_settings: body.settings || {}, p_audit: body.audit || []
    }));
  }
  // candidate documents: POST uploads one file (base64), GET ?id= returns it
  if (url.pathname === '/api/doc' && req.method === 'POST') {
    if (!body.id || !body.data) return json({ error: 'bad request' }, 400);
    return rpc('cw_doc_put', Object.assign({}, who, {
      p_id: String(body.id), p_candidate: String(body.candidate || ''), p_kind: String(body.kind || 'other'),
      p_name: String(body.name || 'document'), p_mime: String(body.mime || 'application/octet-stream'), p_data: String(body.data),
      p_contractor: String(body.contractor || ''), p_division: String(body.division || '')
    }));
  }
  if (url.pathname === '/api/doc' && req.method === 'GET') return rpc('cw_doc_get', Object.assign({}, who, { p_id: String(url.searchParams.get('id') || '') }));
  if (url.pathname === '/api/event' && req.method === 'POST') {
    return rpc('cw_event', Object.assign({}, who, { p_kind: String(body.kind || ''), p_meta: body.meta && typeof body.meta === 'object' ? body.meta : {} }));
  }

  // ---- Admin Portal (the database refuses anyone who isn't an admin) ----
  if (url.pathname === '/api/admin/overview' && req.method === 'GET') return rpc('cw_admin_overview', who);
  if (url.pathname === '/api/admin/save-user' && req.method === 'POST') {
    let fp = null, salt = null;
    if (body.password) {
      const problem = passwordProblem(body.password);
      if (problem) return json({ error: 'password', message: problem }, 400);
      salt = newSalt(); fp = await fingerprint(await deriveKey(String(body.password), salt));
    }
    return rpc('cw_admin_save_user', Object.assign({}, who, {
      p_target: String(body.user || ''), p_role: String(body.role || ''), p_contractor: String(body.contractor || ''),
      p_division: String(body.division || ''), p_name: String(body.name || ''), p_active: body.active !== false, p_fp: fp, p_salt: salt
    }));
  }
  if (url.pathname === '/api/admin/delete-user' && req.method === 'POST') return rpc('cw_admin_delete_user', Object.assign({}, who, { p_target: String(body.user || '') }));
  if (url.pathname === '/api/admin/contractors' && req.method === 'POST') return rpc('cw_admin_set_contractors', Object.assign({}, who, { p_list: Array.isArray(body.list) ? body.list : [] }));
  if (url.pathname === '/api/admin/rename-contractor' && req.method === 'POST') {
    return rpc('cw_admin_rename_contractor', Object.assign({}, who, { p_old: String(body.old || ''), p_new: String(body.new || '') }));
  }
  return json({ error: 'not found' }, 404);
}

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const cookie = (value, maxAge) => `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

function page({ error = '', user = '' }, status = 200) {
  const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<link rel="manifest" href="/manifest.webmanifest"><meta name="theme-color" content="#080807">
<link rel="icon" href="/icons/icon-192.png"><link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
<meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-title" content="Aristo">
<title>Sign in · Aristo Contract Manpower</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600&family=Playfair+Display:ital,wght@0,700;1,500&display=swap">
<style>
:root{color-scheme:dark;--bg:#1a1917;--card:#24221f;--ink:#fff;--cream:#f5f0e8;--muted:#a39d94;--gold:#c4a882;--gold-hover:#d4bc9a;--line:rgba(255,255,255,.16);--danger:#ef5f64}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px 16px;background:var(--bg);color:var(--cream);font:14px/1.6 "DM Sans",system-ui,sans-serif}
.card{width:100%;max-width:400px;background:var(--card);border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:36px 32px}
.mark{font-weight:600;letter-spacing:4px;color:var(--ink);font-size:15px}
.rule{width:32px;height:2px;background:var(--gold);margin:14px 0 22px}
.eyebrow{font-family:"Playfair Display",Georgia,serif;font-style:italic;color:var(--gold);font-size:15px}
h1{font-family:"Playfair Display",Georgia,serif;color:var(--ink);font-size:30px;line-height:36px;margin:2px 0 24px}
label{display:block;font-size:11px;font-weight:500;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
input{width:100%;font:inherit;color:var(--ink);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px;min-height:44px;outline:none;margin-bottom:16px}
input:focus{border-color:var(--gold)}
:focus-visible{outline:2px solid var(--gold);outline-offset:2px}
button{width:100%;min-height:46px;margin-top:6px;border:0;border-radius:0;background:var(--gold);color:#000;font:600 12px "DM Sans",sans-serif;letter-spacing:2px;text-transform:uppercase;cursor:pointer}
button:hover{background:var(--gold-hover)}
.err{border:1px solid var(--danger);color:var(--danger);border-radius:8px;padding:10px 12px;margin-bottom:18px;font-size:13px}
.foot{margin-top:22px;font-size:12px;color:var(--muted)}
</style></head><body>
<main class="card">
  <div class="mark">ARISTO</div><div class="rule"></div>
  <span class="eyebrow">Contract manpower</span>
  <h1>Sign in</h1>
  ${error ? `<div class="err" role="alert">${esc(error)}</div>` : ''}
  <form method="post" action="/login">
    <label for="u">User ID</label>
    <input id="u" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required value="${esc(user)}" ${user ? '' : 'autofocus'}>
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required ${user ? 'autofocus' : ''}>
    <button type="submit">Sign in</button>
  </form>
  <p class="foot">For Aristo HR and approved contractors. Ask HR if you need access.</p>
</main></body></html>`;
  return new Response(html, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY' }
  });
}

const redirect = (to, setCookie) => {
  const h = new Headers({ location: to, 'cache-control': 'no-store' });
  if (setCookie) h.append('set-cookie', setCookie);
  return new Response(null, { status: 303, headers: h });
};

// Tells Vercel to carry on and serve the requested page
const pass = () => new Response(null, { headers: { 'x-middleware-next': '1' } });

const PUBLIC_FILES = new Set(['/manifest.webmanifest', '/icons/icon-192.png', '/icons/icon-512.png', '/icons/icon-maskable-512.png', '/icons/apple-touch-icon.png']);
const ADMIN_PAGES = new Set(['/admin', '/admin.html']);

export default async function middleware(req) {
  const url = new URL(req.url);

  if (url.pathname === '/logout') return redirect('/', cookie('', 0));

  // app icon and install manifest: phones fetch these before anyone signs in; they hold nothing private
  if (PUBLIC_FILES.has(url.pathname)) return pass();

  if (url.pathname === '/login' && req.method === 'POST') {
    const form = await req.formData().catch(() => null);
    const user = String(form?.get('username') || '').trim().toLowerCase();
    const pwd = String(form?.get('password') || '');
    const saltRes = await call('cw_login_salt', { p_user: user });
    if (!saltRes.ok || typeof saltRes.data !== 'string') return page({ error: 'Sign-in is unavailable right now. Please try again in a minute.', user }, 503);
    const key = await deriveKey(pwd, saltRes.data);
    const ip = (req.headers.get('x-forwarded-for') || '').split(',')[0].trim();
    const r = await call('cw_login', { p_user: user, p_key: key, p_ip: ip, p_ua: req.headers.get('user-agent') || '' });
    if (r.ok && r.data && r.data.ok) {
      return redirect(r.data.role === 'admin' ? '/admin' : '/', cookie(encodeURIComponent(user) + '.' + key, SESSION_HOURS * 3600));
    }
    const msg = r.data && r.data.locked ? 'Too many wrong attempts. This login is paused for 15 minutes.'
      : r.data && r.data.inactive ? 'This login has been switched off. Please contact HR.'
      : 'That user ID and password don’t match. Check and try again.';
    return page({ error: msg, user }, 401);
  }

  const s = readCookie(req);

  // the API checks the sign-in itself inside each database call
  if (url.pathname.startsWith('/api/')) {
    if (!s) return json({ error: 'signed out' }, 401);
    return api(req, url, s);
  }

  const me = await whoami(s);
  if (!me) {
    if (url.pathname === '/whoami') return json({ error: 'signed out' }, 401);
    return page({}, 401);
  }
  if (url.pathname === '/login') return redirect(me.role === 'admin' ? '/admin' : '/');
  if (url.pathname === '/whoami') return json(me);
  if (ADMIN_PAGES.has(url.pathname) && me.role !== 'admin') return redirect('/');
  return pass();
}
