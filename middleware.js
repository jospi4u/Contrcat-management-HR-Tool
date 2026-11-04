// Sign-in gate for the whole site, run by Vercel before any page is served.
// Nobody receives the app's HTML until they sign in, so the password can't be bypassed from the browser.
//
// Set in Vercel → Project → Settings → Environment Variables (then redeploy):
//   APP_USERS    one or more logins, comma-separated:  joseph:StrongPass1,hr.office:StrongPass2
//   AUTH_SECRET  any long random text (used to sign the session cookie)
// If APP_USERS is missing the site stays locked.

export const config = { matcher: '/:path*' };

const COOKIE = 'aw_session';
const SESSION_HOURS = 12;
const enc = new TextEncoder();

function users() {
  const map = new Map();
  (process.env.APP_USERS || '').split(',').forEach(pair => {
    const i = pair.indexOf(':');
    if (i > 0) map.set(pair.slice(0, i).trim().toLowerCase(), pair.slice(i + 1).trim());
  });
  return map;
}

async function hmac(text) {
  const secret = process.env.AUTH_SECRET || process.env.APP_USERS || '';
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(text));
  return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, '0')).join('');
}

// Compare via HMAC so timing doesn't reveal how much of a password matched
async function same(a, b) {
  const [x, y] = await Promise.all([hmac('cmp:' + a), hmac('cmp:' + b)]);
  let d = x.length ^ y.length;
  for (let i = 0; i < x.length; i++) d |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return d === 0;
}

async function makeSession(user) {
  const exp = Date.now() + SESSION_HOURS * 3600e3;
  const body = encodeURIComponent(user) + '.' + exp;
  return body + '.' + (await hmac('session:' + body));
}

async function readSession(req) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=([^;]+)'));
  if (!m) return null;
  const parts = m[1].split('.');
  if (parts.length !== 3) return null;
  const [u, exp, sig] = parts;
  if (!(Number(exp) > Date.now())) return null;
  if (!(await same(sig, await hmac('session:' + u + '.' + exp)))) return null;
  const user = decodeURIComponent(u);
  return users().has(user) ? user : null; // removing a user from APP_USERS signs them out
}

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const cookie = (value, maxAge) => `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

function page({ error = '', user = '', locked = false }, status = 200) {
  const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
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
  ${locked ? '' : `<form method="post" action="/login">
    <label for="u">Username</label>
    <input id="u" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required value="${esc(user)}" ${user ? '' : 'autofocus'}>
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required ${user ? 'autofocus' : ''}>
    <button type="submit">Sign in</button>
  </form>`}
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

export default async function middleware(req) {
  const url = new URL(req.url);

  if (users().size === 0) {
    return page({ locked: true, error: 'Sign-in is not set up yet. HR needs to add APP_USERS in Vercel.' }, 503);
  }

  if (url.pathname === '/logout') return redirect('/', cookie('', 0));

  if (url.pathname === '/login' && req.method === 'POST') {
    const form = await req.formData().catch(() => null);
    const user = String(form?.get('username') || '').trim().toLowerCase();
    const pwd = String(form?.get('password') || '');
    const expected = users().get(user);
    const ok = await same(pwd, expected === undefined ? '\u0000no-such-user' : expected);
    if (expected !== undefined && ok) {
      return redirect('/', cookie(await makeSession(user), SESSION_HOURS * 3600));
    }
    return page({ error: 'That username and password don’t match. Check and try again.', user }, 401);
  }

  if (await readSession(req)) {
    if (url.pathname === '/login') return redirect('/');
    return pass();
  }
  return page({}, 401);
}
