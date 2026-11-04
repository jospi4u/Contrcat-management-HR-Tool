// Sign-in gate for the whole site, run by Vercel before any page is served.
// Nobody receives the app's HTML until they sign in, so it can't be bypassed from the browser.
//
// LOGINS: one line per person. Make a new line with:
//   powershell -ExecutionPolicy Bypass -File tools\new-login.ps1 -User <user-id>
// It prints the password (give it to the person) and the line to paste below.
// Each line holds only a salted one-way fingerprint — the password itself is never stored.
// Delete a line to remove that person's access (they are signed out on the next page load).
const USERS = {
  'joseph': { salt: 'fc77088525e6fb937cd46fa5eee0d02d', fp: 'c761c0b819cbd10e6cead2cc2d225bbeee1a838aff67fb7dffc44ff29ebeb1ca' },
  'hr.office': { salt: '8714438895426eaa42b8d5c0fb708542', fp: '754b123c4e06016d3e6eb97475c572dadae79d7002424aa48a969b2180ad6859' },
  'phgs': { salt: '86f76cd31bd2f9a2728f1b7c7c6d0330', fp: 'd2c228c8ee28ee3c5b74ed7c51bc4fc3085f8da8065b780959968c6c49c25334' },
  'supervisor': { salt: 'a53b1bc853958ebccd0f678c191dbf5f', fp: '855833a813d133f692d09a1c34cbc4386e06b0d06d6860726e9f4114b9d15454' },
};

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

function equal(a, b) {
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.min(a.length, b.length); i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

// The session cookie carries the derived key; only someone who knew the password can have it.
async function readSession(req) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=([^;]+)'));
  if (!m) return null;
  const dot = m[1].lastIndexOf('.');
  if (dot < 1) return null;
  const user = decodeURIComponent(m[1].slice(0, dot));
  const key = m[1].slice(dot + 1);
  const u = Object.prototype.hasOwnProperty.call(USERS, user) ? USERS[user] : null;
  if (!u || !/^[0-9a-f]{64}$/.test(key)) return null;
  return equal(await fingerprint(key), u.fp) ? user : null;
}

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const cookie = (value, maxAge) => `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

function page({ error = '', user = '' }, status = 200) {
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

// Used for unknown user IDs so a wrong ID takes as long as a wrong password
const DUMMY_SALT = '00000000000000000000000000000000';

export default async function middleware(req) {
  const url = new URL(req.url);

  if (url.pathname === '/logout') return redirect('/', cookie('', 0));

  if (url.pathname === '/login' && req.method === 'POST') {
    const form = await req.formData().catch(() => null);
    const user = String(form?.get('username') || '').trim().toLowerCase();
    const pwd = String(form?.get('password') || '');
    const u = Object.prototype.hasOwnProperty.call(USERS, user) ? USERS[user] : null;
    const key = await deriveKey(pwd, u ? u.salt : DUMMY_SALT);
    if (u && equal(await fingerprint(key), u.fp)) {
      return redirect('/', cookie(encodeURIComponent(user) + '.' + key, SESSION_HOURS * 3600));
    }
    return page({ error: 'That user ID and password don’t match. Check and try again.', user }, 401);
  }

  if (await readSession(req)) {
    if (url.pathname === '/login') return redirect('/');
    return pass();
  }
  return page({}, 401);
}
