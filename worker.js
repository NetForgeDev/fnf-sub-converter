/**
 * Cloudflare Worker: F&F Xray Subscription Converter
 * Repository: https://github.com/NetForgeDev/fnf-sub-converter
 * KV Binding required: SUB_KV
 * Optional Env Vars (initial fallback): ADMIN_PATH (default: "panel"), ADMIN_PASS (default: "admin123")
 */

const APP_VERSION = '1.0.2';
const GITHUB_URL = 'https://github.com/NetForgeDev/fnf-sub-converter';

const DEFAULT_CS_LIST = [
  {
    id: 'default-cs-1',
    name: 'Standard TLS 1.3 + ECDHE',
    value:
      'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
  },
];

const DEFAULT_FM_LIST = [
  {
    id: 'default-fm-v1',
    name: 'Fragment v1',
    value:
      '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}}]}',
  },
  {
    id: 'default-fm-v2',
    name: 'Fragment v2',
    value:
      '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}]}',
  },
];

const FP_OPTIONS = ['unsafe', 'chrome', 'firefox', 'safari', 'random', 'none'];
const TRANSPORT_OPTIONS = [
  { id: 'ws', label: 'WS' },
  { id: 'httpupgrade', label: 'HTTPUpgrade' },
  { id: 'xhttp', label: 'XHTTP' },
  { id: 'grpc', label: 'gRPC' },
  { id: 'tcp', label: 'TCP' },
];
const ALL_TRANSPORT_IDS = TRANSPORT_OPTIONS.map((t) => t.id);
const VALID_IP_GEN_MODES = ['v4', 'v6', 'both', 'mixed'];
const KV_KEY = 'CONFIG_STATE_V1';

export default {
  async fetch(request, env, ctx) {
    try {
      if (!env.SUB_KV) {
        return new Response(renderKvSetupPage(), {
          status: 500,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }

      const url = new URL(request.url);
      const pathname = url.pathname.replace(/\/+$/, '') || '/';
      const state = await loadState(env);
      const adminRoute = '/' + normalizePath(state.adminPath);

      // 1. Public Subscription Output: /sub/<id>
      if (pathname.startsWith('/sub/')) {
        const subId = decodeURIComponent(pathname.slice(5)).trim();
        return await handlePublicSub(request, url, state, subId);
      }

      // 2. Auth APIs
      if (pathname === '/api/login' && request.method === 'POST') {
        return await handleLogin(request, url, state);
      }
      if (pathname === '/api/logout' && request.method === 'POST') {
        return handleLogout(url);
      }

      // 3. Protected Admin APIs
      if (pathname.startsWith('/api/')) {
        const authed = await verifySession(request, state);
        if (!authed) {
          return jsonResponse({ error: 'Unauthorized' }, 401);
        }
        return await handleAdminApi(request, pathname, env, state);
      }

      // 4. Admin Panel Route
      if (pathname === adminRoute) {
        const authed = await verifySession(request, state);
        if (!authed) {
          return new Response(renderLoginPage(adminRoute), {
            headers: { 'Content-Type': 'text/html; charset=utf-8' },
          });
        }
        return new Response(renderDashboardPage(state, url.origin), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }

      // 5. Neutral Root / Fallback
      return new Response(
        '<!doctype html><html><head><meta charset="utf-8"><title>Service Active</title></head><body style="background:#0b1020;color:#94a3b8;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div>Worker is running.</div></body></html>',
        { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
      );
    } catch (err) {
      return jsonResponse({ error: err.message || 'Internal Error' }, 500);
    }
  },
};

/* ===========================
   State & Auth Management
   =========================== */

async function loadState(env) {
  let state = await env.SUB_KV.get(KV_KEY, 'json');
  if (!state) {
    const initPath = normalizePath(env.ADMIN_PATH || 'panel');
    const initPass = env.ADMIN_PASS || 'admin123';
    state = {
      version: APP_VERSION,
      adminPath: initPath,
      passwordHash: await sha256Hex(initPass),
      sessionSecret: randomId(32),
      csPresets: DEFAULT_CS_LIST,
      fmPresets: DEFAULT_FM_LIST,
      ipPresets: [],
      subs: [],
    };
    await env.SUB_KV.put(KV_KEY, JSON.stringify(state));
  } else {
    let dirty = false;
    if (!Array.isArray(state.csPresets)) { state.csPresets = DEFAULT_CS_LIST; dirty = true; }
    if (!Array.isArray(state.fmPresets)) { state.fmPresets = DEFAULT_FM_LIST; dirty = true; }
    if (!Array.isArray(state.ipPresets)) { state.ipPresets = []; dirty = true; }
    if (!Array.isArray(state.subs)) { state.subs = []; dirty = true; }

    if (state.version !== APP_VERSION) {
      for (const fm of state.fmPresets) {
        if (fm.id === 'default-fm-v1' && fm.name === 'Fragment v1 (Classic)') fm.name = 'Fragment v1';
        if (fm.id === 'default-fm-v2' && fm.name === 'Fragment v2 (Default)') fm.name = 'Fragment v2';
      }
      const idxV1 = state.fmPresets.findIndex((x) => x.id === 'default-fm-v1');
      const idxV2 = state.fmPresets.findIndex((x) => x.id === 'default-fm-v2');
      if (idxV1 !== -1 && idxV2 !== -1 && idxV2 < idxV1) {
        const tmp = state.fmPresets[idxV1];
        state.fmPresets[idxV1] = state.fmPresets[idxV2];
        state.fmPresets[idxV2] = tmp;
      }
      state.version = APP_VERSION;
      dirty = true;
    }

    if (dirty) {
      await env.SUB_KV.put(KV_KEY, JSON.stringify(state));
    }
  }
  return state;
}

async function saveState(env, state) {
  await env.SUB_KV.put(KV_KEY, JSON.stringify(state));
}

function normalizePath(p) {
  const cleaned = String(p || 'panel')
    .trim()
    .replace(/^\/+|\/+$/g, '')
    .replace(/[^a-zA-Z0-9_-]/g, '');
  if (!cleaned || cleaned === 'sub' || cleaned === 'api') return 'panel';
  return cleaned;
}

function resolveSubIpGenMode(sub) {
  if (VALID_IP_GEN_MODES.includes(sub.ipGenMode)) return sub.ipGenMode;
  if (sub.useV4 === true && sub.useV6 === false) return 'v4';
  if (sub.useV4 === false && sub.useV6 === true) return 'v6';
  return 'mixed';
}

function resolveSubTransports(sub) {
  if (Array.isArray(sub.transports) && sub.transports.length > 0) {
    const filtered = sub.transports.filter((t) => ALL_TRANSPORT_IDS.includes(t));
    if (filtered.length > 0) return filtered;
  }
  return ALL_TRANSPORT_IDS.slice();
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function randomId(len = 10) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').slice(0, len);
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return null;
}

async function verifySession(request, state) {
  const token = getCookie(request, 'sub_admin_session');
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [expStr, sig] = parts;
  const exp = Number(expStr);
  if (!exp || Date.now() > exp) return false;
  const expectedSig = await hmacSign(state.sessionSecret, expStr);
  return timingSafeEqual(sig, expectedSig);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function handleLogin(request, url, state) {
  const body = await request.json().catch(() => ({}));
  const password = String(body.password || '');
  const hash = await sha256Hex(password);
  if (!timingSafeEqual(hash, state.passwordHash)) {
    return jsonResponse({ error: 'Invalid password' }, 401);
  }
  const exp = String(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const sig = await hmacSign(state.sessionSecret, exp);
  const token = `${exp}.${sig}`;
  const secureFlag = url.protocol === 'https:' ? '; Secure' : '';
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': `sub_admin_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${secureFlag}`,
    },
  });
}

function handleLogout(url) {
  const secureFlag = url.protocol === 'https:' ? '; Secure' : '';
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': `sub_admin_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureFlag}`,
    },
  });
}

/* ===========================
   Admin API Handlers
   =========================== */

async function handleAdminApi(request, pathname, env, state) {
  const method = request.method;

  if (pathname === '/api/data' && method === 'GET') {
    return jsonResponse({
      version: APP_VERSION,
      adminPath: state.adminPath,
      csPresets: state.csPresets,
      fmPresets: state.fmPresets,
      ipPresets: state.ipPresets,
      subs: state.subs,
      fpOptions: FP_OPTIONS,
      transportOptions: TRANSPORT_OPTIONS,
    });
  }

  // Subscriptions CRUD
  if (pathname === '/api/subs' && (method === 'POST' || method === 'PUT')) {
    const body = await request.json();
    const name = String(body.name || '').trim() || 'Untitled Sub';
    const inputUrl = String(body.inputUrl || '').trim();
    if (!inputUrl) return jsonResponse({ error: 'Input subscription URL or content is required' }, 400);

    const customSlug = String(body.id || '').trim().replace(/[^a-zA-Z0-9_-]/g, '');
    const editingId = String(body.editingId || '').trim();

    const fp = FP_OPTIONS.includes(body.fp) ? body.fp : 'unsafe';
    const csId = String(body.csId || '');
    const fmId = String(body.fmId || '');
    const ipListId = String(body.ipListId || '');
    const ipGenMode = VALID_IP_GEN_MODES.includes(body.ipGenMode) ? body.ipGenMode : '';
    const transports = Array.isArray(body.transports)
      ? body.transports.filter((t) => ALL_TRANSPORT_IDS.includes(t))
      : [];
    const base64 = Boolean(body.base64);

    if (!transports.length) {
      return jsonResponse({ error: 'Please select at least one Transport type' }, 400);
    }
    if (!ipGenMode) {
      return jsonResponse({ error: 'Please select an Output IP Version mode' }, 400);
    }

    if (ipListId) {
      const ipPreset = state.ipPresets.find((x) => x.id === ipListId);
      if (ipPreset) {
        const v4Pool = ipPreset.ips.filter(isIPv4);
        const v6Pool = ipPreset.ips.filter(isIPv6);
        if (ipGenMode === 'v4' && !v4Pool.length) {
          return jsonResponse({ error: 'Selected IP list contains no IPv4 addresses' }, 400);
        }
        if (ipGenMode === 'v6' && !v6Pool.length) {
          return jsonResponse({ error: 'Selected IP list contains no IPv6 addresses' }, 400);
        }
        if (ipGenMode === 'both' && (!v4Pool.length || !v6Pool.length)) {
          return jsonResponse({ error: 'Selected IP list must contain both IPv4 and IPv6 addresses for dual output' }, 400);
        }
        if (ipGenMode === 'mixed' && !ipPreset.ips.length) {
          return jsonResponse({ error: 'Selected IP list is empty' }, 400);
        }
      }
    }

    const subObj = {
      id: editingId ? (customSlug || editingId) : (customSlug || randomId(10)),
      name,
      inputUrl,
      csId,
      fmId,
      ipListId,
      ipGenMode,
      transports,
      fp,
      base64,
      updatedAt: Date.now(),
    };

    if (editingId) {
      const idx = state.subs.findIndex((s) => s.id === editingId);
      if (idx === -1) return jsonResponse({ error: 'Subscription not found' }, 404);
      if (subObj.id !== editingId && state.subs.some((s) => s.id === subObj.id)) {
        return jsonResponse({ error: 'This custom ID is already in use' }, 400);
      }
      state.subs[idx] = subObj;
    } else {
      if (state.subs.some((s) => s.id === subObj.id)) {
        return jsonResponse({ error: 'This custom ID is already in use' }, 400);
      }
      state.subs.unshift(subObj);
    }
    await saveState(env, state);
    return jsonResponse({ ok: true, subs: state.subs });
  }

  if (pathname === '/api/subs' && method === 'DELETE') {
    const body = await request.json();
    state.subs = state.subs.filter((s) => s.id !== body.id);
    await saveState(env, state);
    return jsonResponse({ ok: true, subs: state.subs });
  }

  // CS Presets CRUD
  if (pathname === '/api/cs' && method === 'POST') {
    const body = await request.json();
    const name = String(body.name || '').trim();
    const value = String(body.value || '').trim();
    if (!name || !value) return jsonResponse({ error: 'Name and Cipher Suite value are required' }, 400);

    if (body.id) {
      const idx = state.csPresets.findIndex((x) => x.id === body.id);
      if (idx !== -1) state.csPresets[idx] = { id: body.id, name, value };
    } else {
      state.csPresets.push({ id: 'cs-' + randomId(8), name, value });
    }
    await saveState(env, state);
    return jsonResponse({ ok: true, csPresets: state.csPresets });
  }

  if (pathname === '/api/cs' && method === 'DELETE') {
    const body = await request.json();
    state.csPresets = state.csPresets.filter((x) => x.id !== body.id);
    await saveState(env, state);
    return jsonResponse({ ok: true, csPresets: state.csPresets });
  }

  // FM Presets CRUD
  if (pathname === '/api/fm' && method === 'POST') {
    const body = await request.json();
    const name = String(body.name || '').trim();
    const value = String(body.value || '').trim();
    if (!name || !value) return jsonResponse({ error: 'Name and Final Mask value are required' }, 400);
    try {
      JSON.parse(value);
    } catch {
      return jsonResponse({ error: 'Final Mask must be valid JSON' }, 400);
    }

    if (body.id) {
      const idx = state.fmPresets.findIndex((x) => x.id === body.id);
      if (idx !== -1) state.fmPresets[idx] = { id: body.id, name, value };
    } else {
      state.fmPresets.push({ id: 'fm-' + randomId(8), name, value });
    }
    await saveState(env, state);
    return jsonResponse({ ok: true, fmPresets: state.fmPresets });
  }

  if (pathname === '/api/fm' && method === 'DELETE') {
    const body = await request.json();
    state.fmPresets = state.fmPresets.filter((x) => x.id !== body.id);
    await saveState(env, state);
    return jsonResponse({ ok: true, fmPresets: state.fmPresets });
  }

  // IP Lists CRUD
  if (pathname === '/api/ips' && method === 'POST') {
    const body = await request.json();
    const name = String(body.name || '').trim();
    const ips = parseIpList(body.value || '');
    if (!name) return jsonResponse({ error: 'IP list name is required' }, 400);
    if (!ips.length) return jsonResponse({ error: 'Please enter at least one valid IPv4 or IPv6 address' }, 400);

    if (body.id) {
      const idx = state.ipPresets.findIndex((x) => x.id === body.id);
      if (idx !== -1) state.ipPresets[idx] = { id: body.id, name, ips };
    } else {
      state.ipPresets.push({ id: 'ip-' + randomId(8), name, ips });
    }
    await saveState(env, state);
    return jsonResponse({ ok: true, ipPresets: state.ipPresets });
  }

  if (pathname === '/api/ips' && method === 'DELETE') {
    const body = await request.json();
    state.ipPresets = state.ipPresets.filter((x) => x.id !== body.id);
    await saveState(env, state);
    return jsonResponse({ ok: true, ipPresets: state.ipPresets });
  }

  // Settings (Admin Path & Password)
  if (pathname === '/api/settings' && method === 'POST') {
    const body = await request.json();
    let changedAuth = false;

    if (body.adminPath && String(body.adminPath).trim()) {
      state.adminPath = normalizePath(body.adminPath);
    }
    if (body.newPassword && String(body.newPassword).trim()) {
      if (String(body.newPassword).length < 4) {
        return jsonResponse({ error: 'Password must be at least 4 characters' }, 400);
      }
      state.passwordHash = await sha256Hex(String(body.newPassword));
      state.sessionSecret = randomId(32);
      changedAuth = true;
    }

    await saveState(env, state);
    return jsonResponse({
      ok: true,
      adminPath: state.adminPath,
      reloginRequired: changedAuth,
    });
  }

  // Live Preview
  if (pathname === '/api/preview' && method === 'POST') {
    const body = await request.json();
    const sub = state.subs.find((s) => s.id === body.id);
    if (!sub) return jsonResponse({ error: 'Subscription not found' }, 404);
    const result = await convertSubscription(sub, state);
    return jsonResponse(result);
  }

  return jsonResponse({ error: 'Not Found' }, 404);
}

/* ===========================
   Public Subscription Endpoint
   =========================== */

async function handlePublicSub(request, url, state, subId) {
  if (request.headers.get('X-Sub-Converter') === '1') {
    return new Response('Loop detected', { status: 400 });
  }
  const sub = state.subs.find((s) => s.id === subId);
  if (!sub) {
    return new Response('Subscription not found', { status: 404 });
  }

  const result = await convertSubscription(sub, state);
  const rawText = result.links.join('\n');

  let useBase64 = sub.base64;
  if (url.searchParams.get('b64') === '1') useBase64 = true;
  if (url.searchParams.get('raw') === '1') useBase64 = false;

  const output = useBase64 ? base64EncodeUtf8(rawText) : rawText;

  const headers = new Headers({
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'Profile-Title': `base64:${base64EncodeUtf8(sub.name)}`,
  });

  if (result.upstreamHeaders['subscription-userinfo']) {
    headers.set('subscription-userinfo', result.upstreamHeaders['subscription-userinfo']);
  }
  if (result.upstreamHeaders['profile-update-interval']) {
    headers.set('profile-update-interval', result.upstreamHeaders['profile-update-interval']);
  }

  return new Response(output, { status: 200, headers });
}

/* ===========================
   Core Subscription Converter
   =========================== */

async function fetchAndParseUrl(targetUrl) {
  const userAgents = ['sing-box/1.10.0', 'v2rayNG/1.8.38'];
  let lastStatus = 0;

  for (let i = 0; i < userAgents.length; i++) {
    const resp = await fetch(targetUrl, {
      headers: {
        'User-Agent': userAgents[i],
        Accept: '*/*',
        'X-Sub-Converter': '1',
      },
    });
    lastStatus = resp.status;
    if (!resp.ok) continue;

    const text = await resp.text();
    const parsed = parseSubscriptionPayload(text);
    if (parsed.nodes.length > 0 || parsed.format !== 'unknown') {
      return {
        parsed,
        headers: {
          'subscription-userinfo': resp.headers.get('subscription-userinfo') || '',
          'profile-update-interval': resp.headers.get('profile-update-interval') || '',
        },
      };
    }
  }

  if (lastStatus && lastStatus >= 400) {
    throw new Error(`Failed to fetch input subscription (HTTP ${lastStatus})`);
  }
  return {
    parsed: { format: 'unknown', nodes: [], skippedUnsupported: 0 },
    headers: {},
  };
}

async function convertSubscription(sub, state) {
  const csPreset = state.csPresets.find((x) => x.id === sub.csId);
  const fmPreset = state.fmPresets.find((x) => x.id === sub.fmId);
  const ipPreset = state.ipPresets.find((x) => x.id === sub.ipListId);

  const ipGenMode = resolveSubIpGenMode(sub);
  const allowedTransports = resolveSubTransports(sub);
  const csValue = csPreset ? csPreset.value.trim() : '';
  const fmValue = fmPreset ? fmPreset.value.trim() : '';
  const fpValue = sub.fp || 'unsafe';

  const allPool = ipPreset && Array.isArray(ipPreset.ips) ? ipPreset.ips : [];
  const v4Pool = allPool.filter(isIPv4);
  const v6Pool = allPool.filter(isIPv6);

  if (ipPreset) {
    if (ipGenMode === 'v4' && !v4Pool.length) {
      throw new Error(`Selected IP list "${ipPreset.name}" has no IPv4 addresses`);
    }
    if (ipGenMode === 'v6' && !v6Pool.length) {
      throw new Error(`Selected IP list "${ipPreset.name}" has no IPv6 addresses`);
    }
    if (ipGenMode === 'both' && (!v4Pool.length || !v6Pool.length)) {
      throw new Error(`Selected IP list "${ipPreset.name}" needs both IPv4 and IPv6 addresses`);
    }
    if (ipGenMode === 'mixed' && !allPool.length) {
      throw new Error(`Selected IP list "${ipPreset.name}" is empty`);
    }
  }

  const rawInput = String(sub.inputUrl || '').trim();
  const allNodes = [];
  const detectedFormats = new Set();
  const upstreamHeaders = {};
  let skippedNonTls = 0;
  let skippedTransport = 0;
  let skippedIpVersion = 0;
  let skippedUnsupported = 0;

  if (rawInput.startsWith('{') || rawInput.startsWith('[')) {
    const parsed = parseSubscriptionPayload(rawInput);
    allNodes.push(...parsed.nodes);
    skippedUnsupported += parsed.skippedUnsupported;
    detectedFormats.add(parsed.format);
  } else {
    const lines = rawInput.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    const urlLines = [];
    const directLines = [];

    for (const line of lines) {
      if (/^https?:\/\//i.test(line)) {
        urlLines.push(line);
      } else {
        directLines.push(line);
      }
    }

    for (const targetUrl of urlLines) {
      const fetched = await fetchAndParseUrl(targetUrl);
      allNodes.push(...fetched.parsed.nodes);
      skippedUnsupported += fetched.parsed.skippedUnsupported;
      if (fetched.parsed.format !== 'unknown') detectedFormats.add(fetched.parsed.format);

      if (!upstreamHeaders['subscription-userinfo'] && fetched.headers['subscription-userinfo']) {
        upstreamHeaders['subscription-userinfo'] = fetched.headers['subscription-userinfo'];
      }
      if (!upstreamHeaders['profile-update-interval'] && fetched.headers['profile-update-interval']) {
        upstreamHeaders['profile-update-interval'] = fetched.headers['profile-update-interval'];
      }
    }

    if (directLines.length > 0) {
      const parsed = parseSubscriptionPayload(directLines.join('\n'));
      allNodes.push(...parsed.nodes);
      skippedUnsupported += parsed.skippedUnsupported;
      if (parsed.format !== 'unknown') detectedFormats.add(parsed.format);
    }
  }

  const pickRandom = (arr) => arr[Math.floor(Math.random() * arr.length)];
  const uriOpts = { fp: fpValue, cs: csValue, fm: fmValue };

  const links = [];
  for (const node of allNodes) {
    if (node.security !== 'tls') {
      skippedNonTls++;
      continue;
    }
    if (!allowedTransports.includes(node.netType)) {
      skippedTransport++;
      continue;
    }

    if (ipPreset) {
      if (ipGenMode === 'v4') {
        const built = buildCleanXrayUri({ ...node, server: pickRandom(v4Pool) }, uriOpts);
        if (built) links.push(built);
      } else if (ipGenMode === 'v6') {
        const built = buildCleanXrayUri({ ...node, server: pickRandom(v6Pool) }, uriOpts);
        if (built) links.push(built);
      } else if (ipGenMode === 'both') {
        const builtV4 = buildCleanXrayUri({ ...node, server: pickRandom(v4Pool) }, uriOpts);
        const builtV6 = buildCleanXrayUri({ ...node, server: pickRandom(v6Pool) }, uriOpts);
        if (builtV4) links.push(builtV4);
        if (builtV6) links.push(builtV6);
      } else {
        const built = buildCleanXrayUri({ ...node, server: pickRandom(allPool) }, uriOpts);
        if (built) links.push(built);
      }
    } else {
      if (ipGenMode === 'v4' && isIPv6(node.server)) {
        skippedIpVersion++;
        continue;
      }
      if (ipGenMode === 'v6' && isIPv4(node.server)) {
        skippedIpVersion++;
        continue;
      }
      const built = buildCleanXrayUri(node, uriOpts);
      if (built) links.push(built);
    }
  }

  const modeLabels = {
    v4: 'IPv4 only',
    v6: 'IPv6 only',
    both: 'IPv4 + IPv6 (2x per server)',
    mixed: 'IPv4/IPv6 (Random)',
  };

  return {
    links,
    detectedFormat: Array.from(detectedFormats).join(', ') || 'unknown',
    ipMode: ipPreset
      ? `${ipPreset.name} (${modeLabels[ipGenMode]})`
      : `Original Server IP (${modeLabels[ipGenMode]})`,
    totalFound: allNodes.length,
    convertedCount: links.length,
    skippedNonTls,
    skippedTransport,
    skippedIpVersion,
    skippedUnsupported,
    upstreamHeaders,
  };
}

function normalizeTransportName(raw) {
  const t = String(raw || 'tcp').toLowerCase().trim();
  if (t === 'websocket') return 'ws';
  if (t === 'splithttp') return 'xhttp';
  if (t === 'raw') return 'tcp';
  return t;
}

function parseSubscriptionPayload(rawText) {
  const nodes = [];
  let skippedUnsupported = 0;
  let wasBase64 = false;

  let text = String(rawText || '').replace(/^\uFEFF/, '').trim();

  for (let pass = 0; pass < 2; pass++) {
    const looksLikeJson = text.startsWith('{') || text.startsWith('[');
    const looksLikeUriList = /^(vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic):\/\//im.test(text);
    if (looksLikeJson || looksLikeUriList) break;

    const decoded = tryBase64DecodeUtf8(text);
    if (!decoded) break;
    wasBase64 = true;
    text = decoded.replace(/^\uFEFF/, '').trim();
  }

  if (text.startsWith('{') || text.startsWith('[')) {
    try {
      const json = JSON.parse(text);
      const outbounds = Array.isArray(json)
        ? json
        : Array.isArray(json.outbounds)
          ? json.outbounds
          : [json];

      let isXrayJson = false;
      let isSingboxJson = false;

      for (const ob of outbounds) {
        if (!ob || typeof ob !== 'object') continue;

        if (ob.protocol) {
          isXrayJson = true;
          const proto = String(ob.protocol).toLowerCase();
          if (proto === 'vless' || proto === 'trojan' || proto === 'vmess') {
            nodes.push(...xrayOutboundToNodes(ob));
          } else if (!['freedom', 'blackhole', 'dns', 'loopback'].includes(proto)) {
            skippedUnsupported++;
          }
          continue;
        }

        if (ob.type) {
          isSingboxJson = true;
          const type = String(ob.type).toLowerCase();
          if (type === 'vless' || type === 'trojan' || type === 'vmess') {
            const node = singboxOutboundToNode(ob);
            if (node) nodes.push(node);
          } else if (!['direct', 'block', 'dns', 'selector', 'urltest'].includes(type)) {
            skippedUnsupported++;
          }
        }
      }

      const fmt = isXrayJson && isSingboxJson
        ? 'Sing-box & Xray JSON'
        : isXrayJson
          ? 'Xray JSON'
          : isSingboxJson
            ? 'Sing-box JSON'
            : 'JSON';

      return {
        format: wasBase64 ? `${fmt} (Base64)` : fmt,
        nodes,
        skippedUnsupported,
      };
    } catch {
      // fallthrough
    }
  }

  let foundUriLines = false;
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  for (const line of lines) {
    if (line.startsWith('#') || line.startsWith('//')) continue;
    const lower = line.toLowerCase();
    if (lower.startsWith('vless://') || lower.startsWith('trojan://') || lower.startsWith('vmess://')) {
      foundUriLines = true;
      const node = parseProxyUriToNode(line);
      if (node) nodes.push(node);
      else skippedUnsupported++;
    } else if (/^[a-z0-9+.-]+:\/\//i.test(line)) {
      foundUriLines = true;
      skippedUnsupported++;
    }
  }

  return {
    format: foundUriLines ? (wasBase64 ? 'V2Ray Base64' : 'V2Ray Raw URIs') : 'unknown',
    nodes,
    skippedUnsupported,
  };
}

function xrayOutboundToNodes(ob) {
  const results = [];
  const proto = String(ob.protocol || '').toLowerCase();
  const settings = ob.settings || {};
  const stream = ob.streamSettings || {};
  const tag = String(ob.tag || '');

  let security = String(stream.security || '').toLowerCase();
  if (!security && proto === 'trojan') security = 'tls';

  const tlsSettings = stream.tlsSettings || {};
  const sni = tlsSettings.serverName || '';
  const alpn = Array.isArray(tlsSettings.alpn)
    ? tlsSettings.alpn.join(',')
    : (typeof tlsSettings.alpn === 'string' ? tlsSettings.alpn : '');

  const netType = normalizeTransportName(stream.network || 'tcp');

  let host = '';
  let path = '';
  let serviceName = '';
  let mode = '';
  let authority = '';
  let headerType = '';

  if (netType === 'ws') {
    const ws = stream.wsSettings || {};
    host = extractHeaderHost(ws.headers) || ws.host || '';
    path = ws.path || '';
    headerType = 'none';
  } else if (netType === 'httpupgrade') {
    const hu = stream.httpupgradeSettings || {};
    host = hu.host || extractHeaderHost(hu.headers) || '';
    path = hu.path || '';
  } else if (netType === 'xhttp') {
    const xh = stream.xhttpSettings || stream.splithttpSettings || {};
    host = xh.host || extractHeaderHost(xh.headers) || '';
    path = xh.path || '';
    mode = xh.mode || '';
  } else if (netType === 'grpc') {
    const gr = stream.grpcSettings || {};
    serviceName = gr.serviceName || '';
    mode = gr.multiMode ? 'multi' : '';
    authority = gr.authority || '';
  } else if (netType === 'tcp') {
    const tc = stream.tcpSettings || stream.rawSettings || {};
    const hdr = tc.header || {};
    headerType = hdr.type || 'none';
    if (headerType === 'http' && hdr.request) {
      host = extractHeaderHost(hdr.request.headers);
      path = Array.isArray(hdr.request.path) ? hdr.request.path.join(',') : (hdr.request.path || '');
    }
  }

  if (proto === 'trojan' && Array.isArray(settings.servers)) {
    for (const srv of settings.servers) {
      if (!srv.address || !srv.port || !srv.password) continue;
      results.push({
        proto,
        credential: String(srv.password),
        server: String(srv.address).trim(),
        port: Number(srv.port),
        tag: tag || `${srv.address}:${srv.port}`,
        security,
        netType,
        host,
        path,
        serviceName,
        mode,
        authority,
        sni,
        alpn,
        headerType,
        flow: '',
      });
    }
  } else if ((proto === 'vless' || proto === 'vmess') && Array.isArray(settings.vnext)) {
    for (const vnext of settings.vnext) {
      if (!vnext.address || !vnext.port || !Array.isArray(vnext.users)) continue;
      for (const user of vnext.users) {
        if (!user.id) continue;
        results.push({
          proto,
          credential: String(user.id),
          server: String(vnext.address).trim(),
          port: Number(vnext.port),
          tag: tag || `${vnext.address}:${vnext.port}`,
          security,
          netType,
          host,
          path,
          serviceName,
          mode,
          authority,
          sni,
          alpn,
          headerType,
          flow: proto === 'vless' ? (user.flow || '') : '',
        });
      }
    }
  }

  return results;
}

function singboxOutboundToNode(ob) {
  const proto = String(ob.type).toLowerCase();
  const server = String(ob.server || '').trim();
  const port = Number(ob.server_port);
  if (!server || !port) return null;

  const credential = proto === 'trojan' ? ob.password : ob.uuid;
  if (!credential) return null;

  const tls = ob.tls || {};
  let security = '';
  if (tls.enabled === true) {
    security = (tls.reality && tls.reality.enabled === true) ? 'reality' : 'tls';
  }

  const sni = tls.server_name || '';
  const alpn = Array.isArray(tls.alpn) ? tls.alpn.join(',') : (typeof tls.alpn === 'string' ? tls.alpn : '');

  const tr = ob.transport || {};
  const netType = normalizeTransportName(tr.type || 'tcp');

  let host = '';
  let path = '';
  let serviceName = '';
  let mode = '';
  let authority = '';
  let headerType = '';

  if (netType === 'ws') {
    host = extractHeaderHost(tr.headers) || (Array.isArray(tr.host) ? tr.host.join(',') : tr.host || '');
    path = tr.path || '';
    headerType = 'none';
  } else if (netType === 'httpupgrade') {
    host = (Array.isArray(tr.host) ? tr.host.join(',') : tr.host || '') || extractHeaderHost(tr.headers);
    path = tr.path || '';
  } else if (netType === 'xhttp') {
    host = (Array.isArray(tr.host) ? tr.host.join(',') : tr.host || '') || extractHeaderHost(tr.headers);
    path = tr.path || '';
    mode = tr.mode || '';
  } else if (netType === 'grpc') {
    serviceName = tr.service_name || '';
  } else if (netType === 'tcp') {
    headerType = 'none';
  }

  return {
    proto,
    credential: String(credential),
    server,
    port,
    tag: String(ob.tag || `${server}:${port}`),
    security,
    netType,
    host,
    path,
    serviceName,
    mode,
    authority,
    sni,
    alpn,
    headerType,
    flow: proto === 'vless' ? (ob.flow || '') : '',
  };
}

function extractHeaderHost(headers) {
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === 'host') {
      const val = headers[key];
      return Array.isArray(val) ? val.join(',') : String(val || '');
    }
  }
  return '';
}

function parseProxyUriToNode(uri) {
  try {
    if (uri.toLowerCase().startsWith('vmess://') && !uri.includes('@')) {
      const b64 = uri.slice(8).split('#')[0].trim();
      const decoded = tryBase64DecodeUtf8(b64);
      if (!decoded) return null;
      const obj = JSON.parse(decoded);
      const security = (obj.tls === 'tls' || obj.tls === true) ? 'tls' : '';
      const netType = normalizeTransportName(obj.net || 'tcp');

      return {
        proto: 'vmess',
        credential: String(obj.id || ''),
        server: String(obj.add || '').trim(),
        port: Number(obj.port),
        tag: String(obj.ps || `${obj.add}:${obj.port}`),
        security,
        netType,
        host: netType === 'grpc' ? '' : (obj.host || ''),
        path: netType === 'grpc' ? '' : (obj.path || ''),
        serviceName: netType === 'grpc' ? (obj.path || obj.serviceName || '') : '',
        mode: netType === 'grpc' ? (obj.type || '') : '',
        authority: '',
        sni: obj.sni || obj.host || '',
        alpn: obj.alpn || '',
        headerType: (netType === 'ws' || netType === 'tcp') ? (obj.type || 'none') : '',
        flow: '',
      };
    }

    const protoMatch = uri.match(/^(vless|trojan|vmess):\/\//i);
    if (!protoMatch) return null;
    const proto = protoMatch[1].toLowerCase();
    const httpLike = 'http://' + uri.slice(proto.length + 3);
    const parsed = new URL(httpLike);
    const q = parsed.searchParams;

    const credential = decodeURIComponent(parsed.username);
    const server = parsed.hostname.replace(/^\[|\]$/g, '');
    const port = Number(parsed.port);
    if (!credential || !server || !port) return null;

    let security = (q.get('security') || '').toLowerCase();
    if (!security && proto === 'trojan') security = 'tls';

    const netType = normalizeTransportName(q.get('type') || 'tcp');

    return {
      proto,
      credential,
      server,
      port,
      tag: parsed.hash ? decodeURIComponent(parsed.hash.slice(1)) : `${server}:${port}`,
      security,
      netType,
      host: q.get('host') || '',
      path: q.get('path') || '',
      serviceName: q.get('serviceName') || '',
      mode: q.get('mode') || '',
      authority: q.get('authority') || '',
      sni: q.get('sni') || '',
      alpn: q.get('alpn') || '',
      headerType: q.get('headerType') || ((netType === 'ws' || netType === 'tcp') ? 'none' : ''),
      flow: proto === 'vless' ? (q.get('flow') || '') : '',
    };
  } catch {
    return null;
  }
}

function buildCleanXrayUri(node, opts) {
  const hostFormatted = formatHost(node.server);
  const credEncoded = node.proto === 'trojan' ? encodeURIComponent(node.credential) : node.credential;

  const params = [];
  const addParam = (k, v) => {
    if (v !== undefined && v !== null && String(v) !== '') {
      params.push(`${k}=${encodeURIComponent(String(v))}`);
    }
  };

  addParam('security', 'tls');
  addParam('type', node.netType);
  if (node.proto === 'vless' && node.flow) addParam('flow', node.flow);

  if (node.netType === 'ws' || node.netType === 'httpupgrade') {
    addParam('host', node.host);
    addParam('path', node.path);
  } else if (node.netType === 'xhttp') {
    addParam('host', node.host);
    addParam('path', node.path);
    addParam('mode', node.mode);
  } else if (node.netType === 'grpc') {
    addParam('serviceName', node.serviceName);
    addParam('mode', node.mode);
    addParam('authority', node.authority);
  } else if (node.netType === 'tcp' && node.headerType === 'http') {
    addParam('host', node.host);
    addParam('path', node.path);
  }

  addParam('sni', node.sni);
  addParam('alpn', node.alpn);
  addParam('fp', opts.fp);

  if (opts.cs) addParam('cs', opts.cs);
  if (opts.fm) addParam('fm', opts.fm);

  if (node.netType === 'ws' || node.netType === 'tcp') {
    addParam('headerType', node.headerType || 'none');
  }

  const tagEncoded = encodeURIComponent(node.tag);
  return `${node.proto}://${credEncoded}@${hostFormatted}:${node.port}?${params.join('&')}#${tagEncoded}`;
}

/* ===========================
   Utility Helpers
   =========================== */

function isIPv4(str) {
  return /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(String(str || '').trim());
}

function isIPv6(str) {
  return String(str || '').includes(':');
}

function parseIpList(rawText) {
  const seen = new Set();
  const list = [];
  const lines = String(rawText || '').split(/\r?\n/);

  for (const line of lines) {
    const noComment = line.split('#')[0].trim();
    if (!noComment) continue;
    const tokens = noComment.split(/[\s,;]+/);
    for (let tok of tokens) {
      tok = tok.trim();
      if (!tok) continue;
      if (tok.startsWith('[') && tok.endsWith(']')) {
        tok = tok.slice(1, -1);
      }
      if (!tok || /\s/.test(tok)) continue;
      if (tok.includes('/') || tok.includes('?') || tok.includes('@')) continue;
      if (!seen.has(tok)) {
        seen.add(tok);
        list.push(tok);
      }
    }
  }
  return list;
}

function formatHost(host) {
  const h = String(host || '').trim();
  if (h.includes(':') && !h.startsWith('[')) return `[${h}]`;
  return h;
}

function base64EncodeUtf8(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

function tryBase64DecodeUtf8(b64) {
  try {
    const clean = String(b64 || '')
      .replace(/\s+/g, '')
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    if (!clean || !/^[A-Za-z0-9+/=]+$/.test(clean)) return null;
    const pad = clean.length % 4 === 0 ? clean : clean + '='.repeat(4 - (clean.length % 4));
    const bin = atob(pad);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return new TextDecoder('utf-8').decode(bytes);
  } catch {
    return null;
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

/* ===========================
   UI HTML Templates (English)
   =========================== */

const GITHUB_SVG = `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>`;

function renderKvSetupPage() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>KV Setup Required</title>
<style>body{background:#090d16;color:#e2e8f0;font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
.box{max-width:520px;background:#111827;border:1px solid #1f2937;border-radius:16px;padding:28px;line-height:1.7}
code{background:#1e293b;padding:2px 8px;border-radius:6px;color:#38bdf8}</style></head>
<body><div class="box">
<h2 style="margin-top:0;color:#f87171">KV Namespace Binding Missing</h2>
<p>To store subscriptions, presets, and panel credentials:</p>
<ol>
<li>Create a KV Namespace in your Cloudflare dashboard.</li>
<li>Go to <b>Settings &rarr; Bindings</b> on this Worker and bind it with variable name <code>SUB_KV</code>.</li>
<li>Refresh this page.</li>
</ol></div></body></html>`;
}

function renderLoginPage(adminRoute) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Admin Login - Sub Converter v${APP_VERSION}</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at 20% 20%, #1e1b4b, #090d16 65%);
      color: #f1f5f9; padding: 16px;
    }
    .card {
      width: 100%; max-width: 400px;
      background: rgba(17, 24, 39, 0.78); backdrop-filter: blur(16px);
      border: 1px solid rgba(148, 163, 184, 0.16); border-radius: 20px;
      padding: 32px 28px 24px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
    }
    .logo {
      width: 52px; height: 52px; border-radius: 14px; margin: 0 auto 16px;
      background: linear-gradient(135deg, #6366f1, #06b6d4);
      display: flex; align-items: center; justify-content: center; font-size: 24px;
    }
    h1 { text-align: center; font-size: 20px; margin: 0 0 8px; }
    p { text-align: center; font-size: 13px; color: #94a3b8; margin: 0 0 24px; }
    label { display: block; font-size: 13px; color: #cbd5e1; margin-bottom: 8px; }
    input {
      width: 100%; padding: 12px 14px; border-radius: 12px;
      border: 1px solid rgba(148, 163, 184, 0.22); background: rgba(15, 23, 42, 0.8);
      color: #fff; font-size: 14px; outline: none; font-family: inherit;
    }
    input:focus { border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2); }
    button {
      width: 100%; margin-top: 18px; padding: 12px; border: 0; border-radius: 12px;
      background: linear-gradient(135deg, #6366f1, #0ea5e9); color: #fff;
      font-size: 15px; font-weight: 600; cursor: pointer; font-family: inherit;
      transition: opacity 0.2s;
    }
    button:hover { opacity: 0.92; }
    .err { color: #f87171; font-size: 13px; margin-top: 12px; text-align: center; min-height: 20px; }
    .login-footer {
      margin-top: 14px; padding-top: 14px; border-top: 1px solid rgba(148, 163, 184, 0.14);
      display: flex; align-items: center; justify-content: space-between; font-size: 12px; color: #94a3b8;
    }
    .gh-link {
      display: inline-flex; align-items: center; gap: 6px; color: #cbd5e1; text-decoration: none;
      transition: color 0.2s;
    }
    .gh-link:hover { color: #fff; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">⚡</div>
    <h1>Subscription Converter</h1>
    <p>Enter your password to access the admin panel</p>
    <form id="loginForm">
      <label>Password</label>
      <input type="password" id="pw" placeholder="••••••••" required autofocus />
      <button type="submit">Sign In</button>
      <div class="err" id="err"></div>
    </form>
    <div class="login-footer">
      <span>v${APP_VERSION}</span>
      <a class="gh-link" href="${GITHUB_URL}" target="_blank" rel="noopener noreferrer">${GITHUB_SVG}<span>GitHub</span></a>
    </div>
  </div>
  <script>
    document.getElementById('loginForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      var err = document.getElementById('err');
      err.textContent = '';
      var pw = document.getElementById('pw').value;
      var res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pw })
      });
      var data = await res.json();
      if (res.ok) {
        location.href = ${JSON.stringify(adminRoute)};
      } else {
        err.textContent = data.error || 'Login failed';
      }
    });
  </script>
</body>
</html>`;
}

function renderDashboardPage(state, origin) {
  const initialJson = JSON.stringify({
    version: APP_VERSION,
    origin,
    adminPath: state.adminPath,
    csPresets: state.csPresets,
    fmPresets: state.fmPresets,
    ipPresets: state.ipPresets,
    subs: state.subs,
    fpOptions: FP_OPTIONS,
    transportOptions: TRANSPORT_OPTIONS,
  });

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Xray Subscription Converter Panel v${APP_VERSION}</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #080c17; --card: rgba(17, 24, 39, 0.78); --border: rgba(148, 163, 184, 0.16);
      --text: #f1f5f9; --muted: #94a3b8; --primary: #6366f1; --cyan: #06b6d4;
      --danger: #ef4444; --success: #10b981;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: 'Inter', system-ui, -apple-system, sans-serif; color: var(--text);
      background: radial-gradient(circle at top right, #1e1b4b 0%, var(--bg) 55%);
      min-height: 100vh; padding-bottom: 60px;
    }
    .container { max-width: 1080px; margin: 0 auto; padding: 24px 16px; }
    header {
      display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
      gap: 14px; margin-bottom: 24px; padding-bottom: 18px; border-bottom: 1px solid var(--border);
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-icon {
      width: 44px; height: 44px; border-radius: 12px;
      background: linear-gradient(135deg, var(--primary), var(--cyan));
      display: flex; align-items: center; justify-content: center; font-size: 20px;
    }
    .brand h1 { margin: 0; font-size: 18px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .ver-badge {
      font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 999px;
      background: rgba(99, 102, 241, 0.2); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.35);
    }
    .brand small { color: var(--muted); font-size: 12px; }
    .header-actions { display: flex; align-items: center; gap: 8px; }
    .gh-btn { text-decoration: none; }
    .tabs { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
    .tab-btn {
      background: rgba(15, 23, 42, 0.7); border: 1px solid var(--border); color: var(--muted);
      padding: 10px 16px; border-radius: 12px; cursor: pointer; font-family: inherit;
      font-size: 13px; font-weight: 600; transition: all 0.2s;
    }
    .tab-btn.active {
      background: linear-gradient(135deg, var(--primary), var(--cyan));
      color: #fff; border-color: transparent;
    }
    .card {
      background: var(--card); backdrop-filter: blur(16px); border: 1px solid var(--border);
      border-radius: 18px; padding: 22px; margin-bottom: 20px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
    }
    .card h2 { margin: 0 0 16px; font-size: 16px; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: space-between; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }
    label { display: block; font-size: 12px; color: #cbd5e1; margin-bottom: 6px; font-weight: 500; }
    input, select, textarea {
      width: 100%; padding: 10px 12px; border-radius: 10px;
      border: 1px solid rgba(148, 163, 184, 0.22); background: rgba(15, 23, 42, 0.85);
      color: #fff; font-size: 13px; font-family: inherit; outline: none;
    }
    textarea { min-height: 92px; resize: vertical; line-height: 1.5; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    input:focus, select:focus, textarea:focus { border-color: var(--primary); }
    .btn {
      padding: 9px 16px; border-radius: 10px; border: 0; cursor: pointer;
      font-family: inherit; font-size: 13px; font-weight: 600; transition: 0.2s;
      display: inline-flex; align-items: center; gap: 6px;
    }
    .btn-primary { background: linear-gradient(135deg, var(--primary), var(--cyan)); color: #fff; }
    .btn-secondary { background: rgba(148, 163, 184, 0.15); color: #e2e8f0; }
    .btn-danger { background: rgba(239, 68, 68, 0.16); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
    .btn-sm { padding: 6px 11px; font-size: 12px; border-radius: 8px; }
    .btn:hover { opacity: 0.9; transform: translateY(-1px); }
    .item-list { display: flex; flex-direction: column; gap: 12px; }
    .item {
      background: rgba(15, 23, 42, 0.65); border: 1px solid var(--border);
      border-radius: 14px; padding: 14px 16px;
      display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px;
    }
    .item-meta { flex: 1; min-width: 240px; }
    .item-title { font-weight: 600; font-size: 14px; margin-bottom: 4px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .badge {
      font-size: 11px; padding: 2px 8px; border-radius: 999px; font-weight: 500;
      background: rgba(99, 102, 241, 0.18); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.3);
    }
    .badge-cyan { background: rgba(6, 182, 212, 0.16); color: #67e8f9; border-color: rgba(6, 182, 212, 0.3); }
    .badge-green { background: rgba(16, 185, 129, 0.16); color: #6ee7b7; border-color: rgba(16, 185, 129, 0.3); }
    .badge-amber { background: rgba(245, 158, 11, 0.16); color: #fcd34d; border-color: rgba(245, 158, 11, 0.3); }
    .sub-link-box {
      margin-top: 8px; padding: 7px 10px; border-radius: 8px; background: rgba(2, 6, 23, 0.6);
      border: 1px dashed rgba(148, 163, 184, 0.25); font-size: 12px; color: #38bdf8;
      word-break: break-all; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      max-height: 90px; overflow: auto;
    }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .switch-row { display: flex; align-items: center; gap: 8px; margin-top: 14px; }
    .switch-row input { width: auto; accent-color: var(--primary); cursor: pointer; }
    .check-group {
      display: flex; flex-wrap: wrap; align-items: center; gap: 12px; padding: 8px 12px;
      border-radius: 10px; border: 1px solid rgba(148, 163, 184, 0.22);
      background: rgba(15, 23, 42, 0.85); min-height: 40px;
    }
    .check-item { display: flex; align-items: center; gap: 5px; margin: 0; cursor: pointer; font-size: 12px; color: #f1f5f9; white-space: nowrap; }
    .check-item input { width: auto; margin: 0; accent-color: var(--primary); cursor: pointer; }
    .divider-v { width: 1px; height: 16px; background: rgba(148, 163, 184, 0.25); }
    .hidden { display: none !important; }
    .toast {
      position: fixed; bottom: 20px; right: 20px; padding: 12px 18px; border-radius: 12px;
      background: #10b981; color: #fff; font-size: 13px; font-weight: 600;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4); z-index: 999; opacity: 0; transition: 0.25s; pointer-events: none;
    }
    .toast.show { opacity: 1; }
    .toast.error { background: #ef4444; }
    .modal-bg {
      position: fixed; inset: 0; background: rgba(0, 0, 0, 0.72); backdrop-filter: blur(4px);
      display: flex; align-items: center; justify-content: center; padding: 16px; z-index: 998;
    }
    .modal {
      width: 100%; max-width: 760px; max-height: 85vh; overflow: auto;
      background: #0f172a; border: 1px solid var(--border); border-radius: 18px; padding: 22px;
    }
    .hint { font-size: 12px; color: var(--muted); margin-top: 8px; line-height: 1.6; }
    code { background: rgba(30, 41, 59, 0.9); padding: 1px 6px; border-radius: 5px; color: #38bdf8; }
  </style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <div class="brand-icon">⚡</div>
      <div>
        <h1>Xray Subscription Converter <span class="ver-badge">v${APP_VERSION}</span></h1>
        <small>Auto-detects Sing-box, Xray JSON &amp; V2Ray (Base64 / Raw) &rarr; TLS (WS / HTTPUpgrade / XHTTP / gRPC / TCP) with cs, fm, fp</small>
      </div>
    </div>
    <div class="header-actions">
      <a href="${GITHUB_URL}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm gh-btn" title="GitHub Repository">
        ${GITHUB_SVG}
        <span>GitHub</span>
      </a>
      <button type="button" id="logoutBtn" class="btn btn-secondary btn-sm">Logout</button>
    </div>
  </header>

  <div class="tabs">
    <button type="button" class="tab-btn active" data-tab="subs">🔗 Subscriptions</button>
    <button type="button" class="tab-btn" data-tab="ips">🌐 Clean IPs</button>
    <button type="button" class="tab-btn" data-tab="cs">🔐 Cipher Suites (cs)</button>
    <button type="button" class="tab-btn" data-tab="fm">🧩 Final Mask (fm)</button>
    <button type="button" class="tab-btn" data-tab="settings">⚙️ Panel Settings</button>
  </div>

  <!-- TAB: SUBSCRIPTIONS -->
  <div id="tab-subs">
    <div class="card">
      <h2 id="subFormTitle">Add New Subscription</h2>
      <form id="subForm">
        <input type="hidden" id="subEditingId" />
        <div class="grid">
          <div>
            <label>Subscription Name</label>
            <input type="text" id="subName" placeholder="e.g. Main Xray Sub" required />
          </div>
          <div>
            <label>Custom Output Slug (optional)</label>
            <input type="text" id="subSlug" class="mono" placeholder="Leave blank for auto ID" />
          </div>
          <div>
            <label>TLS Fingerprint (fp)</label>
            <select id="subFp" class="mono"></select>
          </div>
        </div>
        <div style="margin-top:14px">
          <label>Input Subscription URL(s) or Raw Configs (Sing-box, Xray JSON, V2Ray Base64 / Raw URIs)</label>
          <textarea id="subInputUrl" class="mono" placeholder="https://example.com/sub/... (or paste raw/base64 configs directly)" required></textarea>
        </div>
        <div class="grid" style="margin-top:14px">
          <div>
            <label>Cipher Suite (cs)</label>
            <select id="subCs"></select>
          </div>
          <div>
            <label>Final Mask (fm)</label>
            <select id="subFm"></select>
          </div>
          <div>
            <label>Server IP Mode (Clean IP List)</label>
            <select id="subIpList"></select>
          </div>
        </div>
        <div class="grid-2" style="margin-top:14px">
          <div>
            <label>Allowed Transports (TLS required)</label>
            <div class="check-group" id="subTransportsGroup"></div>
          </div>
          <div>
            <label>Output IP Version</label>
            <div class="check-group">
              <label class="check-item"><input type="checkbox" id="subChkV4" /> IPv4</label>
              <label class="check-item"><input type="checkbox" id="subChkV6" /> IPv6</label>
              <span class="divider-v"></span>
              <label class="check-item"><input type="checkbox" id="subChkMixed" checked /> IPv4/IPv6</label>
            </div>
          </div>
        </div>
        <div class="switch-row">
          <input type="checkbox" id="subBase64" />
          <label for="subBase64" style="margin:0;cursor:pointer">Encode output as Base64</label>
        </div>
        <div class="hint">⚠️ Only <code>security=tls</code> configs matching your selected transports are converted. Check <b>IPv4</b> only, <b>IPv6</b> only, <b>both IPv4 &amp; IPv6</b> (2x per server), or <b>IPv4/IPv6</b> (1 random IP from combined list).</div>
        <div style="margin-top:16px;display:flex;gap:10px">
          <button type="submit" class="btn btn-primary">Save Subscription</button>
          <button type="button" id="cancelSubEdit" class="btn btn-secondary hidden">Cancel Edit</button>
        </div>
      </form>
    </div>

    <div class="card">
      <h2>Saved Subscriptions</h2>
      <div id="subsList" class="item-list"></div>
    </div>
  </div>

  <!-- TAB: CLEAN IPS -->
  <div id="tab-ips" class="hidden">
    <div class="card">
      <h2 id="ipFormTitle">Add / Edit Clean IP List (IPv4 &amp; IPv6)</h2>
      <form id="ipForm">
        <input type="hidden" id="ipEditId" />
        <div style="margin-bottom:12px">
          <label>IP List Name</label>
          <input type="text" id="ipName" placeholder="e.g. Cloudflare Mixed IPv4 + IPv6" required />
        </div>
        <div>
          <label>IP Addresses (IPv4 and/or IPv6 — one per line or comma-separated)</label>
          <textarea id="ipValue" class="mono" style="min-height:140px" placeholder="188.114.98.0&#10;162.159.192.1&#10;2606:4700:9c60:d584:4436:752f:7cf4:5757&#10;[2606:4700::6810:85e5]" required></textarea>
          <div class="hint">You can mix IPv4 and IPv6 addresses. Brackets <code>[...]</code> around IPv6 are handled automatically. Lines starting with <code>#</code> are treated as comments.</div>
        </div>
        <div style="margin-top:14px;display:flex;gap:10px">
          <button type="submit" class="btn btn-primary">Save IP List</button>
          <button type="button" id="cancelIpEdit" class="btn btn-secondary hidden">Cancel</button>
        </div>
      </form>
    </div>
    <div class="card">
      <h2>Saved IP Lists</h2>
      <div id="ipsList" class="item-list"></div>
    </div>
  </div>

  <!-- TAB: CIPHER SUITES -->
  <div id="tab-cs" class="hidden">
    <div class="card">
      <h2 id="csFormTitle">Add / Edit Cipher Suite (cs)</h2>
      <form id="csForm">
        <input type="hidden" id="csEditId" />
        <div style="margin-bottom:12px">
          <label>Preset Name</label>
          <input type="text" id="csName" placeholder="e.g. Standard TLS 1.3 + ECDHE" required />
        </div>
        <div>
          <label>Cipher Suites Value (colon-separated)</label>
          <textarea id="csValue" class="mono" placeholder="TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256..." required></textarea>
        </div>
        <div style="margin-top:14px;display:flex;gap:10px">
          <button type="submit" class="btn btn-primary">Save Cipher Suite</button>
          <button type="button" id="cancelCsEdit" class="btn btn-secondary hidden">Cancel</button>
        </div>
      </form>
    </div>
    <div class="card">
      <h2>Saved Cipher Suites</h2>
      <div id="csList" class="item-list"></div>
    </div>
  </div>

  <!-- TAB: FINAL MASK -->
  <div id="tab-fm" class="hidden">
    <div class="card">
      <h2>
        <span id="fmFormTitle">Add / Edit Final Mask (fm)</span>
        <span style="display:flex;gap:8px">
          <button type="button" id="loadFmV1Btn" class="btn btn-secondary btn-sm">Load v1</button>
          <button type="button" id="loadFmV2Btn" class="btn btn-secondary btn-sm">Load v2</button>
        </span>
      </h2>
      <form id="fmForm">
        <input type="hidden" id="fmEditId" />
        <div style="margin-bottom:12px">
          <label>Preset Name</label>
          <input type="text" id="fmName" placeholder="e.g. Fragment v1" required />
        </div>
        <div>
          <label>Final Mask JSON</label>
          <textarea id="fmValue" class="mono" placeholder='{"tcp": [{"type": "fragment", "settings": {...}}]}' required></textarea>
        </div>
        <div style="margin-top:14px;display:flex;gap:10px">
          <button type="submit" class="btn btn-primary">Save Final Mask</button>
          <button type="button" id="cancelFmEdit" class="btn btn-secondary hidden">Cancel</button>
        </div>
      </form>
    </div>
    <div class="card">
      <h2>Saved Final Masks</h2>
      <div id="fmList" class="item-list"></div>
    </div>
  </div>

  <!-- TAB: SETTINGS -->
  <div id="tab-settings" class="hidden">
    <div class="card">
      <h2>Admin Panel Settings</h2>
      <form id="settingsForm">
        <div class="grid">
          <div>
            <label>Admin Panel Path (without leading slash)</label>
            <input type="text" id="setAdminPath" class="mono" required />
            <div class="hint">Example: <code>my-panel</code> &rarr; accessible at <code>/my-panel</code></div>
          </div>
          <div>
            <label>New Password (leave empty to keep current)</label>
            <input type="password" id="setNewPass" class="mono" placeholder="Minimum 4 characters" />
          </div>
        </div>
        <div style="margin-top:16px">
          <button type="submit" class="btn btn-primary">Save Settings</button>
        </div>
      </form>
    </div>
  </div>
</div>

<div id="previewModal" class="modal-bg hidden">
  <div class="modal">
    <h2 style="margin-top:0;display:flex;justify-content:space-between;align-items:center">
      <span>Subscription Output Preview</span>
      <button type="button" id="closePreviewBtn" class="btn btn-secondary btn-sm">Close</button>
    </h2>
    <div id="previewStats" class="hint" style="margin-bottom:10px"></div>
    <textarea id="previewText" class="mono" style="min-height:280px" readonly></textarea>
    <div style="margin-top:12px">
      <button type="button" id="copyPreviewBtn" class="btn btn-primary btn-sm">Copy All Configs</button>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
  var state = ${initialJson};

  function showToast(msg, isError) {
    var t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'toast show' + (isError ? ' error' : '');
    clearTimeout(window.__toastTimer);
    window.__toastTimer = setTimeout(function() { t.className = 'toast'; }, 2800);
  }

  function escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function copyText(txt) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(txt).then(function() {
        showToast('Copied to clipboard');
      }).catch(function() {
        fallbackCopy(txt);
      });
    } else {
      fallbackCopy(txt);
    }
  }

  function fallbackCopy(txt) {
    try {
      var ta = document.createElement('textarea');
      ta.value = txt;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      showToast(ok ? 'Copied to clipboard' : 'Copy failed', !ok);
    } catch (e) {
      showToast('Copy failed', true);
    }
  }

  // Mutual exclusion for Output IP Version checkboxes
  var chkV4 = document.getElementById('subChkV4');
  var chkV6 = document.getElementById('subChkV6');
  var chkMixed = document.getElementById('subChkMixed');

  chkV4.addEventListener('change', function() {
    if (chkV4.checked) chkMixed.checked = false;
  });
  chkV6.addEventListener('change', function() {
    if (chkV6.checked) chkMixed.checked = false;
  });
  chkMixed.addEventListener('change', function() {
    if (chkMixed.checked) {
      chkV4.checked = false;
      chkV6.checked = false;
    }
  });

  function getIpGenModeFromCheckboxes() {
    if (chkMixed.checked) return 'mixed';
    if (chkV4.checked && chkV6.checked) return 'both';
    if (chkV4.checked) return 'v4';
    if (chkV6.checked) return 'v6';
    return '';
  }

  function setIpGenModeCheckboxes(mode) {
    chkV4.checked = (mode === 'v4' || mode === 'both');
    chkV6.checked = (mode === 'v6' || mode === 'both');
    chkMixed.checked = (mode === 'mixed' || !mode);
  }

  function resolveClientIpGenMode(s) {
    if (s.ipGenMode === 'v4' || s.ipGenMode === 'v6' || s.ipGenMode === 'both' || s.ipGenMode === 'mixed') {
      return s.ipGenMode;
    }
    if (s.useV4 === true && s.useV6 === false) return 'v4';
    if (s.useV4 === false && s.useV6 === true) return 'v6';
    return 'mixed';
  }

  function getSelectedTransports() {
    var arr = [];
    document.querySelectorAll('#subTransportsGroup input[type="checkbox"]:checked').forEach(function(cb) {
      arr.push(cb.value);
    });
    return arr;
  }

  function setSelectedTransports(list) {
    var active = Array.isArray(list) && list.length
      ? list
      : state.transportOptions.map(function(t) { return t.id; });
    document.querySelectorAll('#subTransportsGroup input[type="checkbox"]').forEach(function(cb) {
      cb.checked = active.indexOf(cb.value) !== -1;
    });
  }

  // Tabs
  document.querySelectorAll('.tab-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var name = btn.getAttribute('data-tab');
      ['subs', 'ips', 'cs', 'fm', 'settings'].forEach(function(id) {
        document.getElementById('tab-' + id).classList.toggle('hidden', id !== name);
      });
      document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
    });
  });

  function renderSelects() {
    var fpSel = document.getElementById('subFp');
    fpSel.innerHTML = state.fpOptions.map(function(f) {
      return '<option value="' + escapeHtml(f) + '">' + escapeHtml(f) + '</option>';
    }).join('');

    var csSel = document.getElementById('subCs');
    csSel.innerHTML = '<option value="">-- None --</option>' +
      state.csPresets.map(function(c) {
        return '<option value="' + escapeHtml(c.id) + '">' + escapeHtml(c.name) + '</option>';
      }).join('');

    var fmSel = document.getElementById('subFm');
    fmSel.innerHTML = '<option value="">-- None --</option>' +
      state.fmPresets.map(function(f) {
        return '<option value="' + escapeHtml(f.id) + '">' + escapeHtml(f.name) + '</option>';
      }).join('');

    var ipSel = document.getElementById('subIpList');
    ipSel.innerHTML = '<option value="">-- Use Original Server IP --</option>' +
      state.ipPresets.map(function(p) {
        return '<option value="' + escapeHtml(p.id) + '">' + escapeHtml(p.name) + ' (' + p.ips.length + ' IPs)</option>';
      }).join('');

    var trGroup = document.getElementById('subTransportsGroup');
    if (!trGroup.children.length) {
      trGroup.innerHTML = state.transportOptions.map(function(t) {
        return '<label class="check-item"><input type="checkbox" value="' + escapeHtml(t.id) + '" checked /> ' + escapeHtml(t.label) + '</label>';
      }).join('');
    }

    document.getElementById('setAdminPath').value = state.adminPath;
  }

  function renderSubs() {
    var el = document.getElementById('subsList');
    if (!state.subs.length) {
      el.innerHTML = '<div class="hint">No subscriptions added yet.</div>';
      return;
    }
    var modeBadges = {
      v4: 'IPv4 only',
      v6: 'IPv6 only',
      both: 'IPv4 + IPv6 (2x)',
      mixed: 'IPv4/IPv6 (Random)'
    };
    el.innerHTML = state.subs.map(function(s) {
      var outUrl = state.origin + '/sub/' + encodeURIComponent(s.id);
      var csObj = state.csPresets.find(function(x) { return x.id === s.csId; });
      var fmObj = state.fmPresets.find(function(x) { return x.id === s.fmId; });
      var ipObj = state.ipPresets.find(function(x) { return x.id === s.ipListId; });
      var mode = resolveClientIpGenMode(s);
      var verText = modeBadges[mode] || 'IPv4/IPv6 (Random)';
      var trList = Array.isArray(s.transports) && s.transports.length
        ? s.transports
        : state.transportOptions.map(function(t) { return t.id; });
      var trText = trList.length === state.transportOptions.length
        ? 'All Transports'
        : trList.map(function(id) {
            var found = state.transportOptions.find(function(t) { return t.id === id; });
            return found ? found.label : id;
          }).join(', ');
      var sid = escapeHtml(s.id);
      return '<div class="item">' +
        '<div class="item-meta">' +
          '<div class="item-title">' + escapeHtml(s.name) +
            '<span class="badge">fp: ' + escapeHtml(s.fp || 'unsafe') + '</span>' +
            '<span class="badge badge-amber">' + escapeHtml(trText) + '</span>' +
            (csObj ? '<span class="badge badge-cyan">cs: ' + escapeHtml(csObj.name) + '</span>' : '') +
            (fmObj ? '<span class="badge badge-cyan">fm: ' + escapeHtml(fmObj.name) + '</span>' : '') +
            (ipObj
              ? '<span class="badge badge-green">IP: ' + escapeHtml(ipObj.name) + ' · ' + verText + '</span>'
              : '<span class="badge">IP: Original · ' + verText + '</span>') +
            (s.base64 ? '<span class="badge">Base64</span>' : '') +
          '</div>' +
          '<div class="sub-link-box">' + escapeHtml(outUrl) + '</div>' +
        '</div>' +
        '<div class="actions">' +
          '<button type="button" class="btn btn-primary btn-sm" data-action="copy" data-id="' + sid + '">Copy Link</button>' +
          '<button type="button" class="btn btn-secondary btn-sm" data-action="preview" data-id="' + sid + '">Preview</button>' +
          '<button type="button" class="btn btn-secondary btn-sm" data-action="edit" data-id="' + sid + '">Edit</button>' +
          '<button type="button" class="btn btn-danger btn-sm" data-action="delete" data-id="' + sid + '">Delete</button>' +
        '</div>' +
      '</div>';
    }).join('');
  }

  function renderIps() {
    var el = document.getElementById('ipsList');
    if (!state.ipPresets.length) {
      el.innerHTML = '<div class="hint">No IP lists saved yet. Add your clean IPv4/IPv6 addresses above.</div>';
      return;
    }
    el.innerHTML = state.ipPresets.map(function(p) {
      var pid = escapeHtml(p.id);
      var v6Count = p.ips.filter(function(ip) { return ip.indexOf(':') !== -1; }).length;
      var v4Count = p.ips.length - v6Count;
      return '<div class="item">' +
        '<div class="item-meta">' +
          '<div class="item-title">' + escapeHtml(p.name) +
            '<span class="badge badge-green">' + p.ips.length + ' Total</span>' +
            '<span class="badge">' + v4Count + ' IPv4</span>' +
            '<span class="badge badge-cyan">' + v6Count + ' IPv6</span>' +
          '</div>' +
          '<div class="sub-link-box">' + escapeHtml(p.ips.join(', ')) + '</div>' +
        '</div>' +
        '<div class="actions">' +
          '<button type="button" class="btn btn-secondary btn-sm" data-action="edit" data-id="' + pid + '">Edit</button>' +
          '<button type="button" class="btn btn-danger btn-sm" data-action="delete" data-id="' + pid + '">Delete</button>' +
        '</div>' +
      '</div>';
    }).join('');
  }

  function renderCs() {
    var el = document.getElementById('csList');
    if (!state.csPresets.length) {
      el.innerHTML = '<div class="hint">No Cipher Suites saved.</div>';
      return;
    }
    el.innerHTML = state.csPresets.map(function(c) {
      var cid = escapeHtml(c.id);
      return '<div class="item">' +
        '<div class="item-meta">' +
          '<div class="item-title">' + escapeHtml(c.name) + '</div>' +
          '<div class="sub-link-box">' + escapeHtml(c.value) + '</div>' +
        '</div>' +
        '<div class="actions">' +
          '<button type="button" class="btn btn-secondary btn-sm" data-action="edit" data-id="' + cid + '">Edit</button>' +
          '<button type="button" class="btn btn-danger btn-sm" data-action="delete" data-id="' + cid + '">Delete</button>' +
        '</div>' +
      '</div>';
    }).join('');
  }

  function renderFm() {
    var el = document.getElementById('fmList');
    if (!state.fmPresets.length) {
      el.innerHTML = '<div class="hint">No Final Masks saved.</div>';
      return;
    }
    el.innerHTML = state.fmPresets.map(function(f) {
      var fid = escapeHtml(f.id);
      return '<div class="item">' +
        '<div class="item-meta">' +
          '<div class="item-title">' + escapeHtml(f.name) + '</div>' +
          '<div class="sub-link-box">' + escapeHtml(f.value) + '</div>' +
        '</div>' +
        '<div class="actions">' +
          '<button type="button" class="btn btn-secondary btn-sm" data-action="edit" data-id="' + fid + '">Edit</button>' +
          '<button type="button" class="btn btn-danger btn-sm" data-action="delete" data-id="' + fid + '">Delete</button>' +
        '</div>' +
      '</div>';
    }).join('');
  }

  function renderAll() {
    renderSelects();
    renderSubs();
    renderIps();
    renderCs();
    renderFm();
  }

  async function apiCall(path, method, body) {
    var res = await fetch(path, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined
    });
    if (res.status === 401) { location.reload(); return null; }
    var data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'Operation failed', true);
      return null;
    }
    return data;
  }

  // Event delegations
  document.getElementById('subsList').addEventListener('click', function(e) {
    var btn = e.target.closest('button[data-action]');
    if (!btn) return;
    var action = btn.getAttribute('data-action');
    var id = btn.getAttribute('data-id');
    if (action === 'copy') copyText(state.origin + '/sub/' + encodeURIComponent(id));
    else if (action === 'preview') previewSub(id);
    else if (action === 'edit') editSub(id);
    else if (action === 'delete') deleteSub(id);
  });

  document.getElementById('ipsList').addEventListener('click', function(e) {
    var btn = e.target.closest('button[data-action]');
    if (!btn) return;
    var action = btn.getAttribute('data-action');
    var id = btn.getAttribute('data-id');
    if (action === 'edit') editIp(id);
    else if (action === 'delete') deleteIp(id);
  });

  document.getElementById('csList').addEventListener('click', function(e) {
    var btn = e.target.closest('button[data-action]');
    if (!btn) return;
    var action = btn.getAttribute('data-action');
    var id = btn.getAttribute('data-id');
    if (action === 'edit') editCs(id);
    else if (action === 'delete') deleteCs(id);
  });

  document.getElementById('fmList').addEventListener('click', function(e) {
    var btn = e.target.closest('button[data-action]');
    if (!btn) return;
    var action = btn.getAttribute('data-action');
    var id = btn.getAttribute('data-id');
    if (action === 'edit') editFm(id);
    else if (action === 'delete') deleteFm(id);
  });

  // Sub Form
  document.getElementById('subForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    var transports = getSelectedTransports();
    if (!transports.length) {
      showToast('Please select at least one Transport type', true);
      return;
    }
    var ipGenMode = getIpGenModeFromCheckboxes();
    if (!ipGenMode) {
      showToast('Please select an Output IP Version option', true);
      return;
    }
    var payload = {
      editingId: document.getElementById('subEditingId').value,
      name: document.getElementById('subName').value,
      id: document.getElementById('subSlug').value,
      inputUrl: document.getElementById('subInputUrl').value,
      csId: document.getElementById('subCs').value,
      fmId: document.getElementById('subFm').value,
      ipListId: document.getElementById('subIpList').value,
      ipGenMode: ipGenMode,
      transports: transports,
      fp: document.getElementById('subFp').value,
      base64: document.getElementById('subBase64').checked
    };
    var data = await apiCall('/api/subs', 'POST', payload);
    if (data) {
      state.subs = data.subs;
      resetSubForm();
      renderAll();
      showToast('Subscription saved');
    }
  });

  document.getElementById('cancelSubEdit').addEventListener('click', resetSubForm);

  function editSub(id) {
    var s = state.subs.find(function(x) { return x.id === id; });
    if (!s) return;
    document.getElementById('subEditingId').value = s.id;
    document.getElementById('subName').value = s.name;
    document.getElementById('subSlug').value = s.id;
    document.getElementById('subInputUrl').value = s.inputUrl;
    document.getElementById('subCs').value = s.csId || '';
    document.getElementById('subFm').value = s.fmId || '';
    document.getElementById('subIpList').value = s.ipListId || '';
    setSelectedTransports(s.transports);
    setIpGenModeCheckboxes(resolveClientIpGenMode(s));
    document.getElementById('subFp').value = s.fp || 'unsafe';
    document.getElementById('subBase64').checked = Boolean(s.base64);
    document.getElementById('subFormTitle').textContent = 'Edit Subscription: ' + s.name;
    document.getElementById('cancelSubEdit').classList.remove('hidden');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function resetSubForm() {
    document.getElementById('subForm').reset();
    document.getElementById('subEditingId').value = '';
    setSelectedTransports(null);
    setIpGenModeCheckboxes('mixed');
    document.getElementById('subFormTitle').textContent = 'Add New Subscription';
    document.getElementById('cancelSubEdit').classList.add('hidden');
  }

  async function deleteSub(id) {
    if (!confirm('Delete this subscription?')) return;
    var data = await apiCall('/api/subs', 'DELETE', { id: id });
    if (data) {
      state.subs = data.subs;
      renderAll();
      showToast('Subscription deleted');
    }
  }

  async function previewSub(id) {
    showToast('Fetching & converting...');
    var data = await apiCall('/api/preview', 'POST', { id: id });
    if (!data) return;
    document.getElementById('previewStats').textContent =
      'Format: ' + data.detectedFormat +
      ' | IP Mode: ' + data.ipMode +
      ' | Input Nodes: ' + data.totalFound +
      ' | Generated Output: ' + data.convertedCount +
      ' | Skipped (non-TLS): ' + data.skippedNonTls +
      ' | Skipped (transport): ' + data.skippedTransport +
      (data.skippedIpVersion ? ' | Skipped (IP v4/v6): ' + data.skippedIpVersion : '');
    document.getElementById('previewText').value = data.links.join('\\n');
    document.getElementById('previewModal').classList.remove('hidden');
  }

  document.getElementById('closePreviewBtn').addEventListener('click', function() {
    document.getElementById('previewModal').classList.add('hidden');
  });
  document.getElementById('previewModal').addEventListener('click', function(e) {
    if (e.target === this) this.classList.add('hidden');
  });
  document.getElementById('copyPreviewBtn').addEventListener('click', function() {
    copyText(document.getElementById('previewText').value);
  });

  // IP List Form
  document.getElementById('ipForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    var data = await apiCall('/api/ips', 'POST', {
      id: document.getElementById('ipEditId').value,
      name: document.getElementById('ipName').value,
      value: document.getElementById('ipValue').value
    });
    if (data) {
      state.ipPresets = data.ipPresets;
      resetIpForm();
      renderAll();
      showToast('IP list saved');
    }
  });

  document.getElementById('cancelIpEdit').addEventListener('click', resetIpForm);

  function editIp(id) {
    var p = state.ipPresets.find(function(x) { return x.id === id; });
    if (!p) return;
    document.getElementById('ipEditId').value = p.id;
    document.getElementById('ipName').value = p.name;
    document.getElementById('ipValue').value = p.ips.join('\\n');
    document.getElementById('ipFormTitle').textContent = 'Edit IP List: ' + p.name;
    document.getElementById('cancelIpEdit').classList.remove('hidden');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function resetIpForm() {
    document.getElementById('ipForm').reset();
    document.getElementById('ipEditId').value = '';
    document.getElementById('ipFormTitle').textContent = 'Add / Edit Clean IP List (IPv4 & IPv6)';
    document.getElementById('cancelIpEdit').classList.add('hidden');
  }

  async function deleteIp(id) {
    if (!confirm('Delete this IP list?')) return;
    var data = await apiCall('/api/ips', 'DELETE', { id: id });
    if (data) {
      state.ipPresets = data.ipPresets;
      renderAll();
      showToast('IP list deleted');
    }
  }

  // CS Form
  document.getElementById('csForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    var data = await apiCall('/api/cs', 'POST', {
      id: document.getElementById('csEditId').value,
      name: document.getElementById('csName').value,
      value: document.getElementById('csValue').value
    });
    if (data) {
      state.csPresets = data.csPresets;
      resetCsForm();
      renderAll();
      showToast('Cipher Suite saved');
    }
  });

  document.getElementById('cancelCsEdit').addEventListener('click', resetCsForm);

  function editCs(id) {
    var c = state.csPresets.find(function(x) { return x.id === id; });
    if (!c) return;
    document.getElementById('csEditId').value = c.id;
    document.getElementById('csName').value = c.name;
    document.getElementById('csValue').value = c.value;
    document.getElementById('cancelCsEdit').classList.remove('hidden');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function resetCsForm() {
    document.getElementById('csForm').reset();
    document.getElementById('csEditId').value = '';
    document.getElementById('cancelCsEdit').classList.add('hidden');
  }

  async function deleteCs(id) {
    if (!confirm('Delete this Cipher Suite preset?')) return;
    var data = await apiCall('/api/cs', 'DELETE', { id: id });
    if (data) {
      state.csPresets = data.csPresets;
      renderAll();
      showToast('Cipher Suite deleted');
    }
  }

  // FM Form & Templates (v1 first, v2 second)
  document.getElementById('loadFmV1Btn').addEventListener('click', function() {
    document.getElementById('fmValue').value = '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}}]}';
  });
  document.getElementById('loadFmV2Btn').addEventListener('click', function() {
    document.getElementById('fmValue').value = '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0"}},{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["114", "1"], "delays": ["1"], "maxSplit": "11"}}]}';
  });

  document.getElementById('fmForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    var data = await apiCall('/api/fm', 'POST', {
      id: document.getElementById('fmEditId').value,
      name: document.getElementById('fmName').value,
      value: document.getElementById('fmValue').value
    });
    if (data) {
      state.fmPresets = data.fmPresets;
      resetFmForm();
      renderAll();
      showToast('Final Mask saved');
    }
  });

  document.getElementById('cancelFmEdit').addEventListener('click', resetFmForm);

  function editFm(id) {
    var f = state.fmPresets.find(function(x) { return x.id === id; });
    if (!f) return;
    document.getElementById('fmEditId').value = f.id;
    document.getElementById('fmName').value = f.name;
    document.getElementById('fmValue').value = f.value;
    document.getElementById('cancelFmEdit').classList.remove('hidden');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function resetFmForm() {
    document.getElementById('fmForm').reset();
    document.getElementById('fmEditId').value = '';
    document.getElementById('cancelFmEdit').classList.add('hidden');
  }

  async function deleteFm(id) {
    if (!confirm('Delete this Final Mask preset?')) return;
    var data = await apiCall('/api/fm', 'DELETE', { id: id });
    if (data) {
      state.fmPresets = data.fmPresets;
      renderAll();
      showToast('Final Mask deleted');
    }
  }

  // Settings & Logout
  document.getElementById('settingsForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    var newPath = document.getElementById('setAdminPath').value;
    var newPassword = document.getElementById('setNewPass').value;
    var data = await apiCall('/api/settings', 'POST', { adminPath: newPath, newPassword: newPassword });
    if (data) {
      showToast('Settings saved, redirecting...');
      setTimeout(function() {
        location.href = '/' + data.adminPath;
      }, 900);
    }
  });

  document.getElementById('logoutBtn').addEventListener('click', async function() {
    await fetch('/api/logout', { method: 'POST' });
    location.reload();
  });

  renderAll();
</script>
</body>
</html>`;
}
