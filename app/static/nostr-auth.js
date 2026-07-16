/**
 * Shared Nostr auth helpers for clankfeed pages.
 * Requires window.__nostrCrypto to be set by ES module imports before use.
 */

// ---- Auth State ----
// Persist only non-secrets (mode + pubkey) for UX. nsec stays in memory only
// (SECURITY H2). HTTP auth uses an httpOnly cf_session cookie after login.
let authMode = localStorage.getItem('cf_auth_mode') || '';
let userPubkey = localStorage.getItem('cf_pubkey') || '';
let userNsec = ''; // never read from localStorage
// Scrub any legacy secrets left from older clients
localStorage.removeItem('cf_nsec');
localStorage.removeItem('clankfeed_api_key');

function isLoggedIn() {
  return !!(authMode && userPubkey);
}

function setAuthState(mode, pubkey, nsec) {
  authMode = mode;
  userPubkey = pubkey;
  userNsec = nsec || '';
  localStorage.setItem('cf_auth_mode', mode);
  localStorage.setItem('cf_pubkey', pubkey);
  localStorage.removeItem('cf_nsec');
  localStorage.removeItem('clankfeed_api_key');
}

async function establishSession() {
  // Phase 14.5: server session login removed; NIP-98 is per-request only.
  return isLoggedIn();
}

async function clearAuthState() {
  authMode = '';
  userPubkey = '';
  userNsec = '';
  localStorage.removeItem('cf_auth_mode');
  localStorage.removeItem('cf_pubkey');
  localStorage.removeItem('cf_nsec');
  localStorage.removeItem('clankfeed_api_key');
  try {
    await apiFetch('/api/v1/auth/logout', { method: 'POST', credentials: 'include' });
  } catch (e) {}
}

// ---- Nostr Signing ----
function computeEventId(event) {
  const { sha256, bytesToHex } = window.__nostrCrypto;
  const canonical = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  return bytesToHex(sha256(new TextEncoder().encode(canonical)));
}

function signEventLocally(privkeyHex, event) {
  const { schnorr, bytesToHex, getPublicKey } = window.__nostrCrypto;
  event.pubkey = bytesToHex(getPublicKey(privkeyHex));
  event.id = computeEventId(event);
  event.sig = bytesToHex(schnorr.sign(event.id, privkeyHex));
  return event;
}

function derivePubkey(privkeyHex) {
  const { bytesToHex, getPublicKey } = window.__nostrCrypto;
  return bytesToHex(getPublicKey(privkeyHex));
}

async function signNostrEvent(event) {
  if (authMode === 'extension' && window.nostr) {
    return await window.nostr.signEvent(event);
  } else if (authMode === 'nsec' && userNsec) {
    return signEventLocally(userNsec, event);
  }
  return null;
}

// ---- NIP-98 HTTP Auth ----
async function makeNip98Auth(url, method) {
  const event = {
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    tags: [["u", url], ["method", method.toUpperCase()]],
    content: "",
  };
  const signed = await signNostrEvent(event);
  if (!signed) return null;
  return "Nostr " + btoa(JSON.stringify(signed));
}

async function authHeaders(url, method, extra) {
  const headers = extra ? {...extra} : {};
  // SECURITY H5: custom header so no-Origin CSRF cannot mutate with cookies alone
  if (!headers['X-Requested-With'] && !headers['x-requested-with']) {
    headers['X-Requested-With'] = 'XMLHttpRequest';
  }
  const nip98 = await makeNip98Auth(url, method);
  if (nip98) {
    headers['Authorization'] = nip98;
  }
  return headers;
}

async function authFetch(url, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const fullUrl = new URL(url, window.location.origin).href;
  const hdrs = await authHeaders(fullUrl, method, options.headers || {});
  return fetch(url, {...options, headers: hdrs, credentials: 'include'});
}

/** fetch() wrapper that always sends X-Requested-With (SECURITY H5). */
function apiFetch(url, options = {}) {
  const headers = Object.assign({'X-Requested-With': 'XMLHttpRequest'}, options.headers || {});
  return fetch(url, Object.assign({}, options, {headers}));
}

// ---- Payment Helper ----
// Pay a Lightning invoice via Bitcoin Connect (if wallet connected) or QR + polling fallback.
// qrCanvas/bolt11Display are optional DOM elements for fallback QR display.
// onPaid is called after payment is confirmed by the server.
let _payPollTimer = null;

/** Parse L402 macaroon+invoice from a 402 Response (+ optional JSON body). */
function parseL402Challenge(resp, body) {
  if (body && body.l402 && body.l402.macaroon && body.l402.invoice) {
    return { macaroon: body.l402.macaroon, invoice: body.l402.invoice };
  }
  const www = (resp && resp.headers && resp.headers.get('www-authenticate')) || '';
  // Match L402 challenge even when other schemes share the header value
  const m = www.match(/L402\s+macaroon="([^"]+)"\s*,\s*invoice="([^"]+)"/i);
  if (m) return { macaroon: m[1], invoice: m[2] };
  return null;
}

/** Base64url-encode bytes (no padding) for MPP Authorization: Payment credentials. */
function _b64urlEncodeBytes(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Build Authorization: Payment <base64url> for Stripe SPT settle.
 * challenge = data.stripe.challenge echo from 402 JSON; spt = spt_…
 */
function buildStripePaymentAuth(challenge, spt) {
  if (!challenge || !challenge.id || !challenge.request || !spt) {
    throw new Error('Missing Stripe challenge or SPT');
  }
  const credential = {
    challenge: {
      id: challenge.id,
      realm: challenge.realm || '',
      method: challenge.method || 'stripe',
      intent: challenge.intent || 'charge',
      request: challenge.request,
      expires: challenge.expires || '',
    },
    payload: { spt: spt },
  };
  const bytes = new TextEncoder().encode(JSON.stringify(credential));
  return 'Payment ' + _b64urlEncodeBytes(bytes);
}

/** Pay BOLT11 via WebLN / Bitcoin Connect; return hex preimage (no 0x). */
async function payBolt11ForPreimage(bolt11, statusEl) {
  const setStatus = (msg, color) => {
    if (!statusEl) return;
    statusEl.textContent = msg;
    if (color) statusEl.style.color = color;
  };

  // Ensure WebLN provider (Bitcoin Connect sets window.webln onConnected)
  if (window.webln) {
    try {
      if (typeof window.webln.enable === 'function' && !window.webln.enabled) {
        await window.webln.enable();
      }
      setStatus('Paying via connected wallet...', 'var(--dim)');
      const result = await window.webln.sendPayment(bolt11);
      const preimage = (result && (result.preimage || result.paymentPreimage)) || '';
      if (preimage) {
        setStatus('Payment sent!', 'var(--accent)');
        return String(preimage).replace(/^0x/i, '');
      }
    } catch (e) {
      setStatus('Wallet payment failed; try Bitcoin Connect modal...', 'var(--error)');
    }
  }

  if (typeof window.__bcLaunchPaymentModal === 'function') {
    setStatus('Opening Bitcoin Connect...', 'var(--dim)');
    const result = await window.__bcLaunchPaymentModal({ invoice: bolt11 });
    const preimage = (result && (result.preimage || result.paymentPreimage)) || '';
    if (preimage) {
      setStatus('Payment sent!', 'var(--accent)');
      return String(preimage).replace(/^0x/i, '');
    }
  }

  throw new Error('Connect a Lightning wallet (Bitcoin Connect / WebLN) to pay');
}

/**
 * Pay an L402 challenge invoice, then retry the request with
 * Authorization: L402 <macaroon>:<preimage>.
 */
async function payL402AndRetry(url, fetchOptions, challenge, statusEl) {
  if (!challenge || !challenge.macaroon || !challenge.invoice) {
    throw new Error('Missing L402 challenge');
  }
  const preimage = await payBolt11ForPreimage(challenge.invoice, statusEl);
  const headers = Object.assign(
    { 'X-Requested-With': 'XMLHttpRequest' },
    fetchOptions.headers || {},
    { Authorization: 'L402 ' + challenge.macaroon + ':' + preimage },
  );
  return fetch(url, Object.assign({}, fetchOptions, { headers }));
}

async function payInvoice(bolt11, payHash, statusEl, onPaid, qrCanvas, bolt11Display) {
  // Try Bitcoin Connect / WebLN first (capture preimage when available)
  if ((window.__bcConnected || window.webln) && bolt11) {
    statusEl.textContent = 'Paying via connected wallet...';
    statusEl.style.color = 'var(--dim)';
    try {
      const preimage = await payBolt11ForPreimage(bolt11, statusEl);
      statusEl.textContent = 'Payment sent! Confirming...';
      statusEl.style.color = 'var(--accent)';
      await onPaid(preimage);
      return;
    } catch (e) {
      statusEl.textContent = 'Wallet payment failed, use QR below';
      statusEl.style.color = 'var(--error)';
    }
  }

  // Fallback: show QR + poll for payment (no preimage — MPP/token confirm only)
  if (bolt11 && qrCanvas) {
    new QRious({ element: qrCanvas, value: bolt11.toUpperCase(), size: 160, foreground: '#4ade80', background: '#000', level: 'L' });
  }
  if (bolt11 && bolt11Display) {
    bolt11Display.textContent = bolt11.slice(0, 40) + '...';
    // Add copy button if not already present
    if (!bolt11Display.nextElementSibling || !bolt11Display.nextElementSibling.classList.contains('copy-btn')) {
      const copyBtn = document.createElement('span');
      copyBtn.className = 'copy-btn text-xs';
      copyBtn.style.cursor = 'pointer';
      copyBtn.textContent = '[copy]';
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(bolt11);
        copyBtn.textContent = '[copied!]';
        setTimeout(() => copyBtn.textContent = '[copy]', 1500);
      };
      bolt11Display.parentNode.insertBefore(copyBtn, bolt11Display.nextSibling);
    }
  }
  statusEl.textContent = 'Waiting for payment...';
  statusEl.style.color = 'var(--dim)';

  if (_payPollTimer) clearInterval(_payPollTimer);
  if (payHash) {
    _payPollTimer = setInterval(async () => {
      try {
        const pr = await fetch(`/api/v1/payments/status?payment_hash=${payHash}`);
        const ps = await pr.json();
        if (ps.paid) {
          clearInterval(_payPollTimer);
          statusEl.textContent = 'Payment received! Confirming...';
          statusEl.style.color = 'var(--accent)';
          await onPaid(null);
        }
      } catch (e) {}
    }, 3000);
  }
}

// ---- Utility ----
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

/** Wrap obvious http(s) URLs as safe <a> links.
 *  Match URLs on raw text first, then escape non-URL segments and href/text
 *  separately — escape-first would turn & into &amp; and truncate query strings.
 *  Only http/https — javascript: and other schemes stay plain text. */
function linkify(text) {
  const s = text == null ? '' : String(text);
  const re = /https?:\/\/[^\s<>]+/gi;
  let out = '';
  let last = 0;
  let m;
  while ((m = re.exec(s)) !== null) {
    out += esc(s.slice(last, m.index));
    let url = m[0];
    let trail = '';
    while (/[.,;:!?)]$/.test(url)) {
      trail = url.slice(-1) + trail;
      url = url.slice(0, -1);
    }
    if (!/^https?:\/\//i.test(url)) {
      out += esc(m[0]);
    } else {
      const safe = esc(url);
      out +=
        `<a href="${safe}" class="note-link" target="_blank" ` +
        `rel="noopener noreferrer">${safe}</a>${esc(trail)}`;
    }
    last = m.index + m[0].length;
  }
  out += esc(s.slice(last));
  return out;
}

/** Safe JS string literal for embedding in single-quoted HTML onclick attrs.
 *  JSON.stringify alone still emits raw apostrophes (e.g. O'Brien), which
 *  terminate single-quoted HTML attributes — rewrite ' as \\u0027. */
function jsStr(s) {
  return JSON.stringify(s == null ? '' : String(s)).replace(/'/g, '\\u0027');
}
