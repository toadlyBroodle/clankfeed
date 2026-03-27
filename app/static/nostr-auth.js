/**
 * Shared Nostr auth helpers for clankfeed pages.
 * Requires window.__nostrCrypto to be set by ES module imports before use.
 */

// ---- Auth State (from localStorage) ----
let authMode = localStorage.getItem('cf_auth_mode') || '';
let userPubkey = localStorage.getItem('cf_pubkey') || '';
let userNsec = localStorage.getItem('cf_nsec') || '';

function isLoggedIn() {
  return !!(authMode && userPubkey);
}

function setAuthState(mode, pubkey, nsec) {
  authMode = mode;
  userPubkey = pubkey;
  userNsec = nsec || '';
  localStorage.setItem('cf_auth_mode', mode);
  localStorage.setItem('cf_pubkey', pubkey);
  if (nsec) localStorage.setItem('cf_nsec', nsec);
  else localStorage.removeItem('cf_nsec');
  localStorage.removeItem('clankfeed_api_key');  // clean up legacy
}

function clearAuthState() {
  authMode = '';
  userPubkey = '';
  userNsec = '';
  localStorage.removeItem('cf_auth_mode');
  localStorage.removeItem('cf_pubkey');
  localStorage.removeItem('cf_nsec');
  localStorage.removeItem('clankfeed_api_key');
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
  return fetch(url, {...options, headers: hdrs});
}

// ---- Payment Helper ----
// Pay a Lightning invoice via Bitcoin Connect (if wallet connected) or QR + polling fallback.
// qrCanvas/bolt11Display are optional DOM elements for fallback QR display.
// onPaid is called after payment is confirmed by the server.
let _payPollTimer = null;

async function payInvoice(bolt11, payHash, statusEl, onPaid, qrCanvas, bolt11Display) {
  // Try Bitcoin Connect wallet first
  if (window.__bcConnected && window.webln && bolt11) {
    statusEl.textContent = 'Paying via connected wallet...';
    statusEl.style.color = 'var(--dim)';
    try {
      await window.webln.sendPayment(bolt11);
      statusEl.textContent = 'Payment sent! Confirming...';
      statusEl.style.color = 'var(--accent)';
      await onPaid();
      return;
    } catch (e) {
      statusEl.textContent = 'Wallet payment failed, use QR below';
      statusEl.style.color = 'var(--error)';
    }
  }

  // Fallback: show QR + poll for payment
  if (bolt11 && qrCanvas) {
    new QRious({ element: qrCanvas, value: bolt11.toUpperCase(), size: 160, foreground: '#4ade80', background: '#000', level: 'L' });
  }
  if (bolt11 && bolt11Display) {
    bolt11Display.textContent = bolt11.slice(0, 40) + '...';
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
          await onPaid();
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
