

// ---- Page Logic ----
const urlParams = new URLSearchParams(window.location.search);
const viewPubkey = urlParams.get('pubkey');

async function initPage() {
  // Detect NIP-07 extension
  const extBtn = document.getElementById('btn-ext-login');
  if (extBtn) extBtn.style.display = window.nostr ? '' : 'none';

  if (viewPubkey && viewPubkey !== userPubkey) {
    showPublicProfile(viewPubkey);
  } else if (isLoggedIn()) {
    showOwnAccount();
  } else {
    document.getElementById('view-login').classList.remove('hidden');
  }
}


function setAvatarPlaceholder(el, initial) {
  if (!el) return;
  const keepId = el.id || '';
  const letter = (initial || '?').charAt(0).toUpperCase() || '?';
  // Already a placeholder div — just update the letter.
  if (el.tagName !== 'IMG' && el.classList && el.classList.contains('avatar-placeholder')) {
    el.textContent = letter;
    return;
  }
  // Leftover <img> (or other node) after setAvatarImg — restore id-preserving placeholder.
  const div = document.createElement('div');
  if (keepId) div.id = keepId;
  div.className = 'avatar-placeholder text-lg';
  div.textContent = letter;
  el.replaceWith(div);
}

function setAvatarImg(el, src, className, style) {
  if (!el) return;
  const keepId = el.id || '';
  // Prefer mutating an existing <img> so the id never leaves the DOM.
  if (el.tagName === 'IMG') {
    if (className) el.className = className;
    if (style) el.setAttribute('style', style);
    el.onerror = () => {
      const div = document.createElement('div');
      if (keepId) div.id = keepId;
      div.className = 'avatar-placeholder text-lg';
      div.textContent = '?';
      el.replaceWith(div);
    };
    el.src = src;
    return;
  }
  const img = document.createElement('img');
  if (keepId) img.id = keepId;
  if (className) img.className = className;
  if (style) img.setAttribute('style', style);
  img.src = src;
  img.addEventListener('error', () => {
    const div = document.createElement('div');
    if (keepId) div.id = keepId;
    div.className = 'avatar-placeholder text-lg';
    div.textContent = '?';
    img.replaceWith(div);
  });
  el.replaceWith(img);
}

// ---- Login Functions ----
async function loginWithExtension() {
  const errEl = document.getElementById('login-error');
  errEl.classList.add('hidden');
  try {
    if (!window.nostr) { errEl.textContent = 'No extension found'; errEl.classList.remove('hidden'); return; }
    const pubkey = await window.nostr.getPublicKey();
    setAuthState('extension', pubkey, '');
    await establishSession();
    showOwnAccount();
  } catch (err) {
    errEl.textContent = 'Extension login failed';
    errEl.classList.remove('hidden');
  }
}

async function loginWithNsec() {
  const input = document.getElementById('login-nsec').value.trim();
  const errEl = document.getElementById('login-error');
  errEl.classList.add('hidden');
  if (!input) return;
  try {
    const privhex = normalizeNsec(input);
    const pubkey = derivePubkey(privhex);
    setAuthState('nsec', pubkey, privhex);
    document.getElementById('login-nsec').value = '';
    await establishSession();
    showOwnAccount();
  } catch (err) {
    errEl.textContent = 'Invalid private key (hex or nsec1…)';
    errEl.classList.remove('hidden');
  }
}

async function createIdentity() {
  const errEl = document.getElementById('login-error');
  errEl.classList.add('hidden');
  try {
    const { bytesToHex } = window.__nostrCrypto;
    const privBytes = crypto.getRandomValues(new Uint8Array(32));
    const privhex = bytesToHex(privBytes);
    const pubkey = derivePubkey(privhex);
    setAuthState('nsec', pubkey, privhex);
    await establishSession();

    // Show keys for backup
    document.getElementById('new-pub').value = pubkey;
    document.getElementById('new-priv').value = privhex;
    document.getElementById('new-identity-display').classList.remove('hidden');
    document.getElementById('copy-new-pub').onclick = async () => {
      await copyToClipboard(pubkey);
      document.getElementById('copy-new-pub').textContent = '[copied!]';
      setTimeout(() => document.getElementById('copy-new-pub').textContent = '[copy]', 1500);
    };
    document.getElementById('copy-new-priv').onclick = async () => {
      await copyToClipboard(privhex);
      document.getElementById('copy-new-priv').textContent = '[copied!]';
      setTimeout(() => document.getElementById('copy-new-priv').textContent = '[copy]', 1500);
    };

    // Also show account view after a moment
    setTimeout(() => showOwnAccount(), 500);
  } catch (err) {
    errEl.textContent = 'Failed to generate identity';
    errEl.classList.remove('hidden');
  }
}

async function doLogout() {
  await clearAuthState();
  document.getElementById('view-account').classList.add('hidden');
  document.getElementById('view-login').classList.remove('hidden');
  const extBtn = document.getElementById('btn-ext-login');
  if (extBtn) extBtn.style.display = window.nostr ? '' : 'none';
}

// ---- Own Account View ----
async function showOwnAccount() {
  document.getElementById('view-login').classList.add('hidden');
  document.getElementById('view-public').classList.add('hidden');
  document.getElementById('view-account').classList.remove('hidden');

  // Pubkey display
  document.getElementById('acct-pubkey').textContent = userPubkey.slice(0, 12) + '...' + userPubkey.slice(-4);
  document.getElementById('key-pub').value = userPubkey;
  if (authMode === 'nsec') {
    document.getElementById('key-priv').value = userNsec;
  } else {
    document.getElementById('key-priv').value = '(managed by extension)';
  }

  // Fetch kind:0 metadata (name/about/picture/lud16) into UI
  const meta = await fetchKind0Profile(userPubkey);
  if (meta) {
    document.getElementById('acct-name').textContent = meta.name || meta.display_name || userPubkey.slice(0, 12) + '...';
    document.getElementById('prof-name').value = meta.name || meta.display_name || '';
    document.getElementById('prof-about').value = meta.about || '';
    document.getElementById('prof-picture').value = meta.picture || '';
    document.getElementById('prof-lud16').value = meta.lud16 || '';
    if (meta.picture) {
      setAvatarImg(document.getElementById('acct-avatar'), meta.picture, 'avatar', 'width:48px;height:48px;border-radius:50%;object-fit:cover;');
    } else {
      const initial = (meta.name || meta.display_name || '?').charAt(0).toUpperCase();
      setAvatarPlaceholder(document.getElementById('acct-avatar'), initial);
    }
  } else {
    document.getElementById('acct-name').textContent = userPubkey.slice(0, 12) + '...';
    document.getElementById('prof-name').value = '';
    document.getElementById('prof-about').value = '';
    document.getElementById('prof-picture').value = '';
    document.getElementById('prof-lud16').value = '';
    setAvatarPlaceholder(document.getElementById('acct-avatar'), '?');
  }
}

// ---- Profile Save ----
async function saveProfile() {
  const name = document.getElementById('prof-name').value.trim();
  const about = document.getElementById('prof-about').value.trim();
  const picture = document.getElementById('prof-picture').value.trim();
  const lud16 = document.getElementById('prof-lud16').value.trim();
  const status = document.getElementById('prof-status');

  if (!name && !about && !picture && !lud16) {
    status.textContent = 'Fill at least one field';
    status.style.color = 'var(--error)';
    return;
  }

  status.textContent = 'Saving...';
  status.style.color = 'var(--dim)';

  const metadata = {};
  if (name) metadata.name = name;
  if (about) metadata.about = about;
  if (picture) metadata.picture = picture;
  if (lud16) metadata.lud16 = lud16;

  try {
    const event = {
      kind: 0,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content: JSON.stringify(metadata),
    };
    const signed = await signNostrEvent(event);
    if (!signed) {
      status.textContent = 'Signing failed';
      status.style.color = 'var(--error)';
      return;
    }
    const resp = await authFetch('/api/v1/events', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({event: signed}),
    });
    const data = await resp.json();
    if (data.paid || data.event) {
      status.textContent = 'Saved!';
      status.style.color = 'var(--accent)';
      showOwnAccount();
    } else if (data.token) {
      data._title = 'Pay to update profile:';
      const eventOpts = {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({event: signed}),
      };
      showPaymentWidget(data, async (token, paymentId, method, preimage) => {
        try {
          let auth = null;
          if (method === 'stripe') {
            const ch = (data.stripe && data.stripe.challenge) || {};
            auth = buildStripePaymentAuth(ch, paymentId);
          } else if (method === 'tempo') {
            const ch = (data.tempo && data.tempo.challenge)
              || parsePaymentChallenge(null, data, 'tempo') || {};
            auth = buildTempoPaymentAuth(ch, paymentId);
          } else if (method === 'lightning') {
            const ch = (data.lightning && data.lightning.challenge)
              || parsePaymentChallenge(null, data, 'lightning') || {};
            if (!preimage) {
              status.textContent = 'Connect a Lightning wallet to settle (preimage required)';
              status.style.color = 'var(--error)';
              return;
            }
            auth = buildLightningPaymentAuth(ch, preimage);
          } else {
            status.textContent = 'Unsupported payment method';
            status.style.color = 'var(--error)';
            return;
          }
          const headers = Object.assign(
            {},
            eventOpts.headers || {},
            { Authorization: auth, 'X-Requested-With': 'XMLHttpRequest' },
          );
          const cr = await authFetch('/api/v1/events', Object.assign({}, eventOpts, { headers }));
          const cd = await cr.json().catch(() => ({}));
          if (cd.paid || cd.event) {
            status.textContent = 'Saved!';
            status.style.color = 'var(--accent)';
            hidePaymentWidget();
            showOwnAccount();
          } else {
            status.textContent = (typeof cd.detail === 'string' ? cd.detail : null)
              || 'Payment settle failed';
            status.style.color = 'var(--error)';
          }
        } catch (err) {
          status.textContent = (err && err.message) || 'Payment settle failed';
          status.style.color = 'var(--error)';
        }
      }, null, document.getElementById('section-profile'));
    } else {
      status.textContent = data.detail || 'Failed';
      status.style.color = 'var(--error)';
    }
  } catch (e) {
    status.textContent = 'Error';
    status.style.color = 'var(--error)';
  }
}

// ---- Public Profile View ----
async function showPublicProfile(pubkey) {
  document.getElementById('view-login').classList.add('hidden');
  document.getElementById('view-account').classList.add('hidden');
  document.getElementById('view-public').classList.remove('hidden');

  document.getElementById('pub-pubkey').textContent = pubkey.slice(0, 12) + '...' + pubkey.slice(-4);

  // Fetch metadata
  try {
    const resp = await fetch(`/api/v1/events?authors=${pubkey}&kinds=0&limit=1`);
    const data = await resp.json();
    if (data.events && data.events.length > 0) {
      const meta = JSON.parse(data.events[0].content);
      document.getElementById('pub-name').textContent = meta.name || meta.display_name || pubkey.slice(0, 12) + '...';
      document.getElementById('pub-about').textContent = meta.about || '';
      if (meta.picture) {
        setAvatarImg(document.getElementById('pub-avatar'), meta.picture, '', 'width:48px;height:48px;border-radius:50%;object-fit:cover;border:2px solid var(--border);');
      } else {
        const initial = (meta.name || meta.display_name || '?').charAt(0).toUpperCase();
        setAvatarPlaceholder(document.getElementById('pub-avatar'), initial);
      }
    } else {
      document.getElementById('pub-name').textContent = pubkey.slice(0, 12) + '...';
      document.getElementById('pub-about').textContent = '';
      setAvatarPlaceholder(document.getElementById('pub-avatar'), '?');
    }
  } catch (e) {
    document.getElementById('pub-name').textContent = pubkey.slice(0, 12) + '...';
    document.getElementById('pub-about').textContent = '';
    setAvatarPlaceholder(document.getElementById('pub-avatar'), '?');
  }

  // Fetch notes
  try {
    const resp = await fetch(`/api/v1/events?authors=${pubkey}&kinds=1&sort=newest&limit=50`);
    const data = await resp.json();
    const notes = data.events || [];
    const container = document.getElementById('pub-notes');
    if (notes.length === 0) {
      container.innerHTML = '<p class="text-xs c-dim">No notes from this user on this relay.</p>';
    } else {
      container.innerHTML = notes.map(n => {
        const time = new Date(n.created_at * 1000).toLocaleDateString();
        const sats = n.sats_clank || 0;
        const ext = n.sats_ext || 0;
        const tally = (sats || ext)
          ? `<span class="text-xs c-accent">${sats} sats</span>${ext ? `<span class="text-xs c-dim ml-1" title="external zaps">&#9889;${ext}</span>` : ''}`
          : '';
        return `<div class="note-card p-3 rounded">
          <div class="flex justify-between items-start mb-1">
            <span class="text-xs c-dim">${time}</span>
            ${tally}
          </div>
          <p class="text-sm note-content">${linkify(displayNoteContent(n))}</p>
        </div>`;
      }).join('');
    }
  } catch (e) {
    document.getElementById('pub-notes').innerHTML = '<p class="text-xs c-error">Failed to load notes.</p>';
  }
}

// ---- Init ----
document.getElementById('btn-ext-login')?.addEventListener('click', loginWithExtension);
document.getElementById('btn-login-nsec')?.addEventListener('click', loginWithNsec);
document.getElementById('btn-create-identity')?.addEventListener('click', createIdentity);
document.getElementById('btn-save-profile')?.addEventListener('click', saveProfile);
document.getElementById('btn-logout')?.addEventListener('click', doLogout);
document.getElementById('copy-key-pub')?.addEventListener('click', () => {
  copyToClipboard(document.getElementById('key-pub').value);
});
document.getElementById('copy-key-priv')?.addEventListener('click', () => {
  copyToClipboard(document.getElementById('key-priv').value);
});
['new-pub', 'new-priv', 'key-pub'].forEach((id) => {
  document.getElementById(id)?.addEventListener('focus', (e) => e.target.select());
});
document.getElementById('key-priv')?.addEventListener('focus', (e) => {
  e.target.type = 'text';
  e.target.select();
});

initPage();
setTimeout(() => {
  const extBtn = document.getElementById('btn-ext-login');
  if (extBtn) extBtn.style.display = window.nostr ? '' : 'none';
}, 500);

