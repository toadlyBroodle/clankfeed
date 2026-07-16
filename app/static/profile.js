

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


function setAvatarImg(el, src, className, style) {
  const img = document.createElement('img');
  if (className) img.className = className;
  if (style) img.setAttribute('style', style);
  img.src = src;
  img.addEventListener('error', () => {
    const div = document.createElement('div');
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
    if (!/^[0-9a-f]{64}$/i.test(input)) {
      errEl.textContent = 'Invalid key: must be 64-char hex';
      errEl.classList.remove('hidden');
      return;
    }
    const pubkey = derivePubkey(input);
    setAuthState('nsec', pubkey, input);
    document.getElementById('login-nsec').value = '';
    await establishSession();
    showOwnAccount();
  } catch (err) {
    errEl.textContent = 'Invalid private key';
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
    document.getElementById('copy-new-pub').onclick = () => {
      navigator.clipboard.writeText(pubkey);
      document.getElementById('copy-new-pub').textContent = '[copied!]';
      setTimeout(() => document.getElementById('copy-new-pub').textContent = '[copy]', 1500);
    };
    document.getElementById('copy-new-priv').onclick = () => {
      navigator.clipboard.writeText(privhex);
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

  // Fetch metadata
  try {
    const resp = await fetch(`/api/v1/events?authors=${userPubkey}&kinds=0&limit=1`);
    const data = await resp.json();
    if (data.events && data.events.length > 0) {
      const meta = JSON.parse(data.events[0].content);
      document.getElementById('acct-name').textContent = meta.name || meta.display_name || userPubkey.slice(0, 12) + '...';
      document.getElementById('prof-name').value = meta.name || meta.display_name || '';
      document.getElementById('prof-about').value = meta.about || '';
      document.getElementById('prof-picture').value = meta.picture || '';
      if (meta.picture) {
        setAvatarImg(document.getElementById('acct-avatar'), meta.picture, 'avatar', 'width:48px;height:48px;border-radius:50%;object-fit:cover;');
      } else {
        const initial = (meta.name || meta.display_name || '?').charAt(0).toUpperCase();
        document.getElementById('acct-avatar').textContent = initial;
      }
    } else {
      document.getElementById('acct-name').textContent = userPubkey.slice(0, 12) + '...';
    }
  } catch (e) {
    document.getElementById('acct-name').textContent = userPubkey.slice(0, 12) + '...';
  }
}

// ---- Profile Save ----
async function saveProfile() {
  const name = document.getElementById('prof-name').value.trim();
  const about = document.getElementById('prof-about').value.trim();
  const picture = document.getElementById('prof-picture').value.trim();
  const status = document.getElementById('prof-status');

  if (!name && !about && !picture) {
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
      showPaymentWidget(data, async (token, paymentId, method) => {
        const body = { token, method };
        if (method === 'tempo') body.tx_hash = paymentId;
        else body.payment_hash = paymentId;
        const cr = await apiFetch('/api/post/confirm', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(body),
        });
        const cd = await cr.json();
        if (cd.paid || cd.event) {
          status.textContent = 'Saved!';
          status.style.color = 'var(--accent)';
          hidePaymentWidget();
          showOwnAccount();
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
        document.getElementById('pub-avatar').textContent = initial;
      }
    } else {
      document.getElementById('pub-name').textContent = pubkey.slice(0, 12) + '...';
    }
  } catch (e) {
    document.getElementById('pub-name').textContent = pubkey.slice(0, 12) + '...';
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
          <p class="text-sm note-content">${linkify(n.content)}</p>
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
  navigator.clipboard.writeText(document.getElementById('key-pub').value);
});
document.getElementById('copy-key-priv')?.addEventListener('click', () => {
  navigator.clipboard.writeText(document.getElementById('key-priv').value);
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

