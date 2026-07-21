// ---- Config ----
const WS_URL = location.protocol === 'https:'
  ? `wss://${location.host}/`
  : `ws://${location.host}/`;

// ---- State ----
let ws = null;
let subId = 'feed-' + Math.random().toString(36).slice(2, 10);
let notes = [];
let metadataCache = {};  // pubkey -> {name, about, picture, lud16, …}
let currentSort = 'newest';
let currentFeed = 'clankfeed';  // 'clankfeed' | 'external'
let relayPubkey = '';  // set from NIP-11, used to label relay-signed notes as 'anon'
let relayLud16 = '';  // NIP-57 fee-leg lud16 from NIP-11 (14.6)
let zapFeeConfig = { authorWeight: 9, relayWeight: 1, relayUrl: '' };

// ---- WebSocket Relay Client ----
function connect() {
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    setStatus(true);
    // Subscribe to kind:0 (metadata) and kind:1 (notes)
    ws.send(JSON.stringify(["REQ", subId, {kinds: [0, 1], limit: 50}]));
  };

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if (msg[0] === 'EVENT' && msg[1] === subId && msg[2]) {
        const event = msg[2];
        if (event.kind === 0) {
          // Cache metadata
          try {
            metadataCache[event.pubkey] = JSON.parse(event.content);
            renderNotes();  // re-render to show updated names
            updateHeaderLink();  // update if this is the logged-in user's metadata
          } catch (err) {}
        } else {
          addNote(event);
        }
      } else if (msg[0] === 'EOSE') {
        // End of stored events; feed is populated
      } else if (msg[0] === 'AUTH') {
        // NIP-42: relay sent challenge, ignore (web client doesn't auth)
      } else if (msg[0] === 'NOTICE') {
        console.log('Relay notice:', msg[1]);
      }
    } catch (err) {
      console.error('Message parse error:', err);
    }
  };

  ws.onclose = () => {
    setStatus(false);
    setTimeout(connect, 3000); // reconnect
  };

  ws.onerror = () => ws.close();
}

function setStatus(connected) {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  dot.className = 'status-dot ' + (connected ? 'status-connected' : 'status-disconnected');
  text.textContent = connected ? 'connected' : 'disconnected';
}

// ---- Notes Rendering ----
function addNote(event) {
  // Deduplicate
  if (notes.find(n => n.id === event.id)) return;
  // Feed filter: clankfeed tab only shows origin=clankfeed (missing => local)
  const origin = event.origin || 'clankfeed';
  if (currentFeed === 'clankfeed' && origin !== 'clankfeed') return;
  // FEED-1: hide external notes with no sats (sats_ext=0 and sats_clank=0)
  if (origin === 'external' && !(event.sats_ext || 0) && !(event.sats_clank || 0)) return;
  notes.push(event);
  notes.sort((a, b) => b.created_at - a.created_at);
  renderNotes();
}

function renderNotes() {
  const feed = document.getElementById('notes-feed');
  const empty = document.getElementById('empty-feed');
  const topLevel = notes.filter(n => !(n.tags || []).some(t => t[0] === 'e'));
  // #empty-feed is a sibling of #notes-feed so innerHTML wipe cannot destroy it
  feed.innerHTML = topLevel.map(n => renderNoteCard(n)).join('');
  bindAvatarFallback(feed);
  if (empty) {
    if (topLevel.length === 0) empty.classList.remove('hidden');
    else empty.classList.add('hidden');
  }
  // Apply cached reply counts immediately
  for (const [eid, count] of Object.entries(replyCountCache)) {
    const btn = document.getElementById(`expand-replies-${eid}`);
    if (btn) {
      btn.classList.add('has-replies');
      btn.innerHTML = `&#9662; ${count} replies`;
    }
  }
  scheduleReplyCountFetch();
}

let replyCountCache = {};
let replyCountTimer = null;

function scheduleReplyCountFetch() {
  if (replyCountTimer) clearTimeout(replyCountTimer);
  replyCountTimer = setTimeout(fetchReplyCounts, 500);
}

function applyReplyCountToBtn(eid, count, expanded) {
  const btn = document.getElementById(`expand-replies-${eid}`);
  if (!btn || !count) return;
  btn.classList.add('has-replies');
  const arrow = expanded ? '&#9652;' : '&#9662;';
  btn.innerHTML = `${arrow} ${count} replies`;
}

async function fetchReplyCounts(ids) {
  const eventIds = ids && ids.length ? ids : notes.map(n => n.id);
  if (!eventIds.length) return;
  try {
    const resp = await apiFetch('/api/v1/events/reply-counts', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({event_ids: eventIds})
    });
    const data = await resp.json();
    // Merge — do not wipe counts for ids not in this batch (nested expand)
    Object.assign(replyCountCache, data.counts || {});
    for (const [eid, count] of Object.entries(data.counts || {})) {
      applyReplyCountToBtn(eid, count, !!expandedReplies[eid]);
    }
  } catch (e) {}
}

function renderNoteCard(n, isReply) {
  const displayName = getDisplayName(n);
  const pk = (relayPubkey && n.pubkey === relayPubkey) ? 'anon' : n.pubkey.slice(0, 4) + '...' + n.pubkey.slice(-4);
  const timeAgo = relativeTime(n.created_at);
  const pic = getAvatar(n);
  const valueSats = n.sats_clank || 0;
  const extSats = n.sats_ext || 0;
  const initial = esc((displayName || pk).charAt(0).toUpperCase());
  // No inline onerror (blocked without CSP unsafe-inline) — bindAvatarFallback after insert
  const avatarHtml = pic
    ? `<img class="avatar" src="${esc(pic)}" data-fallback-initial="${initial}">`
    : `<div class="avatar-placeholder">${initial}</div>`;
  const parentTag = (n.tags || []).find(t => t[0] === 'e' && t[3] === 'reply');
  const parentId = parentTag ? parentTag[1] : '';
  const replyIndicator = parentId && !isReply
    ? `<div class="reply-indicator text-xs c-dim mb-1" data-action="scroll" data-id="${esc(parentId)}">&#8627; reply to ${esc(parentId.slice(0,8))}...</div>`
    : '';
  const cardClass = isReply ? 'reply-card' : 'note-card';
  const nameAttr = esc(displayName || pk).replace(/"/g, '&quot;');
  return `<div class="${cardClass} p-3 rounded" id="note-${n.id}" data-parent="${esc(parentId)}">
    <div class="flex gap-2">
      <div class="flex flex-col items-center gap-0 vote-col">
        <button class="vote-btn" data-action="zap" data-id="${esc(n.id)}" title="Zap (NIP-57 90/10)">&#9889;</button>
        <span class="vote-value" id="value-${n.id}" class="c-accent" title="clankfeed sats">${valueSats}</span>
        <span class="vote-ext" id="ext-${n.id}" title="external zaps (sats_ext)">&#9889;${extSats}</span>
        <button class="vote-btn" data-action="downvote" data-id="${esc(n.id)}" title="Downvote">&#9660;</button>
      </div>
      <div class="flex-1 min-w-0">
        ${replyIndicator}
        <div class="flex items-center gap-2 mb-1">
          <a href="/profile?pubkey=${n.pubkey}" style="text-decoration:none;display:contents;">${avatarHtml}</a>
          <a href="/profile?pubkey=${n.pubkey}" class="text-xs font-bold c-accent" style="text-decoration:none;">${esc(displayName || pk)}</a>${displayName && pk !== 'anon' ? `<span class="text-xs c-dim ml-1">${pk}</span>` : ''}
          <span class="flex-1"></span>
          <span class="text-xs c-dim">${timeAgo}</span>
        </div>
        <p class="text-sm note-content">${linkify(displayNoteContent(n))}</p>
        <div class="flex items-center gap-3 mt-1">
          <button class="reply-btn text-xs" data-action="reply" data-id="${esc(n.id)}" data-name="${nameAttr}" title="Reply">&#8627; reply</button>
          <button class="reply-btn text-xs" id="expand-replies-${n.id}" data-action="toggle-replies" data-id="${esc(n.id)}" title="Show replies">&#9662; replies</button>
        </div>
      </div>
    </div>
    <div class="vote-prompt" id="vote-prompt-${n.id}">
      <input type="number" id="vote-amount-${n.id}" class="p-1 rounded text-xs w-deposit" min="21" value="21" placeholder="sats">
      <button class="px-2 py-1 rounded text-xs ml-1" id="vote-submit-${n.id}" data-action="submit-vote" data-id="${esc(n.id)}">Pay</button>
      <button class="px-2 py-1 rounded text-xs ml-1 bg-alt" data-action="cancel-vote" data-id="${esc(n.id)}">Cancel</button>
      <span class="text-xs ml-2" id="vote-status-${n.id}" class="c-dim"></span>
    </div>
    <div class="replies-container hidden" id="replies-${n.id}"></div>
  </div>`;
}

function bindAvatarFallback(root) {
  (root || document).querySelectorAll('img.avatar[data-fallback-initial]').forEach((img) => {
    if (img.dataset.fallbackBound) return;
    img.dataset.fallbackBound = '1';
    img.addEventListener('error', () => {
      const initial = img.getAttribute('data-fallback-initial') || '?';
      const div = document.createElement('div');
      div.className = 'avatar-placeholder';
      div.textContent = initial;
      img.replaceWith(div);
    });
  });
}

function handleFeedAction(e) {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const action = el.getAttribute('data-action');
  const id = el.getAttribute('data-id') || '';
  if (action === 'zap') startZap(id);
  else if (action === 'downvote') startVote(id, -1);
  else if (action === 'reply') startReply(id, el.getAttribute('data-name') || '');
  else if (action === 'toggle-replies') toggleReplies(id);
  else if (action === 'submit-vote') submitPendingAction(id);
  else if (action === 'cancel-vote') cancelVote(id);
  else if (action === 'scroll') scrollToNote(id);
}

function getDisplayName(event) {
  // kind:0 metadata: name → display_name → nip05
  const meta = metadataCache[event.pubkey];
  if (meta) {
    if (meta.name) return meta.name;
    if (meta.display_name) return meta.display_name;
    if (meta.nip05) return meta.nip05;
  }
  // Fall back to display_name tag on the event itself
  const tag = (event.tags || []).find(t => t[0] === 'display_name');
  return tag ? tag[1] : '';
}

function getAvatar(event) {
  const meta = metadataCache[event.pubkey];
  return (meta && meta.picture) ? meta.picture : '';
}

function relativeTime(ts) {
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}



// ---- Post Form + Payment (L402 primary) ----
document.getElementById('post-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const content = document.getElementById('post-content').value.trim();
  if (!content) return;

  const btn = document.getElementById('post-btn');
  btn.disabled = true;
  btn.textContent = 'Submitting...';

  try {
    // Logged-in identity that can sign → client-signed kind:1 via /api/v1/events
    if (canSign()) {
      await submitClientSignedPost(content, btn);
      return;
    }
    // Stale session (pubkey cached, cannot sign): nsec scrubbed after /profile→/
    // OR extension mode without window.nostr — do not relay-sign under a logged-in
    // display_name façade; mirror submitZap re-entry. True anon still relay-signs.
    if (isLoggedIn() && !canSign()) {
      btn.disabled = false;
      btn.textContent = 'Post Note';
      const msg = (authMode === 'extension')
        ? 'Restore your Nostr extension (or set identity on /profile) to sign'
        : 'Re-enter your private key on /profile to sign';
      alert(msg);
      return;
    }
    // Anonymous / cannot-sign → relay-signed /api/v1/post
    await submitRelaySignedPost(content, btn);
  } catch (err) {
    console.error('Post error:', err);
    btn.disabled = false;
    btn.textContent = 'Post Note';
  }
});

/** Build NIP-57 zap fee tags for a client-signed kind:1 (author + relay). */
function buildClientZapFeeTags(authorPubkey) {
  const relayUrl = zapFeeConfig.relayUrl
    || (location.protocol === 'https:' ? `wss://${location.host}` : `ws://${location.host}`);
  const aw = String(zapFeeConfig.authorWeight || 9);
  const rw = String(zapFeeConfig.relayWeight || 1);
  const rpk = relayPubkey;
  if (!rpk) return null;
  return [
    ['zap', authorPubkey, relayUrl, aw],
    ['zap', rpk, relayUrl, rw],
  ];
}

/** Client-signed post: user nsec/NIP-07 signs, settle via /api/v1/events. */
async function submitClientSignedPost(content, btn) {
  const name = document.getElementById('post-name').value.trim();
  const amount = parseInt(document.getElementById('post-amount').value);
  const replyTo = document.getElementById('post-form').dataset.replyTo;

  const tags = [];
  if (name) tags.push(['display_name', name]);
  if (replyTo && replyTo.length === 64) tags.push(['e', replyTo, '', 'reply']);

  const authorPk = userPubkey;
  const zapTags = buildClientZapFeeTags(authorPk);
  if (!zapTags) {
    btn.disabled = false;
    btn.textContent = 'Post Note';
    alert('Relay info not loaded yet — wait a moment and retry');
    return;
  }
  tags.push(...zapTags);

  const event = {
    kind: 1,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: withClankfeedAttribution(content),
  };
  const signed = await signNostrEvent(event);
  if (!signed) {
    btn.disabled = false;
    btn.textContent = 'Post Note';
    alert('Could not sign note — re-enter your key on /profile');
    return;
  }

  const body = { event: signed };
  if (amount && amount >= 21) body.amount_sats = amount;

  const postOpts = {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  };
  // NIP-98 so we pass the early-auth gate and get pending+L402 JSON (like profile)
  let resp = await authFetch('/api/v1/events', postOpts);
  let data = await resp.json().catch(() => ({}));

  if (resp.ok && data.paid) {
    document.getElementById('post-content').value = '';
    clearReplyState();
    btn.disabled = false;
    btn.textContent = 'Post Note';
    return;
  }

  if (resp.status === 402 || data.status === 'payment_required') {
    const challenge = parseL402Challenge(resp, data);
    if (challenge) {
      data._title = 'Pay to post (L402):';
      showPaymentWidget(data, null, () => {
        btn.disabled = false;
        btn.textContent = 'Post Note';
      }, document.getElementById('post-form'));
      const lnStatus = document.getElementById('pw-ln-status');
      try {
        resp = await payL402AndRetry('/api/v1/events', postOpts, challenge, lnStatus);
        data = await resp.json().catch(() => ({}));
        if (resp.ok && data.paid) {
          document.getElementById('post-content').value = '';
          clearReplyState();
          hidePaymentWidget();
          btn.disabled = false;
          btn.textContent = 'Post Note';
          return;
        }
        if (lnStatus) {
          lnStatus.textContent = (typeof data.detail === 'string' ? data.detail : null)
            || 'L402 settle failed — try Tempo tab if available';
          lnStatus.style.color = 'var(--error)';
        }
      } catch (payErr) {
        if (lnStatus) {
          lnStatus.textContent = payErr.message || 'Payment failed';
          lnStatus.style.color = 'var(--error)';
        }
      }
    }

    const hasPay = data.bolt11 || data.tempo || data.stripe
      || (data.lightning && data.lightning.bolt11)
      || ((data.methods || []).length > 0);
    if (hasPay) {
      data._title = data._title || 'Pay to post your note:';
      showPaymentWidget(data, async (token, paymentId, method, preimage) => {
        const statusEl = document.getElementById('pw-stripe-status')
          || document.getElementById('pw-tempo-status')
          || document.getElementById('pw-ln-status');
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
              if (statusEl) {
                statusEl.textContent = 'Connect a Lightning wallet to settle (preimage required)';
                statusEl.style.color = 'var(--error)';
              }
              return;
            }
            auth = buildLightningPaymentAuth(ch, preimage);
          } else {
            if (statusEl) {
              statusEl.textContent = 'Unsupported payment method';
              statusEl.style.color = 'var(--error)';
            }
            return;
          }
          const headers = Object.assign(
            {},
            postOpts.headers || {},
            { Authorization: auth, 'X-Requested-With': 'XMLHttpRequest' },
          );
          const cr = await apiFetch('/api/v1/events', Object.assign({}, postOpts, { headers }));
          const cd = await cr.json().catch(() => ({}));
          if (cr.ok && cd.paid) {
            document.getElementById('post-content').value = '';
            clearReplyState();
            btn.disabled = false;
            btn.textContent = 'Post Note';
            hidePaymentWidget();
          } else if (statusEl) {
            statusEl.textContent = (typeof cd.detail === 'string' ? cd.detail : null)
              || (method + ' settle failed');
            statusEl.style.color = 'var(--error)';
          }
        } catch (err) {
          if (statusEl) {
            statusEl.textContent = (err && err.message) || 'Payment settle failed';
            statusEl.style.color = 'var(--error)';
          }
        }
      }, () => {
        btn.disabled = false;
        btn.textContent = 'Post Note';
      }, document.getElementById('post-form'));
      return;
    }
  }

  btn.disabled = false;
  btn.textContent = 'Post Note';
  if (data.detail) alert(typeof data.detail === 'string' ? data.detail : 'Post failed');
}

/** Anonymous relay-signed post via /api/v1/post. */
async function submitRelaySignedPost(content, btn) {
  const body = { content };
  const name = document.getElementById('post-name').value.trim();
  if (name) body.display_name = name;
  const amount = parseInt(document.getElementById('post-amount').value);
  if (amount && amount >= 21) body.amount_sats = amount;
  const replyTo = document.getElementById('post-form').dataset.replyTo;
  if (replyTo) body.reply_to = replyTo;

  const postOpts = {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  };
  // Use apiFetch (no NIP-98) so L402 Authorization is free for the settle retry
  let resp = await apiFetch('/api/v1/post', postOpts);
  let data = await resp.json().catch(() => ({}));

  if (resp.ok && data.paid) {
    document.getElementById('post-content').value = '';
    clearReplyState();
    btn.disabled = false;
    btn.textContent = 'Post Note';
    return;
  }

  if (resp.status === 402 || data.status === 'payment_required') {
    const challenge = parseL402Challenge(resp, data);
    if (challenge) {
      data._title = 'Pay to post (L402):';
      showPaymentWidget(data, null, () => {
        btn.disabled = false;
        btn.textContent = 'Post Note';
      }, document.getElementById('post-form'));
      const lnStatus = document.getElementById('pw-ln-status');
      try {
        resp = await payL402AndRetry('/api/v1/post', postOpts, challenge, lnStatus);
        data = await resp.json().catch(() => ({}));
        if (resp.ok && data.paid) {
          document.getElementById('post-content').value = '';
          clearReplyState();
          hidePaymentWidget();
          btn.disabled = false;
          btn.textContent = 'Post Note';
          return;
        }
        if (lnStatus) {
          lnStatus.textContent = (typeof data.detail === 'string' ? data.detail : null)
            || 'L402 settle failed — try Tempo tab if available';
          lnStatus.style.color = 'var(--error)';
        }
      } catch (payErr) {
        if (lnStatus) {
          lnStatus.textContent = payErr.message || 'Payment failed';
          lnStatus.style.color = 'var(--error)';
        }
      }
      // Fall through to Tempo/MPP widget if L402 wallet path failed
    }

    // Tempo / Stripe / QR fallback (also used when 402 has no L402 challenge)
    const hasPay = data.bolt11 || data.tempo || data.stripe
      || (data.lightning && data.lightning.bolt11)
      || ((data.methods || []).length > 0);
    if (hasPay) {
      data._title = data._title || 'Pay to post your note:';
      showPaymentWidget(data, async (token, paymentId, method, preimage) => {
        const statusEl = document.getElementById('pw-stripe-status')
          || document.getElementById('pw-tempo-status')
          || document.getElementById('pw-ln-status');
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
              if (statusEl) {
                statusEl.textContent = 'Connect a Lightning wallet to settle (preimage required)';
                statusEl.style.color = 'var(--error)';
              }
              return;
            }
            auth = buildLightningPaymentAuth(ch, preimage);
          } else {
            if (statusEl) {
              statusEl.textContent = 'Unsupported payment method';
              statusEl.style.color = 'var(--error)';
            }
            return;
          }
          const headers = Object.assign(
            {},
            postOpts.headers || {},
            { Authorization: auth, 'X-Requested-With': 'XMLHttpRequest' },
          );
          const cr = await apiFetch('/api/v1/post', Object.assign({}, postOpts, { headers }));
          const cd = await cr.json().catch(() => ({}));
          if (cr.ok && cd.paid) {
            document.getElementById('post-content').value = '';
            clearReplyState();
            btn.disabled = false;
            btn.textContent = 'Post Note';
            hidePaymentWidget();
          } else if (statusEl) {
            statusEl.textContent = (typeof cd.detail === 'string' ? cd.detail : null)
              || (method + ' settle failed');
            statusEl.style.color = 'var(--error)';
          }
        } catch (err) {
          if (statusEl) {
            statusEl.textContent = (err && err.message) || 'Payment settle failed';
            statusEl.style.color = 'var(--error)';
          }
        }
      }, () => {
        btn.disabled = false;
        btn.textContent = 'Post Note';
      }, document.getElementById('post-form'));
      return;
    }
  }

  btn.disabled = false;
  btn.textContent = 'Post Note';
}


// ---- Voting / Zap ----
let pendingVoteDir = {};  // event_id -> direction (-1 downvote) or 'zap'
let voteDebounce = {};  // event_id -> timeout ID
let votePending = {};  // event_id -> accumulated clicks {direction, count}

function startZap(eventId) {
  pendingVoteDir[eventId] = 'zap';
  votePending[eventId] = { direction: 'zap', count: 1 };
  const prompt = document.getElementById(`vote-prompt-${eventId}`);
  prompt.classList.add('active');
  const amountInput = document.getElementById(`vote-amount-${eventId}`);
  if (amountInput) amountInput.value = 21;
  const status = document.getElementById(`vote-status-${eventId}`);
  status.textContent = 'Zap (NIP-57 90/10)';
  status.style.color = 'var(--dim)';
  const submitBtn = document.getElementById(`vote-submit-${eventId}`);
  if (submitBtn) submitBtn.textContent = 'Zap';
}

function startVote(eventId, direction) {
  // Downvote only (anti-signal via L402). Tips use startZap.
  if (direction !== -1) return;
  if (!votePending[eventId]) {
    votePending[eventId] = { direction, count: 0 };
  }
  if (votePending[eventId].direction === direction) {
    votePending[eventId].count++;
  } else {
    votePending[eventId] = { direction, count: 1 };
  }

  pendingVoteDir[eventId] = direction;
  const prompt = document.getElementById(`vote-prompt-${eventId}`);
  prompt.classList.add('active');
  const amountInput = document.getElementById(`vote-amount-${eventId}`);
  if (amountInput) amountInput.value = 21 * votePending[eventId].count;

  const status = document.getElementById(`vote-status-${eventId}`);
  const clicks = votePending[eventId].count;
  status.textContent = 'Downvote' + (clicks > 1 ? ` (${clicks}x)` : '');
  status.style.color = 'var(--dim)';
  const submitBtn = document.getElementById(`vote-submit-${eventId}`);
  if (submitBtn) submitBtn.textContent = 'Pay & Downvote';
}

function cancelVote(eventId) {
  document.getElementById(`vote-prompt-${eventId}`).classList.remove('active');
  const vpay = document.getElementById(`vote-pay-${eventId}`);
  if (vpay) vpay.remove();
  delete pendingVoteDir[eventId];
  delete votePending[eventId];
  if (voteDebounce[eventId]) { clearTimeout(voteDebounce[eventId]); delete voteDebounce[eventId]; }
  hidePaymentWidget();
}

function submitPendingAction(eventId) {
  if (pendingVoteDir[eventId] === 'zap') return submitZap(eventId);
  return submitVote(eventId);
}

async function submitVote(eventId) {
  const direction = pendingVoteDir[eventId] || -1;
  if (direction !== -1) {
    const status = document.getElementById(`vote-status-${eventId}`);
    status.textContent = 'Tips use Zap (NIP-57)';
    status.style.color = 'var(--error)';
    return;
  }
  const amountInput = document.getElementById(`vote-amount-${eventId}`);
  const amount = parseInt(amountInput.value) || 21;
  const status = document.getElementById(`vote-status-${eventId}`);

  status.textContent = 'Submitting...';
  status.style.color = 'var(--dim)';

  try {
    const voteBody = { direction, amount_sats: amount };
    const voteOpts = {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(voteBody),
    };
    let resp = await apiFetch(`/api/v1/events/${eventId}/vote`, voteOpts);
    let data = await resp.json().catch(() => ({}));

    if (data.voted) {
      voteSuccess(eventId, direction, amount, data.new_sats_clank, data.new_sats_ext);
      return;
    }

    if (resp.status === 402 || data.status === 'payment_required') {
      const challenge = parseL402Challenge(resp, data);
      // Preserve co-challenges: L402 settle overwrite must not drop stripe/tempo
      const pay402 = data;
      if (challenge) {
        status.textContent = 'Pay L402 to downvote...';
        try {
          resp = await payL402AndRetry(
            `/api/v1/events/${eventId}/vote`, voteOpts, challenge, status,
          );
          data = await resp.json().catch(() => ({}));
          if (data.voted) {
            voteSuccess(eventId, direction, amount, data.new_sats_clank, data.new_sats_ext);
            return;
          }
          status.textContent = data.detail || 'L402 downvote failed';
          status.style.color = 'var(--error)';
        } catch (payErr) {
          status.textContent = payErr.message || 'Payment failed';
          status.style.color = 'var(--error)';
        }
        // Fall through to Tempo/Stripe/QR widget if L402 wallet path failed
      }
      const hasPay = pay402.bolt11 || pay402.tempo || pay402.stripe
        || (pay402.lightning && pay402.lightning.bolt11)
        || ((pay402.methods || []).length > 0);
      if (hasPay) {
        status.textContent = '';
        showVotePayment(eventId, direction, pay402);
        return;
      }
      if (!challenge) {
        status.textContent = (typeof data.detail === 'string' ? data.detail : null) || 'Vote failed';
        status.style.color = 'var(--error)';
      }
      return;
    }

    status.textContent = data.detail || 'Vote failed';
    status.style.color = 'var(--error)';
  } catch (err) {
    status.textContent = 'Error';
    status.style.color = 'var(--error)';
  }
}

/** Split total sats across NIP-57 zap tags by weight. */
function splitZapAmounts(totalSats, zapTags) {
  const weights = zapTags.map(t => parseInt(t[3], 10) || 0);
  const sum = weights.reduce((a, b) => a + b, 0) || 1;
  let allocated = 0;
  const parts = zapTags.map((t, i) => {
    const isLast = i === zapTags.length - 1;
    const sats = isLast
      ? Math.max(1, totalSats - allocated)
      : Math.max(1, Math.floor((totalSats * weights[i]) / sum));
    if (!isLast) allocated += sats;
    return { pubkey: t[1], relay: t[2], weight: weights[i], sats };
  });
  return parts;
}

async function resolveLud16ForPubkey(pubkey) {
  if (relayPubkey && pubkey === relayPubkey && relayLud16) return relayLud16;
  const meta = metadataCache[pubkey];
  if (meta && typeof meta.lud16 === 'string' && meta.lud16.includes('@')) {
    return meta.lud16.trim();
  }
  const parsed = await fetchKind0Profile(pubkey);
  if (parsed) {
    metadataCache[pubkey] = parsed;
    if (typeof parsed.lud16 === 'string' && parsed.lud16.includes('@')) {
      return parsed.lud16.trim();
    }
  }
  return null;
}

/** Load logged-in user's kind:0 into metadataCache (header / zaps). */
async function hydrateOwnProfile() {
  if (!isLoggedIn() || !userPubkey) return null;
  const meta = await fetchKind0Profile(userPubkey);
  if (meta) {
    metadataCache[userPubkey] = meta;
    updateHeaderLink();
  }
  return meta;
}

async function submitZap(eventId) {
  const amountInput = document.getElementById(`vote-amount-${eventId}`);
  const status = document.getElementById(`vote-status-${eventId}`);
  if (!amountInput) {
    if (status) {
      status.textContent = 'Amount input missing';
      status.style.color = 'var(--error)';
    }
    return;
  }
  const amount = parseInt(amountInput.value) || 21;

  if (!canSign()) {
    status.textContent = (authMode === 'extension' && !window.nostr)
      ? 'Restore your Nostr extension (or set identity on /profile) to zap'
      : (authMode === 'nsec' && !userNsec)
        ? 'Re-enter your private key on /profile to sign'
        : 'Set identity on /profile to zap';
    status.style.color = 'var(--error)';
    return;
  }

  const note = notes.find(n => n.id === eventId);
  if (!note) {
    status.textContent = 'Note not found';
    status.style.color = 'var(--error)';
    return;
  }

  const zapTags = (note.tags || []).filter(t => Array.isArray(t) && t[0] === 'zap' && t.length >= 4);
  if (zapTags.length < 2) {
    status.textContent = 'Note missing zap fee tags';
    status.style.color = 'var(--error)';
    return;
  }

  status.textContent = 'Building zap split...';
  status.style.color = 'var(--dim)';

  try {
    const parts = splitZapAmounts(amount, zapTags);
    for (const part of parts) {
      const lud16 = await resolveLud16ForPubkey(part.pubkey);
      if (!lud16) {
        status.textContent = part.pubkey === relayPubkey
          ? 'Relay lud16 not configured'
          : 'Author has no lud16 (kind:0)';
        status.style.color = 'var(--error)';
        return;
      }
      part.lud16 = lud16;
    }

    // Pay each leg: kind:9734 → LNURL invoice → WebLN
    for (const part of parts) {
      status.textContent = `Zapping ${part.sats} sats → ${part.lud16}...`;
      const amountMsat = part.sats * 1000;
      const zapRequest = {
        kind: 9734,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['p', part.pubkey],
          ['e', eventId],
          ['amount', String(amountMsat)],
          ['relays', location.origin.replace(/^http/, 'ws')],
        ],
        content: '',
      };
      const signed = await signNostrEvent(zapRequest);
      if (!signed) {
        status.textContent = 'Could not sign zap request';
        status.style.color = 'var(--error)';
        return;
      }

      const invResp = await apiFetch('/api/v1/zap/invoice', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          lud16: part.lud16,
          amount_msat: amountMsat,
          zap_request: signed,
        }),
      });
      const invData = await invResp.json().catch(() => ({}));
      if (!invResp.ok || !invData.bolt11) {
        status.textContent = invData.detail || 'Zap invoice failed';
        status.style.color = 'var(--error)';
        return;
      }

      await payBolt11ForPreimage(invData.bolt11, status);
    }

    status.textContent = `Zapped ${amount} sats (90/10 split)`;
    status.style.color = 'var(--accent)';
    const extEl = document.getElementById(`ext-${eventId}`);
    if (extEl) {
      const cur = parseInt(String(extEl.textContent).replace(/\D/g, ''), 10) || 0;
      extEl.textContent = '\u26A1' + (cur + amount);
    }
    if (note) note.sats_ext = (note.sats_ext || 0) + amount;
    setTimeout(() => cancelVote(eventId), 2500);
  } catch (err) {
    status.textContent = err.message || 'Zap failed';
    status.style.color = 'var(--error)';
  }
}

function voteSuccess(eventId, direction, amount, newValue, newSatsExt) {
  hidePaymentWidget();
  delete votePending[eventId];
  const valueEl = document.getElementById(`value-${eventId}`);
  if (valueEl) valueEl.textContent = newValue;
  const extEl = document.getElementById(`ext-${eventId}`);
  if (extEl && newSatsExt !== undefined && newSatsExt !== null) {
    extEl.textContent = '\u26A1' + newSatsExt;
  }
  const note = notes.find(n => n.id === eventId);
  if (note) {
    note.sats_clank = newValue;
    if (newSatsExt !== undefined && newSatsExt !== null) note.sats_ext = newSatsExt;
  }
  const status = document.getElementById(`vote-status-${eventId}`);
  status.textContent = (direction === 1 ? '+' : '-') + amount + ' sats';
  status.style.color = 'var(--accent)';
  const vpay = document.getElementById(`vote-pay-${eventId}`);
  if (vpay) vpay.remove();
  setTimeout(() => cancelVote(eventId), 2000);
}

function showVotePayment(eventId, direction, data) {
  const amount = (data.lightning && data.lightning.amount_sats) || (data.amount_sats) || 21;
  data._title = `Pay to downvote (${amount} sats):`;
  showPaymentWidget(data, async (token, paymentId, method, preimage) => {
    const status = document.getElementById(`vote-status-${eventId}`);
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
          if (status) {
            status.textContent = 'Connect a Lightning wallet to settle (preimage required)';
            status.style.color = 'var(--error)';
          }
          return;
        }
        auth = buildLightningPaymentAuth(ch, preimage);
      } else {
        if (status) {
          status.textContent = 'Unsupported payment method';
          status.style.color = 'var(--error)';
        }
        return;
      }
      const voteBody = { direction, amount_sats: amount };
      const resp = await apiFetch(`/api/v1/events/${eventId}/vote`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: auth,
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: JSON.stringify(voteBody),
      });
      const d = await resp.json().catch(() => ({}));
      if (d.voted) {
        voteSuccess(eventId, direction, amount, d.new_sats_clank, d.new_sats_ext);
        hidePaymentWidget();
      } else if (status) {
        status.textContent = (typeof d.detail === 'string' ? d.detail : null)
          || (method + ' settle failed');
        status.style.color = 'var(--error)';
      }
    } catch (err) {
      if (status) {
        status.textContent = (err && err.message) || 'Payment settle failed';
        status.style.color = 'var(--error)';
      }
    }
  }, null, document.getElementById(`vote-prompt-${eventId}`));
}

// ---- Replies ----
function startReply(eventId, authorName) {
  const form = document.getElementById('post-form');
  const section = document.getElementById('post-section');
  form.dataset.replyTo = eventId;
  const ctx = document.getElementById('reply-context');
  ctx.classList.remove('hidden');
  document.getElementById('reply-context-name').textContent = authorName + ' (' + eventId.slice(0,8) + '...)';
  document.getElementById('post-content').placeholder = 'Write a reply...';
  document.getElementById('post-btn').textContent = 'Post Reply';
  // Move form below the note being replied to
  const noteEl = document.getElementById(`note-${eventId}`);
  if (noteEl) {
    noteEl.parentNode.insertBefore(section, noteEl.nextSibling);
  }
  document.getElementById('post-content').focus();
  section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function clearReplyState() {
  const form = document.getElementById('post-form');
  const section = document.getElementById('post-section');
  delete form.dataset.replyTo;
  document.getElementById('reply-context').classList.add('hidden');
  document.getElementById('reply-context-name').textContent = '';
  document.getElementById('post-content').placeholder = 'Write a note... (costs sats to post)';
  document.getElementById('post-btn').textContent = 'Post Note';
  // Move form back to its original position (before the feed section)
  const feedSection = document.querySelector('#notes-feed').closest('section');
  if (feedSection) {
    feedSection.parentNode.insertBefore(section, feedSection);
  }
}

let expandedReplies = {};  // event_id -> true if expanded

async function toggleReplies(eventId) {
  const container = document.getElementById(`replies-${eventId}`);
  const btn = document.getElementById(`expand-replies-${eventId}`);
  if (!container) return;

  if (expandedReplies[eventId]) {
    container.classList.add('hidden');
    container.innerHTML = '';
    delete expandedReplies[eventId];
    const count = replyCountCache[eventId];
    if (btn) btn.innerHTML = count ? `&#9662; ${count} replies` : '&#9662; replies';
    return;
  }

  const count = replyCountCache[eventId];
  if (btn) btn.innerHTML = count ? `&#9652; ${count} replies` : '&#9652; replies';
  container.classList.remove('hidden');
  container.innerHTML = '<p class="text-xs c-dim p-2">Loading...</p>';
  expandedReplies[eventId] = true;

  try {
    const resp = await fetch(`/api/v1/events/${eventId}/replies?sort=newest&limit=50`);
    const data = await resp.json();
    const replies = data.replies || [];
    // Never lower a prior reply-counts total with capped page size (limit=50)
    const cnt = typeof data.count === 'number' ? data.count : replies.length;
    if (cnt > 0) {
      const merged = Math.max(replyCountCache[eventId] || 0, cnt);
      replyCountCache[eventId] = merged;
      applyReplyCountToBtn(eventId, merged, true);
    }

    if (replies.length === 0) {
      container.innerHTML = '<p class="text-xs c-dim p-2">No replies yet.</p>';
      return;
    }

    container.innerHTML = replies.map(r => renderNoteCard(r, true)).join('');
    bindAvatarFallback(container);
    // Apply any cached counts to newly rendered nested expand buttons
    for (const r of replies) {
      applyReplyCountToBtn(r.id, replyCountCache[r.id], false);
    }
    // Fetch counts for nested reply cards (merge into cache)
    await fetchReplyCounts(replies.map(r => r.id));
  } catch (err) {
    container.innerHTML = '<p class="text-xs c-error p-2">Failed to load replies.</p>';
  }
}

function scrollToNote(eventId) {
  const el = document.getElementById(`note-${eventId}`);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    el.style.borderColor = 'var(--accent)';
    setTimeout(() => el.style.borderColor = '', 1500);
  }
}

// ---- Sort & Filter & Feed ----
let filterMinValue = null;
let filterMaxValue = null;
const DEFAULT_SINCE = '1day';
let filterSinceKey = DEFAULT_SINCE;  // 1day | 3day | 1week | 1month | all

const SINCE_WINDOW_SECS = {
  '1day': 86400,
  '3day': 259200,
  '1week': 604800,
  '1month': 2592000,
};

function sinceParamForFilter() {
  const secs = SINCE_WINDOW_SECS[filterSinceKey];
  if (!secs) return null;
  return Math.floor(Date.now() / 1000) - secs;
}

function filtersAreDefault() {
  return filterMinValue === null && filterMaxValue === null && filterSinceKey === DEFAULT_SINCE;
}

function applyFilters() {
  const minVal = document.getElementById('filter-min').value;
  const maxVal = document.getElementById('filter-max').value;
  filterMinValue = minVal ? parseInt(minVal) : null;
  filterMaxValue = maxVal ? parseInt(maxVal) : null;
  const sinceEl = document.getElementById('filter-since');
  if (sinceEl) filterSinceKey = sinceEl.value || DEFAULT_SINCE;
  const clearBtn = document.getElementById('clear-filters-btn');
  clearBtn.style.display = filtersAreDefault() ? 'none' : 'inline';
  setSort(currentSort);
}

function clearFilters() {
  filterMinValue = null;
  filterMaxValue = null;
  filterSinceKey = DEFAULT_SINCE;
  document.getElementById('filter-min').value = '';
  document.getElementById('filter-max').value = '';
  const sinceEl = document.getElementById('filter-since');
  if (sinceEl) sinceEl.value = DEFAULT_SINCE;
  document.getElementById('clear-filters-btn').style.display = 'none';
  setSort(currentSort);
}

function setFeed(feed) {
  currentFeed = feed === 'external' ? 'external' : 'clankfeed';
  document.getElementById('feed-clankfeed').className =
    currentFeed === 'clankfeed' ? 'px-2 py-1 rounded bg-primary text-xs font-bold' : 'px-2 py-1 rounded bg-alt text-xs font-bold';
  document.getElementById('feed-external').className =
    currentFeed === 'external' ? 'px-2 py-1 rounded bg-primary text-xs font-bold' : 'px-2 py-1 rounded bg-alt text-xs font-bold';
  // Default ranking per feed: clankfeed → sats_clank (value); external → sats_ext
  if (currentFeed === 'external' && currentSort === 'value') {
    currentSort = 'ext';
  } else if (currentFeed === 'clankfeed' && (currentSort === 'ext' || currentSort === 'zaps')) {
    currentSort = 'value';
  }
  setSort(currentSort);
}

async function setSort(mode) {
  // Normalize Top button: value on clankfeed, ext on external
  if (mode === 'value' && currentFeed === 'external') mode = 'ext';
  if (mode === 'ext' && currentFeed === 'clankfeed') mode = 'value';
  currentSort = mode;
  const isNewest = mode === 'newest';
  const isTop = mode === 'value' || mode === 'clank' || mode === 'ext' || mode === 'zaps';
  document.getElementById('sort-newest').className = isNewest ? 'px-2 py-1 rounded bg-primary' : 'px-2 py-1 rounded bg-alt';
  document.getElementById('sort-value').className = isTop ? 'px-2 py-1 rounded bg-primary' : 'px-2 py-1 rounded bg-alt';

  try {
    // clankfeed tab: origin=clankfeed + sats_clank (value); external: origin=all + sats_ext when Top
    let url;
    if (currentFeed === 'external' && isTop) {
      url = `/api/v1/events?sort=ext&kinds=0,1&limit=50&origin=all`;
    } else if (currentFeed === 'external') {
      url = `/api/v1/events?sort=newest&kinds=0,1&limit=50&origin=all`;
    } else if (isTop) {
      url = `/api/v1/events?sort=value&kinds=0,1&limit=50&origin=clankfeed`;
    } else {
      url = `/api/v1/events?sort=newest&kinds=0,1&limit=50&origin=clankfeed`;
    }
    if (filterMinValue !== null) url += `&min_value=${filterMinValue}`;
    if (filterMaxValue !== null) url += `&max_value=${filterMaxValue}`;
    const since = sinceParamForFilter();
    if (since !== null) url += `&since=${since}`;
    const resp = await fetch(url);
    const data = await resp.json();
    const fetched = data.events || [];
    // Separate metadata and notes
    notes = [];
    for (const e of fetched) {
      if (e.kind === 0) {
        try { metadataCache[e.pubkey] = JSON.parse(e.content); } catch(_) {}
      } else {
        notes.push(e);
      }
    }
    renderNotes();
  } catch (err) {
    console.error('Sort fetch error:', err);
  }
}


// ---- Header Account Link ----
function updateHeaderLink() {
  const link = document.getElementById('header-account-link');
  if (!link) return;
  if (isLoggedIn()) {
    const meta = metadataCache[userPubkey];
    const name = (meta && (meta.name || meta.display_name)) || userPubkey.slice(0, 8) + '...';
    link.textContent = name;
    link.style.color = 'var(--accent)';
  } else {
    link.textContent = 'Identity';
    link.style.color = '';
  }
}

// ---- Init ----
document.getElementById('clear-reply-btn')?.addEventListener('click', clearReplyState);
document.getElementById('feed-clankfeed')?.addEventListener('click', () => setFeed('clankfeed'));
document.getElementById('feed-external')?.addEventListener('click', () => setFeed('external'));
document.getElementById('sort-newest')?.addEventListener('click', () => setSort('newest'));
document.getElementById('sort-value')?.addEventListener('click', () => setSort('value'));
document.getElementById('apply-filters-btn')?.addEventListener('click', applyFilters);
document.getElementById('clear-filters-btn')?.addEventListener('click', clearFilters);
document.getElementById('filter-since')?.addEventListener('change', () => {
  const sinceEl = document.getElementById('filter-since');
  filterSinceKey = (sinceEl && sinceEl.value) || DEFAULT_SINCE;
  const clearBtn = document.getElementById('clear-filters-btn');
  if (clearBtn) {
    clearBtn.style.display = filtersAreDefault() ? 'none' : 'inline';
  }
  setSort(currentSort);
});
document.getElementById('notes-feed')?.addEventListener('click', handleFeedAction);

connect();
updateHeaderLink();
hydrateOwnProfile();
setTimeout(updateHeaderLink, 500);
setFeed('clankfeed');  // load clankfeed-only feed via REST (origin=clankfeed)

// Fetch relay info for pubkey display + zap fee config (cache: no-store avoids
// serving cached HTML when Accept negotiates NIP-11 JSON on the same URL)
fetch('/', { headers: { 'Accept': 'application/nostr+json' }, cache: 'no-store' })
  .then(async r => {
    const ct = (r.headers.get('content-type') || '').toLowerCase();
    if (!ct.includes('json') && !ct.includes('nostr+json')) {
      throw new Error('NIP-11 expected JSON, got ' + (ct || 'unknown'));
    }
    return r.json();
  })
  .then(info => {
    if (info.pubkey) {
      relayPubkey = info.pubkey;
      document.getElementById('relay-pubkey').textContent =
        'relay: ' + info.pubkey.slice(0, 12) + '...';
      renderNotes();  // re-render with 'anon' labels
      updateHeaderLink();  // update with user's display name if available
    }
    if (info.lud16) relayLud16 = info.lud16;
    const fees = info.zap_fees || info.zapFees;
    if (fees && typeof fees === 'object') {
      zapFeeConfig = {
        authorWeight: fees.author_weight || fees.authorWeight || 9,
        relayWeight: fees.relay_weight || fees.relayWeight || 1,
        relayUrl: fees.relay_url || fees.relayUrl || '',
      };
    }
  })
  .catch(e => console.error('NIP-11 fetch failed:', e));