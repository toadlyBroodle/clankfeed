/**
 * Shared payment widget for clankfeed.
 * Injects a full payment UI (Lightning QR + Tempo + Stripe tabs) into the page.
 * Requires: nostr-auth.js (payInvoice, esc, buildStripePaymentAuth), QRious CDN.
 *
 * Usage:
 *   showPaymentWidget(data, onConfirm, onCancel, anchorEl)
 *   - data: server response with token, bolt11/lightning, tempo, stripe, methods
 *   - onConfirm(token, paymentId, method): called after payment confirmed
 *   - onCancel: called when user clicks Cancel
 *   - anchorEl: DOM element to insert widget after (optional)
 */

let _pw_currentData = null;
let _pw_currentBolt11 = '';
let _pw_activeMethod = 'lightning';
let _pw_stripe = null;
let _pw_stripeCard = null;
let _pw_stripeMounting = false;

function _ensureWidgetDOM() {
  if (document.getElementById('pw-widget')) return;
  const div = document.createElement('div');
  div.id = 'pw-widget';
  div.className = 'hidden mt-4 p-4 rounded b-accent';
  div.innerHTML = `
    <div class="flex justify-between items-center mb-2">
      <p class="text-sm c-accent" id="pw-title">Payment required</p>
      <button class="text-xs px-2 py-1 rounded bg-alt" id="pw-cancel-btn">Cancel</button>
    </div>
    <div id="pw-tabs" class="flex gap-2 mb-3 text-xs">
      <button id="pw-tab-ln" class="px-3 py-1 rounded bg-primary">Lightning</button>
      <button id="pw-tab-tempo" class="hidden px-3 py-1 rounded bg-alt">Tempo (USD)</button>
      <button id="pw-tab-stripe" class="hidden px-3 py-1 rounded bg-alt">Card (Stripe)</button>
    </div>
    <div id="pw-lightning">
      <div class="flex gap-4 items-start">
        <canvas id="pw-qr" width="160" height="160"></canvas>
        <div class="flex-1">
          <p class="text-xs mb-1 c-dim">Lightning Invoice:</p>
          <div class="flex items-center gap-1">
            <code id="pw-bolt11" class="text-xs break-all c-text"></code>
          </div>
          <p class="text-xs mt-2 c-dim" id="pw-ln-status">Waiting for payment...</p>
        </div>
      </div>
    </div>
    <div id="pw-tempo" class="hidden">
      <div class="text-xs space-y-2">
        <p class="c-dim">Send <span id="pw-tempo-amount" class="c-accent"></span> to:</p>
        <div class="flex items-center gap-1">
          <code id="pw-tempo-recipient" class="text-xs break-all c-text"></code>
          <span class="copy-btn text-xs" id="pw-tempo-copy">[copy]</span>
        </div>
        <p class="c-dim">Token: <span id="pw-tempo-token" class="c-text"></span></p>
        <p class="c-dim">Chain: Tempo <span id="pw-tempo-network"></span></p>
        <div class="mt-2">
          <label class="block mb-1 c-dim">Paste tx hash after sending:</label>
          <div class="flex gap-2">
            <input id="pw-tempo-tx" type="text" class="p-2 rounded text-xs flex-1" placeholder="0x...">
            <button class="px-3 py-1 rounded text-xs" id="pw-tempo-confirm-btn">Confirm</button>
          </div>
        </div>
        <p class="text-xs c-dim" id="pw-tempo-status"></p>
      </div>
    </div>
    <div id="pw-stripe" class="hidden">
      <div class="text-xs space-y-2">
        <p class="c-dim">Pay <span id="pw-stripe-amount" class="c-accent"></span> with card:</p>
        <div id="pw-stripe-card" class="p-2 rounded" style="background:#111;min-height:40px;border:1px solid var(--border);"></div>
        <div class="flex gap-2 items-center">
          <button class="px-3 py-1 rounded text-xs" id="pw-stripe-pay-btn">Pay with card</button>
        </div>
        <div class="mt-2">
          <label class="block mb-1 c-dim">Or paste SPT (agents):</label>
          <div class="flex gap-2">
            <input id="pw-stripe-spt" type="text" class="p-2 rounded text-xs flex-1" placeholder="spt_...">
            <button class="px-3 py-1 rounded text-xs" id="pw-stripe-spt-btn">Confirm SPT</button>
          </div>
        </div>
        <p class="text-xs c-dim" id="pw-stripe-status"></p>
      </div>
    </div>
  `;
  document.body.appendChild(div);  // temporary; moved by showPaymentWidget
  document.getElementById('pw-tab-ln').addEventListener('click', () => _pwSwitchTab('lightning'));
  document.getElementById('pw-tab-tempo').addEventListener('click', () => _pwSwitchTab('tempo'));
  document.getElementById('pw-tab-stripe').addEventListener('click', () => _pwSwitchTab('stripe'));
}

function _loadStripeJs() {
  return new Promise((resolve, reject) => {
    if (window.Stripe) return resolve(window.Stripe);
    const existing = document.querySelector('script[data-cf-stripe]');
    if (existing) {
      existing.addEventListener('load', () => resolve(window.Stripe));
      existing.addEventListener('error', () => reject(new Error('Stripe.js failed to load')));
      return;
    }
    const s = document.createElement('script');
    s.src = 'https://js.stripe.com/v3/';
    s.async = true;
    s.setAttribute('data-cf-stripe', '1');
    s.onload = () => resolve(window.Stripe);
    s.onerror = () => reject(new Error('Stripe.js failed to load'));
    document.head.appendChild(s);
  });
}

async function _pwMountStripeCard(data) {
  const statusEl = document.getElementById('pw-stripe-status');
  const mountEl = document.getElementById('pw-stripe-card');
  if (!data || !data.stripe || !data.stripe.publishable_key) {
    if (statusEl) statusEl.textContent = 'Stripe publishable key missing';
    return;
  }
  if (_pw_stripeCard || _pw_stripeMounting) return;
  _pw_stripeMounting = true;
  try {
    const StripeCtor = await _loadStripeJs();
    _pw_stripe = StripeCtor(data.stripe.publishable_key);
    const elements = _pw_stripe.elements();
    _pw_stripeCard = elements.create('card', {
      style: {
        base: { color: '#4ade80', '::placeholder': { color: '#666' }, fontSize: '14px' },
        invalid: { color: '#f87171' },
      },
    });
    if (mountEl) {
      mountEl.innerHTML = '';
      _pw_stripeCard.mount('#pw-stripe-card');
    }
    if (statusEl) {
      statusEl.textContent = '';
      statusEl.style.color = 'var(--dim)';
    }
  } catch (err) {
    if (statusEl) {
      statusEl.textContent = (err && err.message) || 'Failed to load Stripe';
      statusEl.style.color = 'var(--error)';
    }
  } finally {
    _pw_stripeMounting = false;
  }
}

function showPaymentWidget(data, onConfirm, onCancel, anchorEl) {
  _ensureWidgetDOM();
  const widget = document.getElementById('pw-widget');
  _pw_currentData = data;
  _pw_currentBolt11 = data.bolt11 || (data.lightning && data.lightning.bolt11) || '';
  const methods = data.methods || [];
  const payHash = data.payment_hash || (data.lightning && data.lightning.payment_hash) || '';

  // Move widget to anchor position
  if (anchorEl) {
    anchorEl.parentNode.insertBefore(widget, anchorEl.nextSibling);
  }

  widget.classList.remove('hidden');

  // Title
  const title = document.getElementById('pw-title');
  if (data._title) {
    title.textContent = data._title;
  } else {
    title.textContent = 'Payment required';
  }

  // Tabs
  document.getElementById('pw-tab-ln').classList.toggle('hidden', !methods.includes('lightning'));
  document.getElementById('pw-tab-tempo').classList.toggle('hidden', !methods.includes('tempo'));
  document.getElementById('pw-tab-stripe').classList.toggle('hidden', !methods.includes('stripe'));

  // Tempo fields
  if (data.tempo) {
    document.getElementById('pw-tempo-amount').textContent = data.tempo.amount_usd + ' USD';
    document.getElementById('pw-tempo-recipient').textContent = data.tempo.recipient;
    document.getElementById('pw-tempo-token').textContent = data.tempo.currency.slice(0, 10) + '...' + data.tempo.currency.slice(-4);
    document.getElementById('pw-tempo-network').textContent = data.tempo.testnet ? '(testnet)' : '(mainnet)';
    document.getElementById('pw-tempo-tx').value = '';
    document.getElementById('pw-tempo-status').textContent = '';
  }

  // Stripe fields
  if (data.stripe) {
    document.getElementById('pw-stripe-amount').textContent =
      (data.stripe.amount_usd || '') + ' USD';
    document.getElementById('pw-stripe-spt').value = '';
    document.getElementById('pw-stripe-status').textContent = '';
    // Unmount previous card element when re-showing
    if (_pw_stripeCard) {
      try { _pw_stripeCard.destroy(); } catch (e) {}
      _pw_stripeCard = null;
      _pw_stripe = null;
    }
  }

  _pwSwitchTab(methods[0] || 'lightning');

  // Cancel button
  document.getElementById('pw-cancel-btn').onclick = () => {
    hidePaymentWidget();
    if (onCancel) onCancel();
  };

  // Tempo confirm
  document.getElementById('pw-tempo-confirm-btn').onclick = async () => {
    const txHash = document.getElementById('pw-tempo-tx').value.trim();
    const statusEl = document.getElementById('pw-tempo-status');
    if (!txHash || !txHash.startsWith('0x')) {
      statusEl.textContent = 'Enter a valid tx hash (0x...)';
      statusEl.style.color = 'var(--error)';
      return;
    }
    statusEl.textContent = 'Verifying on-chain...';
    statusEl.style.color = 'var(--dim)';
    if (onConfirm) await onConfirm(data.token, txHash, 'tempo');
  };

  // Tempo copy
  document.getElementById('pw-tempo-copy').onclick = () => {
    if (!data.tempo) return;
    navigator.clipboard.writeText(data.tempo.recipient);
    const btn = document.getElementById('pw-tempo-copy');
    btn.textContent = '[copied!]';
    setTimeout(() => btn.textContent = '[copy]', 1500);
  };

  // Stripe: card pay via Elements → /api/v1/payments/stripe-spt → onConfirm(spt)
  document.getElementById('pw-stripe-pay-btn').onclick = async () => {
    const statusEl = document.getElementById('pw-stripe-status');
    if (!_pw_stripe || !_pw_stripeCard) {
      statusEl.textContent = 'Card form not ready — switch to Card tab again';
      statusEl.style.color = 'var(--error)';
      return;
    }
    statusEl.textContent = 'Creating payment method...';
    statusEl.style.color = 'var(--dim)';
    try {
      const { paymentMethod, error } = await _pw_stripe.createPaymentMethod({
        type: 'card',
        card: _pw_stripeCard,
      });
      if (error) {
        statusEl.textContent = error.message || 'Card error';
        statusEl.style.color = 'var(--error)';
        return;
      }
      statusEl.textContent = 'Minting SPT...';
      const resp = await fetch('/api/v1/payments/stripe-spt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: JSON.stringify({ payment_method: paymentMethod.id }),
      });
      const body = await resp.json().catch(() => ({}));
      if (!resp.ok || !body.spt) {
        statusEl.textContent = (typeof body.detail === 'string' ? body.detail : null)
          || 'SPT mint failed';
        statusEl.style.color = 'var(--error)';
        return;
      }
      statusEl.textContent = 'Confirming...';
      statusEl.style.color = 'var(--accent)';
      if (onConfirm) await onConfirm(data.token, body.spt, 'stripe');
    } catch (err) {
      statusEl.textContent = (err && err.message) || 'Stripe pay failed';
      statusEl.style.color = 'var(--error)';
    }
  };

  // Stripe: paste SPT (agents)
  document.getElementById('pw-stripe-spt-btn').onclick = async () => {
    const spt = document.getElementById('pw-stripe-spt').value.trim();
    const statusEl = document.getElementById('pw-stripe-status');
    if (!spt || !spt.startsWith('spt_')) {
      statusEl.textContent = 'Enter a valid SPT (spt_...)';
      statusEl.style.color = 'var(--error)';
      return;
    }
    statusEl.textContent = 'Confirming SPT...';
    statusEl.style.color = 'var(--dim)';
    if (onConfirm) await onConfirm(data.token, spt, 'stripe');
  };

  // Lightning: auto-pay via BC when onConfirm provided; else QR display only (L402 caller settles)
  const lnStatus = document.getElementById('pw-ln-status');
  if (methods.includes('lightning') && _pw_currentBolt11) {
    if (onConfirm) {
      payInvoice(_pw_currentBolt11, payHash, lnStatus, async (preimage) => {
        if (onConfirm) await onConfirm(data.token, payHash, 'lightning', preimage);
      }, document.getElementById('pw-qr'), document.getElementById('pw-bolt11'));
    } else {
      // Show QR for visibility while caller runs payL402AndRetry
      const qr = document.getElementById('pw-qr');
      const boltEl = document.getElementById('pw-bolt11');
      if (qr) {
        new QRious({ element: qr, value: _pw_currentBolt11.toUpperCase(), size: 160, foreground: '#4ade80', background: '#000', level: 'L' });
      }
      if (boltEl) boltEl.textContent = _pw_currentBolt11.slice(0, 40) + '...';
      lnStatus.textContent = 'Pay via wallet (L402)...';
      lnStatus.style.color = 'var(--dim)';
    }
  } else {
    lnStatus.textContent = '';
  }
}

function hidePaymentWidget() {
  const widget = document.getElementById('pw-widget');
  if (widget) widget.classList.add('hidden');
  if (typeof _payPollTimer !== 'undefined' && _payPollTimer) {
    clearInterval(_payPollTimer);
    _payPollTimer = null;
  }
}

function _pwSwitchTab(method) {
  _pw_activeMethod = method;
  const ln = document.getElementById('pw-lightning');
  const tempo = document.getElementById('pw-tempo');
  const stripe = document.getElementById('pw-stripe');
  if (ln) ln.classList.toggle('hidden', method !== 'lightning');
  if (tempo) tempo.classList.toggle('hidden', method !== 'tempo');
  if (stripe) stripe.classList.toggle('hidden', method !== 'stripe');
  const lnTab = document.getElementById('pw-tab-ln');
  const tempoTab = document.getElementById('pw-tab-tempo');
  const stripeTab = document.getElementById('pw-tab-stripe');
  if (lnTab) {
    const lnHidden = lnTab.classList.contains('hidden');
    lnTab.className = (lnHidden ? 'hidden ' : '') + (method === 'lightning' ? 'px-3 py-1 rounded bg-primary' : 'px-3 py-1 rounded bg-alt');
  }
  if (tempoTab) {
    const tempoHidden = tempoTab.classList.contains('hidden');
    tempoTab.className = (tempoHidden ? 'hidden ' : '') + (method === 'tempo' ? 'px-3 py-1 rounded bg-primary' : 'px-3 py-1 rounded bg-alt');
  }
  if (stripeTab) {
    const stripeHidden = stripeTab.classList.contains('hidden');
    stripeTab.className = (stripeHidden ? 'hidden ' : '') + (method === 'stripe' ? 'px-3 py-1 rounded bg-primary' : 'px-3 py-1 rounded bg-alt');
  }
  if (method === 'stripe' && _pw_currentData) {
    _pwMountStripeCard(_pw_currentData);
  }
}
