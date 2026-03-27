/**
 * Shared payment widget for clankfeed.
 * Injects a full payment UI (Lightning QR + Tempo tabs) into the page.
 * Requires: nostr-auth.js (payInvoice, esc), QRious CDN.
 *
 * Usage:
 *   showPaymentWidget(data, onConfirm, onCancel, anchorEl)
 *   - data: server response with token, bolt11/lightning, tempo, methods
 *   - onConfirm(token, paymentId, method): called after payment confirmed
 *   - onCancel: called when user clicks Cancel
 *   - anchorEl: DOM element to insert widget after (optional)
 */

let _pw_currentData = null;
let _pw_currentBolt11 = '';
let _pw_activeMethod = 'lightning';

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
      <button id="pw-tab-ln" class="px-3 py-1 rounded bg-primary" onclick="_pwSwitchTab('lightning')">Lightning</button>
      <button id="pw-tab-tempo" class="hidden px-3 py-1 rounded bg-alt" onclick="_pwSwitchTab('tempo')">Tempo (USD)</button>
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
  `;
  document.body.appendChild(div);  // temporary; moved by showPaymentWidget
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

  // Tempo fields
  if (data.tempo) {
    document.getElementById('pw-tempo-amount').textContent = data.tempo.amount_usd + ' USD';
    document.getElementById('pw-tempo-recipient').textContent = data.tempo.recipient;
    document.getElementById('pw-tempo-token').textContent = data.tempo.currency.slice(0, 10) + '...' + data.tempo.currency.slice(-4);
    document.getElementById('pw-tempo-network').textContent = data.tempo.testnet ? '(testnet)' : '(mainnet)';
    document.getElementById('pw-tempo-tx').value = '';
    document.getElementById('pw-tempo-status').textContent = '';
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

  // Lightning: use shared payInvoice (BC wallet first, QR + poll fallback)
  const lnStatus = document.getElementById('pw-ln-status');
  if (methods.includes('lightning') && _pw_currentBolt11) {
    payInvoice(_pw_currentBolt11, payHash, lnStatus, async () => {
      if (onConfirm) await onConfirm(data.token, payHash, 'lightning');
    }, document.getElementById('pw-qr'), document.getElementById('pw-bolt11'));
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
  if (ln) ln.classList.toggle('hidden', method !== 'lightning');
  if (tempo) tempo.classList.toggle('hidden', method !== 'tempo');
  const lnTab = document.getElementById('pw-tab-ln');
  const tempoTab = document.getElementById('pw-tab-tempo');
  if (lnTab) {
    const lnHidden = lnTab.classList.contains('hidden');
    lnTab.className = (lnHidden ? 'hidden ' : '') + (method === 'lightning' ? 'px-3 py-1 rounded bg-primary' : 'px-3 py-1 rounded bg-alt');
  }
  if (tempoTab) {
    const tempoHidden = tempoTab.classList.contains('hidden');
    tempoTab.className = (tempoHidden ? 'hidden ' : '') + (method === 'tempo' ? 'px-3 py-1 rounded bg-primary' : 'px-3 py-1 rounded bg-alt');
  }
}
