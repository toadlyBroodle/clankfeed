import { init, launchPaymentModal, onConnected } from 'https://esm.sh/@getalby/bitcoin-connect@3.12.2';
import { schnorr } from 'https://esm.sh/@noble/curves@1.8.1/secp256k1';
import { sha256 } from 'https://esm.sh/@noble/hashes@1.7.1/sha256';
import { bytesToHex, hexToBytes } from 'https://esm.sh/@noble/hashes@1.7.1/utils';
import { bech32 } from 'https://esm.sh/@scure/base@1.2.4';

init({ appName: 'clankfeed' });
window.__bcLaunchPaymentModal = launchPaymentModal;
window.__bcConnected = false;
onConnected((provider) => {
  window.__bcConnected = true;
  window.webln = provider;
});

/** Decode NIP-19 nsec1… → 32-byte Uint8Array. Throws on bad input. */
function decodeNsecBytes(nsec) {
  const { prefix, words } = bech32.decode(String(nsec).trim().toLowerCase(), 90);
  if (prefix !== 'nsec') throw new Error('not an nsec');
  const bytes = new Uint8Array(bech32.fromWords(words));
  if (bytes.length !== 32) throw new Error('nsec length');
  return bytes;
}

// Expose noble crypto to the global scope for Nostr signing + NIP-19 nsec
window.__nostrCrypto = {
  schnorr,
  sha256,
  bytesToHex,
  hexToBytes,
  getPublicKey: schnorr.getPublicKey,
  bech32,
  decodeNsecBytes,
};
