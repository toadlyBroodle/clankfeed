import { init, launchPaymentModal, onConnected } from 'https://esm.sh/@getalby/bitcoin-connect@3.12.2';
import { schnorr } from 'https://esm.sh/@noble/curves@1.8.1/secp256k1';
import { sha256 } from 'https://esm.sh/@noble/hashes@1.7.1/sha256';
import { bytesToHex, hexToBytes } from 'https://esm.sh/@noble/hashes@1.7.1/utils';

init({ appName: 'clankfeed' });
window.__bcLaunchPaymentModal = launchPaymentModal;
window.__bcConnected = false;
onConnected((provider) => {
  window.__bcConnected = true;
  window.webln = provider;
});

// Expose noble crypto to the global scope for Nostr signing
window.__nostrCrypto = { schnorr, sha256, bytesToHex, hexToBytes, getPublicKey: schnorr.getPublicKey };
