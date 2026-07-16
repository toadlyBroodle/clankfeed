"""14.10: ops docs — LNBits = L402 invoice destination only; prod BASE_URL guidance."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ENV_EXAMPLE = (_ROOT / ".env.example").read_text()
_README = (_ROOT / "README.md").read_text()


class TestOpsL402EnvDocs1410:
    """Operators must learn LNBits is access-fee (L402) destination, not tip custody."""

    def test_env_example_documents_lnbits_as_l402_invoice_destination(self):
        """PAYMENT_URL/PAYMENT_KEY comments must state L402 invoice destination only."""
        lower = _ENV_EXAMPLE.lower()
        assert "payment_url" in lower and "payment_key" in lower
        assert "l402" in lower, ".env.example must mention L402 near LNBits vars"
        assert "invoice destination" in lower or "invoice-destination" in lower, (
            ".env.example must say LNBits wallet is the L402 invoice destination"
        )
        # Non-custodial: tips settle off our books
        assert "tip" in lower or "custod" in lower or "nips-57" in lower or "nip-57" in lower, (
            ".env.example must warn LNBits is not for tip custody / NIP-57 author remits"
        )

    def test_readme_documents_lnbits_l402_destination_and_prod_base_url(self):
        """README env table / ops notes must name L402 destination + prod wss BASE_URL."""
        assert "`PAYMENT_KEY`" in _README or "PAYMENT_KEY" in _README
        assert "`PAYMENT_URL`" in _README or "PAYMENT_URL" in _README
        lower = _README.lower()
        assert "l402" in lower
        assert "invoice destination" in lower or "invoice-destination" in lower
        assert "wss://clankfeed.com" in _README, (
            "README must document production BASE_URL=wss://clankfeed.com"
        )

    def test_adversarial_comment_only_l402_mention_does_not_count(self):
        """A bare '# L402' without invoice-destination wording must not satisfy the gate."""
        # Require the invoice-destination phrase on an uncommented or comment line
        # adjacent to PAYMENT_* — reject if the only L402 hit is unrelated prose.
        payment_block = []
        lines = _ENV_EXAMPLE.splitlines()
        for i, raw in enumerate(lines):
            if "PAYMENT_URL" in raw or "PAYMENT_KEY" in raw:
                start = max(0, i - 3)
                end = min(len(lines), i + 2)
                payment_block.extend(lines[start:end])
        block = "\n".join(payment_block).lower()
        assert "l402" in block, "L402 note must sit near PAYMENT_URL/PAYMENT_KEY"
        assert "invoice destination" in block or "invoice-destination" in block
