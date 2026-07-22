"""Phase 15.1 / 15.5: receive-only LNBits wallet contract + pay-once docs."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _py_sources(*rel_paths: str) -> list[Path]:
    return [ROOT / p for p in rel_paths]


class TestReceiveOnlyLightningCode:
    """Guardrail: lightning helpers only mint invoices / poll status — never spend."""

    def test_lightning_module_has_no_out_true_pay(self):
        src = (ROOT / "app" / "lightning.py").read_text()
        assert '"out": True' not in src
        assert "'out': True" not in src
        # Invoice create must be receive-only
        assert '"out": False' in src or "'out': False" in src

    def test_lightning_and_l402_have_no_pay_invoice_helper(self):
        banned_names = {
            "pay_invoice",
            "pay_bolt11",
            "withdraw",
            "transfer",
            "send_payment",
        }
        for path in _py_sources("app/lightning.py", "app/l402.py"):
            tree = ast.parse(path.read_text())
            defined = {
                n.name
                for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            overlap = defined & banned_names
            assert not overlap, f"{path.name} defines spend helpers: {overlap}"

    def test_lightning_only_hits_invoice_and_status_endpoints(self):
        """POST /api/v1/payments is allowed only for invoice create (out:False)."""
        src = (ROOT / "app" / "lightning.py").read_text()
        # No LNBits payments list / decode / fee-reserve spend paths
        for banned in (
            "/api/v1/payments/lnurl",
            "/api/v1/payments/fee-reserve",
            "admin/api",
        ):
            assert banned not in src


class TestReceiveOnlyDocs:
    def test_env_example_inkey_receive_only(self):
        text = (ROOT / ".env.example").read_text().lower()
        assert "inkey" in text or "receive-only" in text or "receive only" in text
        assert "adminkey" in text  # must warn never to use it
        assert "payment_key" in text

    def test_claude_md_receive_only_wallet(self):
        text = (ROOT / "CLAUDE.md").read_text().lower()
        assert "receive-only" in text or "receive only" in text or "inkey" in text
        assert "clankfeed" in text
        # Must not still claim shared satring wallet as the live model
        assert "same lnbits wallet as satring" not in text

    def test_readme_pay_once_outbox(self):
        readme = (ROOT / "README.md").read_text()
        lower = readme.lower()
        assert "outbox" in lower
        assert "pay once" in lower or "pay-once" in lower or "paying once" in lower
        assert "receive-only" in lower or "receive only" in lower or "inkey" in lower
        assert "nwc" in lower
        assert "botfeed" in lower
        assert "clankwright.com" in lower  # lud16 host — no lnurlp on clankfeed.com

    def test_api_md_pay_once_outbox(self):
        api = (ROOT / "docs" / "API.md").read_text()
        lower = api.lower()
        assert "outbox" in lower
        assert "receive-only" in lower or "receive only" in lower or "inkey" in lower
        assert "nwc" in lower
