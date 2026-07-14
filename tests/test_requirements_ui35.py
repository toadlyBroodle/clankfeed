"""UI3.5: requirements.txt must list pytest-asyncio alongside playwright."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_REQ = (_ROOT / "requirements.txt").read_text()


def _req_lines() -> list[str]:
    """Non-empty, non-comment requirement lines (package name before any extras/version)."""
    lines = []
    for raw in _REQ.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def _pkg_name(line: str) -> str:
    """Strip extras and version pins: 'pytest-asyncio>=0.23' -> 'pytest-asyncio'."""
    name = line.split(";", 1)[0].strip()
    for sep in ("[", "==", ">=", "<=", "~=", "!=", ">"):
        if sep in name:
            name = name.split(sep, 1)[0].strip()
    return name.lower()


class TestRequirementsUI35:
    """Fresh `pip install -r requirements.txt` must run the async suite AND Playwright smoke."""

    def test_pytest_asyncio_is_listed(self):
        """UI3.4 dropped pytest-asyncio; restore it so async fixtures import."""
        names = {_pkg_name(line) for line in _req_lines()}
        assert "pytest-asyncio" in names, (
            "requirements.txt must include pytest-asyncio "
            "(tests import pytest_asyncio; fresh installs break without it)"
        )

    def test_playwright_is_listed(self):
        """Keep playwright for UI3.4 browser smoke; do not replace one with the other."""
        names = {_pkg_name(line) for line in _req_lines()}
        assert "playwright" in names, (
            "requirements.txt must keep playwright>=1.49.0 for feed UI smoke"
        )

    def test_adversarial_comment_only_does_not_count(self):
        """A commented-out '# pytest-asyncio' line must not satisfy the requirement."""
        # Reconstruct: only uncommented package lines count
        uncommented = [
            line
            for raw in _REQ.splitlines()
            if (line := raw.strip()) and not line.startswith("#")
        ]
        names = {_pkg_name(line) for line in uncommented}
        # If someone "fixes" by commenting, this still fails until a real line exists
        assert any(
            _pkg_name(line) == "pytest-asyncio" for line in uncommented
        ), "pytest-asyncio must be an active (uncommented) requirements line"
        assert "pytest-asyncio" in names
