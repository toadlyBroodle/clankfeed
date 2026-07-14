"""13.1: NIP-57 zap fee-split config defaults + env docs."""

from pathlib import Path

from app import config

_ROOT = Path(__file__).resolve().parents[1]
_ENV_EXAMPLE = (_ROOT / ".env.example").read_text()
_README = (_ROOT / "README.md").read_text()
_CONFIG_SRC = (_ROOT / "app" / "config.py").read_text()


class TestZapFeeConfig131:
    """ZAP_AUTHOR_WEIGHT / ZAP_RELAY_WEIGHT / RELAY_LUD16 must exist with Phase 13 defaults."""

    def test_zap_author_weight_default_is_9(self):
        assert hasattr(config.settings, "ZAP_AUTHOR_WEIGHT")
        assert config.settings.ZAP_AUTHOR_WEIGHT == 9
        assert isinstance(config.settings.ZAP_AUTHOR_WEIGHT, int)

    def test_zap_relay_weight_default_is_1(self):
        assert hasattr(config.settings, "ZAP_RELAY_WEIGHT")
        assert config.settings.ZAP_RELAY_WEIGHT == 1
        assert isinstance(config.settings.ZAP_RELAY_WEIGHT, int)

    def test_relay_lud16_is_str_attr(self):
        """RELAY_LUD16 is a string setting (empty until prod sets the lightning address)."""
        assert hasattr(config.settings, "RELAY_LUD16")
        assert isinstance(config.settings.RELAY_LUD16, str)

    def test_weight_ratio_is_nine_to_one(self):
        """Locked product rule: 90/10 fee → author weight 9, relay weight 1."""
        total = config.settings.ZAP_AUTHOR_WEIGHT + config.settings.ZAP_RELAY_WEIGHT
        assert total == 10
        assert config.settings.ZAP_AUTHOR_WEIGHT == 9 * config.settings.ZAP_RELAY_WEIGHT

    def test_adversarial_weights_are_positive(self):
        """Zero/negative weights would break NIP-57 split math; defaults must be > 0."""
        assert config.settings.ZAP_AUTHOR_WEIGHT > 0
        assert config.settings.ZAP_RELAY_WEIGHT > 0

    def test_config_source_reads_env_with_phase13_defaults(self):
        """Hardcoding without getenv would ignore operator overrides — require env wiring."""
        assert 'os.getenv("ZAP_AUTHOR_WEIGHT", "9")' in _CONFIG_SRC
        assert 'os.getenv("ZAP_RELAY_WEIGHT", "1")' in _CONFIG_SRC
        assert 'os.getenv("RELAY_LUD16", "")' in _CONFIG_SRC


class TestZapFeeEnvDocs131:
    """Operators must discover the three vars in .env.example and README."""

    def test_env_example_documents_zap_weights_and_relay_lud16(self):
        for key in ("ZAP_AUTHOR_WEIGHT", "ZAP_RELAY_WEIGHT", "RELAY_LUD16"):
            assert key in _ENV_EXAMPLE, f".env.example must document {key}"
        assert "ZAP_AUTHOR_WEIGHT=9" in _ENV_EXAMPLE
        assert "ZAP_RELAY_WEIGHT=1" in _ENV_EXAMPLE
        assert "RELAY_LUD16=" in _ENV_EXAMPLE

    def test_readme_documents_zap_fee_env_vars(self):
        for key in ("ZAP_AUTHOR_WEIGHT", "ZAP_RELAY_WEIGHT", "RELAY_LUD16"):
            assert f"`{key}`" in _README or key in _README, (
                f"README env table must document {key}"
            )

    def test_adversarial_comment_only_env_example_does_not_count(self):
        """A '# ZAP_AUTHOR_WEIGHT=9' comment must not satisfy the docs gate."""
        uncommented = [
            line
            for raw in _ENV_EXAMPLE.splitlines()
            if (line := raw.strip()) and not line.startswith("#")
        ]
        joined = "\n".join(uncommented)
        assert "ZAP_AUTHOR_WEIGHT=9" in joined
        assert "ZAP_RELAY_WEIGHT=1" in joined
        assert any(line.startswith("RELAY_LUD16=") for line in uncommented)
