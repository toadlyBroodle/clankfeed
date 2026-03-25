"""Tests for BTC/USD rate conversion."""

import pytest
from app.rates import usd_to_sats


class TestUsdToSats:
    def test_basic_conversion(self):
        # $1 at $100k/BTC = 1000 sats
        assert usd_to_sats(1.0, 100_000.0) == 1000

    def test_small_amount(self):
        # $0.01 at $100k/BTC = 10 sats
        assert usd_to_sats(0.01, 100_000.0) == 10

    def test_larger_amount(self):
        # $10 at $50k/BTC = 20000 sats
        assert usd_to_sats(10.0, 50_000.0) == 20000

    def test_zero_usd(self):
        assert usd_to_sats(0.0, 100_000.0) == 0

    def test_zero_price(self):
        assert usd_to_sats(1.0, 0.0) == 0

    def test_negative_price(self):
        assert usd_to_sats(1.0, -50000.0) == 0

    def test_negative_usd(self):
        assert usd_to_sats(-1.0, 100_000.0) == 0

    def test_fractional_sats_truncated(self):
        # $0.001 at $100k = 1 sat (truncated from 1.0)
        assert usd_to_sats(0.001, 100_000.0) == 1

    def test_sub_sat_returns_zero(self):
        # $0.0001 at $100k = 0.1 sats -> truncated to 0
        assert usd_to_sats(0.0001, 100_000.0) == 0
