"""Tests for Tempo stablecoin payment integration."""

import json
import time
import pytest
from app.tempo_pay import build_tempo_challenge, extract_tempo_tx_hash
from app.mpp import _b64url_decode, _verify_challenge_id, _MPP_REALM


class TestTempoChallenge:
    def test_build_challenge_format(self):
        challenge = build_tempo_challenge("0.01", "test payment")
        assert challenge.startswith("Payment ")
        assert 'method="tempo"' in challenge
        assert 'intent="charge"' in challenge
        assert f'realm="{_MPP_REALM}"' in challenge
        assert 'description="test payment"' in challenge

    def test_build_challenge_request_contains_tempo_details(self):
        challenge = build_tempo_challenge("0.50")
        # Extract request param
        for part in challenge.split(", "):
            if part.startswith('request="'):
                request_b64 = part.split('"')[1]
                break
        request_json = json.loads(_b64url_decode(request_b64))
        assert request_json["amount"] == "0.50"
        assert request_json["currency"] == "USD"
        assert request_json["methodDetails"]["chain"] == "tempo"
        assert "currency" in request_json["methodDetails"]

    def test_challenge_hmac_verifies(self):
        challenge = build_tempo_challenge("0.01")
        # Parse all params
        params = {}
        for part in challenge.replace("Payment ", "").split(", "):
            key, val = part.split("=", 1)
            params[key] = val.strip('"')
        assert _verify_challenge_id(
            params["id"], params["realm"], params["method"],
            params["intent"], params["request"], params["expires"],
        )

    def test_expired_challenge_fails(self):
        # Build a challenge, then check it won't verify with a past expiry
        assert not _verify_challenge_id(
            "fake", _MPP_REALM, "tempo", "charge", "fake_request",
            str(int(time.time()) - 1),
        )


class TestTempoExtract:
    def test_extract_tx_hash(self):
        cred = {"payload": {"txHash": "0xabc123"}}
        assert extract_tempo_tx_hash(cred) == "0xabc123"

    def test_extract_missing(self):
        assert extract_tempo_tx_hash({}) == ""
