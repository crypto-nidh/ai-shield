"""
Tests for the Pattern Matcher (rule-based heuristic scanner).
Tests each heuristic rule independently and combined scoring.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.pattern_matcher import calculate_threat_score


class TestCalculateThreatScore:
    """Test the main scoring function."""

    def test_empty_text(self):
        """Empty text should return zero score."""
        result = calculate_threat_score("")
        assert result["score"] == 0.0
        assert result["threat_level"] == "low"
        assert len(result["matched_rules"]) == 0

    def test_none_text(self):
        """None should return zero score."""
        result = calculate_threat_score(None)
        assert result["score"] == 0.0

    def test_safe_text(self):
        """Normal text should have low threat score."""
        result = calculate_threat_score(
            "Hey team, can we reschedule the standup to 10am? "
            "I have a dentist appointment."
        )
        assert result["threat_level"] == "low"
        assert result["score"] < 30

    def test_result_structure(self):
        """Result should have required fields."""
        result = calculate_threat_score("Test text")
        assert "score" in result
        assert "threat_level" in result
        assert "matched_rules" in result
        assert "explanation" in result

    def test_score_range(self):
        """Score should be between 0 and 100."""
        texts = [
            "Hello, how are you?",
            "URGENT: Verify your account immediately!",
            "Click here to update your password now!",
        ]
        for text in texts:
            result = calculate_threat_score(text)
            assert 0 <= result["score"] <= 100


class TestUrgencyDetection:
    """Test urgency keyword detection."""

    def test_act_now(self):
        """Should detect 'act now' urgency."""
        result = calculate_threat_score("You must act now to avoid account suspension!")
        matches = [m for m in result["matched_rules"] if m["rule"] == "urgency_keyword"]
        assert len(matches) > 0

    def test_within_24_hours(self):
        """Should detect time pressure."""
        result = calculate_threat_score(
            "Your account will be closed within 24 hours. "
            "Verify your account immediately."
        )
        matches = [m for m in result["matched_rules"] if m["rule"] == "urgency_keyword"]
        assert len(matches) >= 2

    def test_no_urgency_in_normal_text(self):
        """Normal text should not trigger urgency rules."""
        result = calculate_threat_score(
            "Looking forward to our meeting next week. "
            "Let me know if you need anything."
        )
        matches = [m for m in result["matched_rules"] if m["rule"] == "urgency_keyword"]
        assert len(matches) == 0


class TestSuspiciousURLs:
    """Test suspicious URL pattern detection."""

    def test_ip_address_url(self):
        """Should detect IP-based URLs."""
        result = calculate_threat_score(
            "Please visit http://192.168.1.100/login to verify."
        )
        matches = [m for m in result["matched_rules"] if m["rule"] == "suspicious_url"]
        assert len(matches) > 0

    def test_url_shortener(self):
        """Should detect URL shorteners."""
        result = calculate_threat_score(
            "Click this link: https://bit.ly/3xAbCdE"
        )
        matches = [m for m in result["matched_rules"] if m["rule"] == "suspicious_url"]
        assert len(matches) > 0

    def test_lookalike_domain(self):
        """Should detect typosquatting domains."""
        result = calculate_threat_score(
            "Login at https://paypa1.com/secure/login"
        )
        matches = [m for m in result["matched_rules"] if m["rule"] == "suspicious_url"]
        assert len(matches) > 0

    def test_normal_url_not_flagged(self):
        """Normal URLs should not be flagged."""
        result = calculate_threat_score(
            "Check out https://docs.python.org/3/tutorial/"
        )
        matches = [m for m in result["matched_rules"] if m["rule"] == "suspicious_url"]
        assert len(matches) == 0


class TestImpersonation:
    """Test brand/CEO impersonation detection."""

    def test_ceo_wire_transfer(self):
        """Should detect CEO impersonation with money transfer request."""
        result = calculate_threat_score(
            "From the CEO: Please wire transfer the funds immediately to this account. "
            "Don't tell anyone about this confidential transaction."
        )
        matches = [m for m in result["matched_rules"] if m["rule"] == "ceo_impersonation"]
        assert len(matches) > 0

    def test_gift_card_scam(self):
        """Should detect gift card scam patterns."""
        result = calculate_threat_score(
            "I need you to buy 4 Apple gift cards worth $500 each."
        )
        matches = [m for m in result["matched_rules"] if m["rule"] == "ceo_impersonation"]
        assert len(matches) > 0


class TestCredentialHarvesting:
    """Test credential harvesting detection."""

    def test_password_request(self):
        """Should detect requests for passwords."""
        result = calculate_threat_score(
            "Please enter your password to verify your identity. "
            "Confirm your account immediately."
        )
        matches = [m for m in result["matched_rules"] if m["rule"] == "credential_harvesting"]
        assert len(matches) > 0

    def test_ssn_request(self):
        """Should detect requests for SSN."""
        result = calculate_threat_score(
            "Please provide your Social Security Number for account verification. "
            "Verify your identity within 24 hours."
        )
        matches = [m for m in result["matched_rules"] if m["rule"] == "credential_harvesting"]
        assert len(matches) > 0


class TestThreatLevels:
    """Test that threat levels map correctly."""

    def test_low_threat(self):
        """Innocuous text should be low threat."""
        result = calculate_threat_score("Thanks for the update!")
        assert result["threat_level"] == "low"

    def test_high_threat(self):
        """Text with many red flags should be high threat."""
        result = calculate_threat_score(
            "URGENT: Your Bank of America account has been compromised! "
            "Act now to verify your identity within 24 hours. "
            "Click here: https://bankofamerica-secure-verify.com/login "
            "Please provide your password and Social Security Number immediately. "
            "Your account will be suspended. Verify your account now."
        )
        assert result["threat_level"] in ("medium", "high")
