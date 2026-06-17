"""
Tests for the AI Phishing Detector.
Tests both ML mode and rule-based fallback mode.
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_phishing_detector import (
    detect_ai_phishing,
    get_sample_emails,
    AI_PHISHING_EMAILS,
    HUMAN_EMAILS,
)


class TestDetectAIPhishing:
    """Test the main detect_ai_phishing function."""

    def test_empty_text_returns_safe(self):
        """Empty text should return not AI-generated."""
        result = detect_ai_phishing("")
        assert result["is_ai_generated"] is False
        assert result["confidence"] == 0.0
        assert result["threat_level"] == "low"

    def test_none_text_returns_safe(self):
        """None input should return not AI-generated."""
        result = detect_ai_phishing(None)
        assert result["is_ai_generated"] is False
        assert result["confidence"] == 0.0

    def test_whitespace_only_returns_safe(self):
        """Whitespace-only text should return safe."""
        result = detect_ai_phishing("   \n\t  ")
        assert result["is_ai_generated"] is False

    def test_short_text_returns_result(self):
        """Very short text should still return a valid result."""
        result = detect_ai_phishing("Hello there")
        assert "is_ai_generated" in result
        assert "confidence" in result
        assert "explanation" in result
        assert "threat_level" in result

    def test_result_has_required_fields(self, phishing_email_text):
        """Result should contain all required fields."""
        result = detect_ai_phishing(phishing_email_text)
        assert "is_ai_generated" in result
        assert "confidence" in result
        assert "explanation" in result
        assert "threat_level" in result
        assert "method_used" in result
        assert "details" in result

    def test_confidence_range(self, phishing_email_text):
        """Confidence should be between 0 and 100."""
        result = detect_ai_phishing(phishing_email_text)
        assert 0 <= result["confidence"] <= 100

    def test_threat_level_values(self, phishing_email_text):
        """Threat level should be one of the valid values."""
        result = detect_ai_phishing(phishing_email_text)
        assert result["threat_level"] in ("low", "medium", "high")

    def test_method_used_values(self, phishing_email_text):
        """Method should be 'ml', 'rules', 'combined', or 'none'."""
        result = detect_ai_phishing(phishing_email_text)
        assert result["method_used"] in ("ml", "rules", "combined", "none")

    def test_explanation_is_string(self, phishing_email_text):
        """Explanation should be a non-empty string."""
        result = detect_ai_phishing(phishing_email_text)
        assert isinstance(result["explanation"], str)
        assert len(result["explanation"]) > 0


class TestRulesOnlyMode:
    """Test phishing detection in rules-only mode (no ML model)."""

    def _detect_rules_only(self, text):
        """Force rules-only detection by mocking model unavailability."""
        with patch("ai_phishing_detector._load_model", return_value=False):
            with patch("ai_phishing_detector._pipeline", None):
                with patch("ai_phishing_detector._model_load_attempted", True):
                    return detect_ai_phishing(text)

    def test_phishing_email_detected(self, phishing_email_text):
        """Phishing email should be flagged even without ML model."""
        result = self._detect_rules_only(phishing_email_text)
        assert result["threat_level"] in ("medium", "high")
        assert result["confidence"] > 0

    def test_safe_email_low_score(self, safe_email_text):
        """Safe email should have low threat score."""
        result = self._detect_rules_only(safe_email_text)
        assert result["threat_level"] == "low"
        assert result["confidence"] < 50

    def test_rules_confidence_capped_at_70(self, phishing_email_text):
        """In rules-only mode, confidence should be capped at 70%."""
        result = self._detect_rules_only(phishing_email_text)
        assert result["confidence"] <= 70.0
        assert result["method_used"] == "rules"


class TestSampleEmails:
    """Test with the embedded sample emails."""

    def test_ai_phishing_samples_exist(self):
        """Should have 5 AI phishing sample emails."""
        assert len(AI_PHISHING_EMAILS) == 5

    def test_human_email_samples_exist(self):
        """Should have 5 human sample emails."""
        assert len(HUMAN_EMAILS) == 5

    def test_get_sample_emails_returns_both(self):
        """get_sample_emails should return both categories."""
        samples = get_sample_emails()
        assert "ai_phishing" in samples
        assert "human" in samples

    @pytest.mark.parametrize("email_key", [
        "bec_scam", "fake_bank", "fake_ceo", "urgency_scam", "credential_harvest",
    ])
    def test_phishing_samples_have_content(self, email_key):
        """Each phishing sample should have subject and body."""
        email = AI_PHISHING_EMAILS[email_key]
        assert "subject" in email
        assert "body" in email
        assert len(email["body"]) > 50

    @pytest.mark.parametrize("email_key", [
        "business_meeting", "newsletter", "friend_email",
        "order_receipt", "appointment_reminder",
    ])
    def test_human_samples_have_content(self, email_key):
        """Each human sample should have subject and body."""
        email = HUMAN_EMAILS[email_key]
        assert "subject" in email
        assert "body" in email
        assert len(email["body"]) > 20


class TestSampleDataFiles:
    """Test that sample data files exist and are readable."""

    SAMPLE_DIR = Path(__file__).parent / "sample_data"

    @pytest.mark.parametrize("filename", [
        "ai_phishing_email_1.txt",
        "ai_phishing_email_2.txt",
        "ai_phishing_email_3.txt",
        "ai_phishing_email_4.txt",
        "ai_phishing_email_5.txt",
    ])
    def test_phishing_sample_files_exist(self, filename):
        """Phishing sample data files should exist."""
        filepath = self.SAMPLE_DIR / filename
        assert filepath.exists(), f"Missing sample file: {filename}"
        content = filepath.read_text(encoding='utf-8')
        assert len(content) > 50

    @pytest.mark.parametrize("filename", [
        "human_email_1.txt",
        "human_email_2.txt",
        "human_email_3.txt",
        "human_email_4.txt",
        "human_email_5.txt",
    ])
    def test_human_sample_files_exist(self, filename):
        """Human sample data files should exist."""
        filepath = self.SAMPLE_DIR / filename
        assert filepath.exists(), f"Missing sample file: {filename}"
        content = filepath.read_text(encoding='utf-8')
        assert len(content) > 20


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_very_long_text(self):
        """Should handle very long text without crashing."""
        long_text = "This is suspicious text. " * 5000
        result = detect_ai_phishing(long_text)
        assert "is_ai_generated" in result

    def test_html_content(self):
        """Should handle HTML-heavy content."""
        html_text = """
        <html><body>
        <p>Dear Customer,</p>
        <p><a href="http://evil.com">Click here</a> to verify your account immediately.</p>
        <p>Your account will be suspended within 24 hours.</p>
        </body></html>
        """
        result = detect_ai_phishing(html_text)
        assert "is_ai_generated" in result

    def test_unicode_content(self):
        """Should handle unicode/international text."""
        unicode_text = "Cher client, votre compte a été compromis. Vérifiez immédiatement! 🚨"
        result = detect_ai_phishing(unicode_text)
        assert "is_ai_generated" in result

    def test_special_characters(self):
        """Should handle text with special characters."""
        special_text = "Hello <script>alert('xss')</script> & test \"quotes\" 'apostrophes'"
        result = detect_ai_phishing(special_text)
        assert "is_ai_generated" in result
