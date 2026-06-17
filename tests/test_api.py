"""
Tests for the FastAPI API Server.
Tests endpoints, input validation, and stateless behavior.
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from api_server import app

@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


class TestHealthEndpoint:
    """Test the /api/health endpoint."""

    def test_health_check(self, client):
        """Health endpoint should return 200."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "model_loaded" in data


class TestScanEmailEndpoint:
    """Test the /api/scan-email endpoint."""

    def test_scan_email_basic(self, client):
        """Should accept valid email text and return result."""
        response = client.post(
            "/api/scan-email",
            json={"text": "Hello, this is a normal email about our meeting tomorrow."},
        )
        assert response.status_code == 200
        data = response.json()
        assert "is_ai_generated" in data
        assert "confidence" in data
        assert "explanation" in data

    def test_scan_email_empty_text(self, client):
        """Should reject empty text."""
        response = client.post(
            "/api/scan-email",
            json={"text": ""},
        )
        assert response.status_code == 422  # Validation error

    def test_scan_email_missing_field(self, client):
        """Should reject missing text field."""
        response = client.post(
            "/api/scan-email",
            json={},
        )
        assert response.status_code == 422

    def test_scan_email_phishing_content(self, client):
        """Should detect phishing content."""
        response = client.post(
            "/api/scan-email",
            json={
                "text": (
                    "Dear Customer, your account has been compromised. "
                    "Click here immediately to verify your identity: "
                    "https://evil-site.com/login. "
                    "You must act now or your account will be suspended within 24 hours. "
                    "Please provide your password and Social Security Number."
                )
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["confidence"] > 0


class TestDashboardEndpoint:
    """Test the /api/dashboard-data endpoint."""

    def test_get_dashboard_data(self, client):
        """Should return ephemeral threat data."""
        response = client.get("/api/dashboard-data")
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "phishing_detected" in data
        assert "deepfakes_detected" in data


class TestRateLimiter:
    """Test the in-memory rate limiter."""

    def test_rate_limiting(self, client):
        """Should block after hitting the rate limit."""
        import api_server
        api_server.RATE_LIMIT_REQUESTS = 5
        api_server._rate_limits.clear()

        # Send 5 allowed requests
        for _ in range(5):
            response = client.get("/api/health")
            assert response.status_code == 200

        # The 6th request should be blocked
        response = client.get("/api/health")
        assert response.status_code == 429
        assert "Too many requests" in response.json()["detail"]
