"""
Shared test fixtures for AI Shield test suite.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def temp_dir():
    """Provide a temporary directory that's cleaned up after the test."""
    tmpdir = tempfile.mkdtemp()
    yield Path(tmpdir)
    # Best-effort cleanup — may fail on Windows if SQLite WAL holds locks
    import shutil
    try:
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass


@pytest.fixture
def temp_db(temp_dir):
    """Provide a temporary SQLite database path."""
    return temp_dir / "test_threats.db"


@pytest.fixture
def sample_threats():
    """Provide sample threat data for testing."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)

    return [
        {
            "id": 1,
            "timestamp": (now - timedelta(hours=5)).isoformat(),
            "type": "phishing",
            "source": "Fake bank email",
            "confidence": 92.5,
            "threat_level": "high",
            "is_threat": True,
            "details": {"method_used": "combined"},
        },
        {
            "id": 2,
            "timestamp": (now - timedelta(hours=3)).isoformat(),
            "type": "deepfake",
            "source": "suspicious_call.wav",
            "confidence": 67.0,
            "threat_level": "medium",
            "is_threat": True,
            "details": {"heuristic_score": 60.0},
        },
        {
            "id": 3,
            "timestamp": (now - timedelta(hours=1)).isoformat(),
            "type": "phishing",
            "source": "Newsletter",
            "confidence": 12.0,
            "threat_level": "low",
            "is_threat": False,
            "details": {"method_used": "rules"},
        },
    ]


@pytest.fixture
def phishing_email_text():
    """Provide sample phishing email text."""
    return (
        "Dear Valued Customer,\n\n"
        "We have detected unusual activity on your account. "
        "Your account will be suspended within 24 hours unless you verify your identity. "
        "Click here to verify your account immediately: "
        "https://bankofamerica-secure-verify.com/login\n\n"
        "Please provide your password and Social Security Number for verification.\n\n"
        "Bank of America Security Team"
    )


@pytest.fixture
def safe_email_text():
    """Provide sample safe email text."""
    return (
        "Hey Dave,\n\n"
        "Just checking in about the BBQ this Saturday. "
        "I'll bring the potato salad and some beer. "
        "What time should I come over?\n\n"
        "- Jake"
    )


@pytest.fixture
def sample_audio_dir(temp_dir):
    """Generate sample audio files and return the directory."""
    from deepfake_voice_scanner import generate_sample_audio
    generate_sample_audio(str(temp_dir))
    return temp_dir
