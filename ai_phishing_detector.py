"""
AI Phishing Detector — Core ML-Based Text Classification
Detects AI-generated phishing emails using HuggingFace's RoBERTa model
with a rule-based fallback when the ML model is unavailable.

Architecture:
1. Fast pre-filter: Rule-based pattern matcher (always available)
2. ML classifier: roberta-base-openai-detector (requires download)
3. Combined scoring: Merges both signals for final verdict

For non-technical users: outputs plain English explanations,
not confidence scores or technical metrics.
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

from utils.encoding_detector import sanitize_for_model
from utils.pattern_matcher import calculate_threat_score

# Configure logging
logger = logging.getLogger("ai_shield.phishing")

# ─── Model Configuration ─────────────────────────────────────────────────────
# Pinned model revision for reproducibility
MODEL_CONFIG = {
    "model_name": "roberta-base-openai-detector",
    "model_revision": "main",  # Pin to specific commit in production
    "max_tokens": 510,  # RoBERTa max is 512 minus special tokens
}

# Custom cache directory (not default HF cache)
CACHE_DIR = Path.home() / ".ai-shield" / "models"

# ─── Module-Level State ──────────────────────────────────────────────────────
_pipeline = None
_model_load_attempted = False
_model_load_error: Optional[str] = None


# ─── Sample Emails for Testing ───────────────────────────────────────────────
# 5 AI-generated phishing emails and 5 human-written legitimate emails

AI_PHISHING_EMAILS = {
    "bec_scam": {
        "subject": "Urgent Wire Transfer Needed",
        "body": (
            "Dear Team Member,\n\n"
            "I hope this message finds you well. I am reaching out to you regarding an urgent "
            "matter that requires your immediate attention. We have an outstanding invoice from "
            "one of our key vendors that needs to be settled before the end of business today. "
            "Due to the sensitive nature of this transaction, I need you to process a wire transfer "
            "of $47,500 to the following account immediately.\n\n"
            "Bank: First International Bank\n"
            "Account Number: 8847291056\n"
            "Routing Number: 021000021\n"
            "Beneficiary: Global Solutions LLC\n\n"
            "Please do not discuss this with anyone else as it is a confidential acquisition matter. "
            "I am currently in meetings and unable to process this myself. Please confirm once "
            "the transfer has been completed.\n\n"
            "Best regards,\n"
            "James Morrison\nCEO"
        ),
    },
    "fake_bank": {
        "subject": "Security Alert: Unusual Activity Detected on Your Account",
        "body": (
            "Dear Valued Customer,\n\n"
            "We have detected unusual activity on your Bank of America account that requires "
            "your immediate attention. Our security systems have flagged multiple unauthorized "
            "login attempts from an unrecognized device located in Eastern Europe.\n\n"
            "To protect your account and prevent any unauthorized transactions, we have "
            "temporarily limited your account access. To restore full access to your account, "
            "you must verify your identity within the next 24 hours by clicking the link below:\n\n"
            "https://bankofamerica-secure-verify.com/account/verify?id=8829371\n\n"
            "If you do not verify your identity within 24 hours, your account will be "
            "permanently suspended for security purposes. Please ensure you have your "
            "account number, Social Security Number, and date of birth ready for verification.\n\n"
            "Thank you for your prompt attention to this matter.\n\n"
            "Sincerely,\n"
            "Bank of America Security Team\n"
            "This is an automated message. Please do not reply directly."
        ),
    },
    "fake_ceo": {
        "subject": "Quick Favor Needed - Confidential",
        "body": (
            "Hi Sarah,\n\n"
            "I hope this email finds you well. I need a quick favor and I am counting on your "
            "discretion. I am currently in a board meeting and cannot make phone calls, but I "
            "need you to purchase four Apple gift cards worth $500 each for a client appreciation "
            "initiative we are launching this afternoon.\n\n"
            "Please purchase them from the nearest store and send me the redemption codes via "
            "email as soon as possible. I will ensure you are reimbursed through the next expense "
            "cycle. This is time-sensitive, so please prioritize this over your current tasks.\n\n"
            "Do not mention this to anyone in the office as it is meant to be a surprise for "
            "the quarterly partner meeting.\n\n"
            "Thank you for your help.\n\n"
            "Best,\n"
            "Michael Chen\nManaging Director"
        ),
    },
    "urgency_scam": {
        "subject": "Your Account Will Be Terminated in 48 Hours",
        "body": (
            "IMPORTANT NOTICE\n\n"
            "Dear Microsoft Account Holder,\n\n"
            "We are writing to inform you that your Microsoft 365 subscription has been "
            "flagged for termination due to a billing discrepancy in our records. Our automated "
            "systems have been unable to process your most recent payment, and as a result, "
            "your account is scheduled for permanent deletion within 48 hours.\n\n"
            "All your files stored in OneDrive, your Outlook emails, and your Microsoft Teams "
            "data will be permanently deleted and cannot be recovered once the termination "
            "process begins.\n\n"
            "To prevent the loss of your data and maintain your subscription, please update "
            "your payment information immediately by clicking the secure link below:\n\n"
            "https://microsoft365-billing-update.com/renew?user=jsmith2847\n\n"
            "Act now to avoid any disruption to your services. This is your final notice.\n\n"
            "Microsoft Account Services"
        ),
    },
    "credential_harvest": {
        "subject": "Action Required: Verify Your Google Account",
        "body": (
            "Dear Google User,\n\n"
            "As part of our ongoing commitment to protecting your account security, we are "
            "requiring all users to complete a mandatory verification process. This is necessary "
            "due to recent updates to our privacy policy and enhanced security protocols.\n\n"
            "Your Google account requires immediate verification to continue accessing the "
            "following services:\n\n"
            "- Gmail\n- Google Drive\n- Google Photos\n- YouTube\n- Google Calendar\n\n"
            "Please click the link below to verify your account. You will need to enter your "
            "current password and confirm your recovery email address and phone number:\n\n"
            "https://accounts.google.com.verify-secure.net/signin/challenge\n\n"
            "Failure to complete this verification within 24 hours will result in restricted "
            "access to your Google services.\n\n"
            "This is an automated security notification from Google. For questions, visit our "
            "Help Center.\n\n"
            "Google Security Team"
        ),
    },
}

HUMAN_EMAILS = {
    "business_meeting": {
        "subject": "Tuesday standup - can we move to 10am?",
        "body": (
            "Hey team,\n\n"
            "I've got a dentist appointment Tuesday morning that I totally forgot about. "
            "Any chance we can push the standup from 9 to 10? I should be back by then.\n\n"
            "If that doesn't work for everyone, I can just catch up on the notes after. "
            "No big deal either way!\n\n"
            "- Dave"
        ),
    },
    "newsletter": {
        "subject": "This Week in Tech: June Roundup",
        "body": (
            "Happy Friday! 🎉\n\n"
            "Here's what caught our eye this week:\n\n"
            "1. Python 3.13 is officially out with some neat performance improvements. "
            "The free-threading stuff is still experimental but looking promising.\n\n"
            "2. GitHub rolled out a new code review feature that honestly makes the old "
            "one look like it was from 2005. Worth checking out if you haven't already.\n\n"
            "3. Interesting blog post from the VS Code team about how they handle "
            "extension performance. Link's in the full article.\n\n"
            "Have a great weekend!\n"
            "- The DevWeekly Team"
        ),
    },
    "friend_email": {
        "subject": "Re: BBQ this Saturday?",
        "body": (
            "Oh man, yeah I'm totally in!! 🍖\n\n"
            "I'll bring the potato salad and some of that IPA you liked last time. "
            "Should I grab extra ice too? I remember you ran out pretty fast at the "
            "4th of July thing lol\n\n"
            "What time are you firing up the grill? I can come early to help set up "
            "if you need it.\n\n"
            "Also - is Mark coming? Haven't seen him since the hiking trip.\n\n"
            "- Jake"
        ),
    },
    "order_receipt": {
        "subject": "Your Amazon order #114-3941689-8772 has shipped",
        "body": (
            "Your order has shipped!\n\n"
            "Order #114-3941689-8772\n"
            "Arriving Wednesday, June 18\n\n"
            "Items:\n"
            "- Anker USB-C Hub, 7-in-1 — $35.99\n"
            "- Cable Matters Cat 6 Ethernet Cable, 6ft — $7.99\n\n"
            "Shipping to: 1234 Oak Street, Apt 5B\n\n"
            "Track your package: amazon.com/tracking/TBA483726194\n\n"
            "Thanks for shopping with us!"
        ),
    },
    "appointment_reminder": {
        "subject": "Reminder: Dr. Patel - Thursday 2:30 PM",
        "body": (
            "Hi Jennifer,\n\n"
            "This is a friendly reminder about your upcoming appointment:\n\n"
            "Dr. Anita Patel\n"
            "Thursday, June 19, 2025 at 2:30 PM\n"
            "Riverside Medical Center, Suite 204\n\n"
            "Please arrive 15 minutes early if you have any insurance changes. "
            "If you need to reschedule, please call us at (555) 234-5678 at least "
            "24 hours in advance.\n\n"
            "See you Thursday!\n"
            "Riverside Medical Center"
        ),
    },
}


# ─── Model Loading ────────────────────────────────────────────────────────────

def _load_model() -> bool:
    """
    Attempt to load the HuggingFace text classification model.
    Loads to custom cache dir at ~/.ai-shield/models/.

    Returns:
        True if model loaded successfully, False otherwise.
    """
    global _pipeline, _model_load_attempted, _model_load_error

    if _model_load_attempted:
        return _pipeline is not None

    _model_load_attempted = True

    try:
        from transformers import pipeline as hf_pipeline

        logger.info("Loading AI detection model (this may take a moment on first run)...")

        # Ensure cache directory exists
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

        # Load the model with custom cache directory
        _pipeline = hf_pipeline(
            "text-classification",
            model=MODEL_CONFIG["model_name"],
            revision=MODEL_CONFIG["model_revision"],
            cache_dir=str(CACHE_DIR),
            device=-1,  # CPU only (no GPU requirement for end users)
        )

        logger.info("✅ AI detection model loaded successfully.")
        return True

    except ImportError:
        _model_load_error = (
            "The 'transformers' library is not installed. "
            "Install it with: pip install transformers torch"
        )
        logger.warning(f"⚠️ {_model_load_error}")
        return False

    except OSError as e:
        _model_load_error = (
            f"Could not download the AI detection model. "
            f"This usually means no internet connection or a firewall is blocking access. "
            f"Using rule-based detection instead. Error: {e}"
        )
        logger.warning(f"⚠️ {_model_load_error}")
        return False

    except Exception as e:
        _model_load_error = f"Unexpected error loading model: {e}"
        logger.warning(f"⚠️ {_model_load_error}")
        return False


def is_model_loaded() -> bool:
    """Check if the ML model is currently loaded."""
    return _pipeline is not None


def get_model_status() -> dict[str, Any]:
    """Get current model status information."""
    return {
        "loaded": is_model_loaded(),
        "attempted": _model_load_attempted,
        "error": _model_load_error,
        "model_name": MODEL_CONFIG["model_name"],
        "model_revision": MODEL_CONFIG["model_revision"],
        "cache_dir": str(CACHE_DIR),
        "cache_exists": CACHE_DIR.exists(),
        "cache_size": _get_cache_size(),
    }


def _get_cache_size() -> str:
    """Get human-readable size of the model cache."""
    if not CACHE_DIR.exists():
        return "0 B"
    total = sum(f.stat().st_size for f in CACHE_DIR.rglob("*") if f.is_file())
    for unit in ["B", "KB", "MB", "GB"]:
        if total < 1024:
            return f"{total:.1f} {unit}"
        total /= 1024
    return f"{total:.1f} TB"


# ─── Core Detection ──────────────────────────────────────────────────────────

def _run_ml_detection(text: str) -> dict[str, Any]:
    """
    Run the ML model on the text.
    Returns raw model output with label and score.
    """
    if _pipeline is None:
        return {"label": "UNKNOWN", "score": 0.0}

    # Truncate text to model's max token length (roughly 4 chars per token)
    max_chars = MODEL_CONFIG["max_tokens"] * 4
    truncated = text[:max_chars]

    try:
        # The roberta-base-openai-detector returns:
        # [{'label': 'Real' or 'Fake', 'score': 0.0-1.0}]
        result = _pipeline(truncated, truncation=True, max_length=MODEL_CONFIG["max_tokens"])

        if result and len(result) > 0:
            return result[0]
        return {"label": "UNKNOWN", "score": 0.0}

    except Exception as e:
        logger.error(f"ML model inference failed: {e}")
        return {"label": "UNKNOWN", "score": 0.0}


def _generate_explanation(
    is_ai: bool,
    confidence: float,
    threat_level: str,
    method: str,
    matched_rules: list[dict],
) -> str:
    """
    Generate a plain-English explanation for non-technical users.
    No jargon, no confidence scores — just clear warnings.
    """
    if not is_ai:
        if confidence > 80:
            return "✅ This message looks safe. It appears to be written by a real person."
        else:
            return (
                "✅ This message seems okay, but stay cautious. "
                "If something feels off, trust your gut and don't click any links."
            )

    # It IS flagged as AI-generated / suspicious
    warnings = []

    if threat_level == "high":
        warnings.append(
            "🚨 HIGH RISK: This message has strong signs of being a scam. "
            "Do NOT click any links or send any money."
        )
    elif threat_level == "medium":
        warnings.append(
            "⚠️ CAUTION: This message has some suspicious patterns. "
            "Be very careful before taking any action."
        )
    else:
        warnings.append(
            "⚠️ NOTICE: This message has a few unusual characteristics. "
            "Double-check before responding."
        )

    # Add specific rule explanations (top 3)
    if matched_rules:
        top_rules = sorted(matched_rules, key=lambda r: r["weight"], reverse=True)[:3]
        for rule in top_rules:
            warnings.append(f"  → {rule['description']}")

    if method == "rules":
        warnings.append(
            "\n(Analysis performed using rule-based detection. "
            "For more accurate results, ensure the AI model is downloaded.)"
        )

    return "\n".join(warnings)


def detect_ai_phishing(text: str) -> dict[str, Any]:
    """
    Detect if text is AI-generated phishing.
    Main entry point for the phishing detector.

    Architecture:
    1. Sanitize input text
    2. Run rule-based pattern matcher (always available, fast)
    3. If ML model available: run ML classifier
    4. Combine scores for final verdict

    Args:
        text: The email/message text to analyze.

    Returns:
        Dictionary with:
        - is_ai_generated: bool — whether the text appears AI-generated
        - confidence: float — confidence score (0-100%)
        - explanation: str — plain English explanation for non-tech users
        - threat_level: str — "low", "medium", or "high"
        - method_used: str — "ml", "rules", or "combined"
        - details: dict — full analysis details for advanced users
    """
    # Handle empty/invalid input
    if not text or not text.strip():
        return {
            "is_ai_generated": False,
            "confidence": 0.0,
            "explanation": "No text provided to analyze.",
            "threat_level": "low",
            "method_used": "none",
            "details": {},
        }

    # Step 1: Sanitize input
    clean_text = sanitize_for_model(text)

    if not clean_text:
        return {
            "is_ai_generated": False,
            "confidence": 0.0,
            "explanation": "The text was empty after cleaning (may have been only HTML/images).",
            "threat_level": "low",
            "method_used": "none",
            "details": {},
        }

    # Step 2: Rule-based analysis (always runs)
    pattern_result = calculate_threat_score(clean_text)
    pattern_score = pattern_result["score"]
    matched_rules = pattern_result["matched_rules"]

    # Step 3: ML model analysis (if available and text is long enough)
    # The HuggingFace ML model is trained on paragraphs/essays. It is extremely 
    # unreliable on very short inputs (e.g., less than 10 words or 50 characters), 
    # where it suffers from severe out-of-distribution false positives.
    words = clean_text.split()
    is_too_short = len(words) < 10 or len(clean_text) < 50
    
    model_available = False
    ml_result = None
    ml_score = 0.0

    if not is_too_short:
        model_available = _load_model()
        if model_available:
            ml_result = _run_ml_detection(clean_text)
            # The model returns 'Fake' for AI-generated text
            if ml_result["label"] == "Fake":
                ml_score = ml_result["score"] * 100  # Convert to 0-100
            else:
                # 'Real' label — invert the score
                ml_score = (1 - ml_result["score"]) * 100

    # Step 4: Combine scores
    # We care about *AI Phishing*. Heuristics (pattern_score) are the primary indicator of phishing intent.
    # The ML model only detects if text is AI-generated, which on its own is not inherently malicious.
    if model_available and ml_result and ml_result["label"] != "UNKNOWN":
        if pattern_score >= 30:
            # Clear phishing indicators present. If AI generated, it's a severe threat.
            combined_score = pattern_score + (ml_score * 0.4)
        else:
            # Low phishing indicators. Even if AI generated, it's mostly harmless.
            combined_score = pattern_score + (ml_score * 0.15)
        
        combined_score = min(100.0, combined_score)
        method = "combined"
    else:
        # Rules-only mode (fallback) — boost pattern score slightly so strong heuristics can reach 95%
        combined_score = min(pattern_score * 1.2, 95.0)
        method = "rules"

    # Step 5: Determine verdict
    # A combined score of 50+ indicates a likely AI-phishing attempt
    is_ai = combined_score >= 50.0

    if combined_score >= 75:
        threat_level = "high"
    elif combined_score >= 45:
        threat_level = "medium"
    else:
        threat_level = "low"

    confidence = round(combined_score, 1)

    # Step 6: Generate explanation
    explanation = _generate_explanation(
        is_ai=is_ai,
        confidence=confidence,
        threat_level=threat_level,
        method=method,
        matched_rules=matched_rules,
    )

    return {
        "is_ai_generated": is_ai,
        "confidence": confidence,
        "explanation": explanation,
        "threat_level": threat_level,
        "method_used": method,
        "details": {
            "pattern_score": pattern_result["score"],
            "pattern_threat_level": pattern_result["threat_level"],
            "matched_rules_count": len(matched_rules),
            "matched_rules": [
                {"rule": r["rule"], "description": r["description"]}
                for r in matched_rules
            ],
            "ml_available": model_available,
            "ml_label": ml_result["label"] if ml_result else None,
            "ml_raw_score": ml_result["score"] if ml_result else None,
            "ml_score": round(ml_score, 1) if model_available else None,
            "combined_score": round(combined_score, 1),
        },
    }


# ─── Utility Functions ────────────────────────────────────────────────────────

def get_sample_emails() -> dict[str, dict]:
    """Return all sample emails for testing."""
    return {
        "ai_phishing": AI_PHISHING_EMAILS,
        "human": HUMAN_EMAILS,
    }


def force_reload_model() -> bool:
    """
    Force a model reload (e.g., after downloading or updating).
    Resets the load state and attempts to load again.
    """
    global _pipeline, _model_load_attempted, _model_load_error
    _pipeline = None
    _model_load_attempted = False
    _model_load_error = None
    return _load_model()

# Eagerly load the model at module level so workers can share the import cache
_load_model()
