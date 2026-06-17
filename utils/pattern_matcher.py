"""
Pattern Matcher — Rule-Based Phishing Heuristic Scanner
Always-available, no ML model needed. Acts as fallback when HuggingFace
model is unavailable, and as a fast pre-filter before ML inference.

Checks for:
- Urgency keywords and pressure tactics
- Suspicious URL patterns
- Impersonation signals (CEO/bank/service spoofing)
- Grammar anomalies typical of AI-generated text
- Link-text mismatches (display text doesn't match actual URL)
"""

import re
from typing import Any


# ─── Urgency Keywords ────────────────────────────────────────────────────────
# Words/phrases that create artificial urgency — weighted by severity
URGENCY_KEYWORDS: dict[str, float] = {
    # High urgency (weight 3.0)
    "act now": 3.0,
    "immediately": 3.0,
    "urgent action required": 3.0,
    "your account will be suspended": 3.0,
    "your account has been compromised": 3.0,
    "unauthorized access": 3.0,
    "verify your identity": 3.0,
    "confirm your identity": 3.0,
    "within 24 hours": 3.0,
    "within 48 hours": 3.0,
    "account will be closed": 3.0,
    "account will be terminated": 3.0,
    "failure to respond": 3.0,
    "hack": 3.0,
    "hacked": 3.0,
    "stolen": 3.0,
    # Medium urgency (weight 2.0)
    "click here": 2.0,
    "click below": 2.0,
    "click the link": 2.0,
    "click this link": 2.0,
    "verify your account": 2.0,
    "update your information": 2.0,
    "confirm your account": 2.0,
    "unusual activity": 2.0,
    "suspicious activity": 2.0,
    "security alert": 2.0,
    "important notice": 2.0,
    "action required": 2.0,
    "respond immediately": 2.0,
    "limited time": 2.0,
    "don't miss out": 2.0,
    "expire soon": 2.0,
    "expiring soon": 2.0,
    # Low urgency (weight 1.0)
    "dear customer": 1.0,
    "dear user": 1.0,
    "dear account holder": 1.0,
    "valued customer": 1.0,
    "as soon as possible": 1.0,
    "kindly": 1.0,
    "please be advised": 1.0,
    "for your protection": 1.0,
    "for security purposes": 1.0,
    "we have detected": 1.0,
    "we noticed": 1.0,
}

# ─── Suspicious URL Patterns ─────────────────────────────────────────────────
SUSPICIOUS_URL_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # IP address URLs (not domain names) — very suspicious
    (
        re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        "URL uses IP address instead of domain name",
        4.0,
    ),
    # URL shorteners — often used to hide real destination
    (
        re.compile(r"https?://(?:bit\.ly|tinyurl|t\.co|goo\.gl|rb\.gy|is\.gd|v\.gd)/", re.IGNORECASE),
        "URL uses link shortener to hide destination",
        3.0,
    ),
    # Lookalike domains (e.g., paypa1.com, amaz0n.com)
    (
        re.compile(r"https?://[^\s]*(?:paypa[l1]|amaz[o0]n|g[o0]{2}gle|app[l1]e|micr[o0]s[o0]ft|faceb[o0]{2}k)[^\s]*\.", re.IGNORECASE),
        "URL contains lookalike brand domain (possible typosquatting)",
        5.0,
    ),
    # Excessive subdomains (login.secure.bank.evil.com)
    (
        re.compile(r"https?://(?:[^/]*\.){4,}"),
        "URL has excessive subdomains (hiding real domain)",
        3.0,
    ),
    # Data URIs (can embed malicious content)
    (
        re.compile(r"data:text/html", re.IGNORECASE),
        "Contains data URI (can embed hidden content)",
        4.0,
    ),
    # URLs with @ symbol (user@host trick to obscure real domain)
    (
        re.compile(r"https?://[^/]*@"),
        "URL contains @ symbol (obscures real destination)",
        4.0,
    ),
]

# ─── Impersonation Signals ────────────────────────────────────────────────────
# Brand/service names commonly impersonated in phishing
IMPERSONATED_BRANDS: list[str] = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook", "meta",
    "netflix", "bank of america", "wells fargo", "chase", "citibank",
    "irs", "social security", "medicare", "fedex", "ups", "usps",
    "dhl", "walmart", "costco", "target", "best buy",
]

# CEO/executive impersonation patterns
CEO_IMPERSONATION_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (
        re.compile(r"(?:from|sent by|on behalf of)\s+(?:the\s+)?(?:ceo|cfo|cto|president|director|executive|managing director)", re.IGNORECASE),
        "Claims to be from a company executive (possible BEC scam)",
        4.0,
    ),
    (
        re.compile(r"(?:wire|transfer|send)\s+(?:the\s+)?(?:funds|money|payment|amount)", re.IGNORECASE),
        "Requests money transfer (common in BEC attacks)",
        5.0,
    ),
    (
        re.compile(r"(?:gift\s*cards?|itunes\s*cards?|google\s*play\s*cards?|steam\s*cards?)", re.IGNORECASE),
        "Mentions gift cards (common scam payment method)",
        5.0,
    ),
    (
        re.compile(r"(?:don'?t|do not)\s+(?:tell|mention|share|discuss)\s+(?:this|it)\s+(?:with|to)\s+anyone", re.IGNORECASE),
        "Asks to keep communication secret (social engineering tactic)",
        4.0,
    ),
]

# ─── Credential Harvesting Signals ────────────────────────────────────────────
CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (
        re.compile(r"(?:enter|provide|confirm|verify|update)\s+(?:your\s+)?(?:password|login|credentials|ssn|social\s*security|credit\s*card|bank\s*account)", re.IGNORECASE),
        "Requests sensitive credentials (passwords, SSN, financial info)",
        5.0,
    ),
    (
        re.compile(r"(?:log\s*in|sign\s*in)\s+(?:to\s+)?(?:verify|confirm|update|secure)", re.IGNORECASE),
        "Asks to log in to verify/confirm (phishing lure)",
        3.0,
    ),
]


def _check_urgency(text: str) -> list[dict[str, Any]]:
    """Check for urgency keywords and pressure tactics."""
    text_lower = text.lower()
    matches = []
    for keyword, weight in URGENCY_KEYWORDS.items():
        if keyword in text_lower:
            matches.append({
                "rule": "urgency_keyword",
                "matched": keyword,
                "weight": weight,
                "description": f"Uses pressure tactic: '{keyword}'",
            })
    return matches


def _check_suspicious_urls(text: str) -> list[dict[str, Any]]:
    """Check for suspicious URL patterns."""
    matches = []
    for pattern, description, weight in SUSPICIOUS_URL_PATTERNS:
        found = pattern.findall(text)
        if found:
            matches.append({
                "rule": "suspicious_url",
                "matched": found[0] if len(found) == 1 else found,
                "weight": weight,
                "description": description,
            })
    return matches


def _check_impersonation(text: str) -> list[dict[str, Any]]:
    """Check for brand/CEO impersonation signals."""
    text_lower = text.lower()
    matches = []

    # Brand impersonation — only flag if combined with urgency/credential asks
    for brand in IMPERSONATED_BRANDS:
        if brand in text_lower:
            # Check if the email also has credential-harvesting language
            has_credential_ask = any(
                p.search(text) for p, _, _ in CREDENTIAL_PATTERNS
            )
            has_urgency = any(
                kw in text_lower for kw in list(URGENCY_KEYWORDS.keys())[:10]
            )
            if has_credential_ask or has_urgency:
                matches.append({
                    "rule": "brand_impersonation",
                    "matched": brand,
                    "weight": 3.0,
                    "description": f"Mentions '{brand}' with urgency/credential request (possible impersonation)",
                })
                break  # One brand match is enough

    # CEO/executive impersonation
    for pattern, description, weight in CEO_IMPERSONATION_PATTERNS:
        if pattern.search(text):
            matches.append({
                "rule": "ceo_impersonation",
                "matched": pattern.pattern,
                "weight": weight,
                "description": description,
            })

    return matches


def _check_credential_harvesting(text: str) -> list[dict[str, Any]]:
    """Check for credential harvesting patterns."""
    matches = []
    for pattern, description, weight in CREDENTIAL_PATTERNS:
        if pattern.search(text):
            matches.append({
                "rule": "credential_harvesting",
                "matched": pattern.pattern,
                "weight": weight,
                "description": description,
            })
    return matches


def _check_link_text_mismatch(text: str) -> list[dict[str, Any]]:
    """
    Check for link-text mismatches in HTML content.
    Example: <a href="http://evil.com">Click here to visit PayPal</a>
    The display text says 'PayPal' but the link goes to 'evil.com'.
    """
    matches = []
    # Pattern to find <a href="URL">text</a>
    link_pattern = re.compile(
        r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL,
    )
    for url, display_text in link_pattern.findall(text):
        display_lower = display_text.lower().strip()
        url_lower = url.lower()

        # Check if display text mentions a brand that isn't in the URL
        for brand in IMPERSONATED_BRANDS:
            if brand in display_lower and brand not in url_lower:
                matches.append({
                    "rule": "link_text_mismatch",
                    "matched": f"Display: '{display_text.strip()}' → URL: '{url}'",
                    "weight": 5.0,
                    "description": f"Link text mentions '{brand}' but URL goes elsewhere (deceptive link)",
                })
                break

    return matches


def _check_ai_writing_patterns(text: str) -> list[dict[str, Any]]:
    """
    Check for patterns common in AI-generated text.
    AI text tends to be overly formal, perfectly structured, and use
    certain phrases more frequently than humans.
    """
    matches = []
    text_lower = text.lower()

    # AI-generated text often uses these filler phrases
    ai_phrases = [
        ("i hope this email finds you well", 1.5),
        ("i hope this message finds you well", 1.5),
        ("please do not hesitate to", 1.0),
        ("do not hesitate to reach out", 1.0),
        ("at your earliest convenience", 1.0),
        ("i wanted to reach out", 1.0),
        ("i am writing to inform you", 1.0),
        ("please find attached", 0.5),
        ("as per our conversation", 0.5),
        ("moving forward", 0.5),
    ]

    ai_phrase_count = 0
    for phrase, weight in ai_phrases:
        if phrase in text_lower:
            ai_phrase_count += 1
            if ai_phrase_count >= 2:  # Only flag if multiple AI phrases present
                matches.append({
                    "rule": "ai_writing_pattern",
                    "matched": phrase,
                    "weight": weight,
                    "description": f"Uses AI-typical phrasing: '{phrase}'",
                })

    # Check for unnaturally perfect grammar with formal structure
    # (long sentences with zero contractions can indicate AI)
    sentences = re.split(r"[.!?]+", text)
    long_formal_sentences = sum(
        1 for s in sentences
        if len(s.split()) > 20 and not re.search(r"(?:n't|'re|'ve|'ll|'s|'m|'d)\b", s)
    )
    if long_formal_sentences >= 3:
        matches.append({
            "rule": "ai_writing_pattern",
            "matched": f"{long_formal_sentences} long formal sentences without contractions",
            "weight": 2.0,
            "description": "Unnaturally formal writing style (possible AI generation)",
        })

    return matches


def calculate_threat_score(text: str) -> dict[str, Any]:
    """
    Run all heuristic checks and calculate a combined threat score.
    This is the main entry point for the pattern matcher.

    Args:
        text: Email/message text to analyze.

    Returns:
        Dictionary with:
        - score: float (0-100, higher = more suspicious)
        - threat_level: str ("low", "medium", "high")
        - matched_rules: list of matched rule details
        - explanation: str (human-readable summary)
    """
    if not text or not text.strip():
        return {
            "score": 0.0,
            "threat_level": "low",
            "matched_rules": [],
            "explanation": "No text to analyze.",
        }

    # Run all checks
    all_matches: list[dict[str, Any]] = []
    all_matches.extend(_check_urgency(text))
    all_matches.extend(_check_suspicious_urls(text))
    all_matches.extend(_check_impersonation(text))
    all_matches.extend(_check_credential_harvesting(text))
    all_matches.extend(_check_link_text_mismatch(text))
    all_matches.extend(_check_ai_writing_patterns(text))

    # Calculate raw score from weights
    raw_score = sum(m["weight"] for m in all_matches)

    # Normalize to 0-100 scale
    # A few strong indicators (e.g., urgency + malicious link) should trigger a high score.
    # We map a score of 12 to 100%.
    normalized_score = min(100.0, (raw_score / 12.0) * 100.0)

    # Determine threat level
    if normalized_score >= 60:
        threat_level = "high"
    elif normalized_score >= 30:
        threat_level = "medium"
    else:
        threat_level = "low"

    # Build human-readable explanation
    if not all_matches:
        explanation = "No suspicious patterns detected."
    else:
        # Pick the top 3 most important rules for the explanation
        top_rules = sorted(all_matches, key=lambda m: m["weight"], reverse=True)[:3]
        descriptions = [r["description"] for r in top_rules]
        explanation = "Warning signs found: " + "; ".join(descriptions) + "."

    return {
        "score": round(normalized_score, 1),
        "threat_level": threat_level,
        "matched_rules": all_matches,
        "explanation": explanation,
    }
