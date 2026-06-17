"""
Encoding Detector & Text Normalizer
Handles text encoding detection, HTML stripping, base64 decoding, and input sanitization.
Ensures all text is clean UTF-8 before passing to ML models.
"""

import base64
import html
import re
import email
from email import policy
from typing import Optional


# Maximum text length we'll process (50,000 chars as per API spec)
MAX_TEXT_LENGTH = 50_000

# Regex patterns for cleaning
HTML_TAG_PATTERN = re.compile(r"<[^>]+>", re.DOTALL)
MULTI_WHITESPACE_PATTERN = re.compile(r"\s+")
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    re.IGNORECASE,
)
# Control characters except newline, tab, carriage return
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def detect_encoding(raw_bytes: bytes) -> str:
    """
    Detect the encoding of raw bytes.
    Tries UTF-8 first (most common), then falls back to common encodings.

    Args:
        raw_bytes: The raw byte content to detect encoding for.

    Returns:
        The detected encoding name (e.g., 'utf-8', 'ascii', 'latin-1').
    """
    # Try UTF-8 first (most common on modern systems)
    try:
        raw_bytes.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        pass

    # Try ASCII (subset of UTF-8, but worth checking explicitly)
    try:
        raw_bytes.decode("ascii")
        return "ascii"
    except UnicodeDecodeError:
        pass

    # Try other common encodings
    for encoding in ["latin-1", "cp1252", "iso-8859-1", "utf-16"]:
        try:
            raw_bytes.decode(encoding)
            return encoding
        except (UnicodeDecodeError, UnicodeError):
            continue

    # Last resort: latin-1 always succeeds (maps bytes 1:1 to unicode)
    return "latin-1"


def normalize_to_utf8(text_input: str | bytes) -> str:
    """
    Normalize any text input to a clean UTF-8 string.
    Handles both string and bytes input.

    Args:
        text_input: String or bytes to normalize.

    Returns:
        Clean UTF-8 string.
    """
    if isinstance(text_input, bytes):
        encoding = detect_encoding(text_input)
        text = text_input.decode(encoding, errors="replace")
    else:
        text = text_input

    # Remove null bytes (security: prevents null byte injection)
    text = text.replace("\x00", "")

    # Remove other control characters but keep newlines, tabs, carriage returns
    text = CONTROL_CHAR_PATTERN.sub("", text)

    return text


def strip_html(text: str) -> str:
    """
    Remove HTML tags and decode HTML entities.
    Converts HTML email content to plain text.

    Args:
        text: HTML-containing text.

    Returns:
        Plain text with HTML removed.
    """
    # First decode HTML entities (&amp; -> &, &lt; -> <, etc.)
    text = html.unescape(text)

    # Remove HTML tags
    text = HTML_TAG_PATTERN.sub(" ", text)

    # Collapse multiple whitespace into single spaces
    text = MULTI_WHITESPACE_PATTERN.sub(" ", text)

    return text.strip()


def decode_base64_content(text: str) -> str:
    """
    Detect and decode base64-encoded content within text.
    Common in email attachments and obfuscated phishing emails.

    Args:
        text: Text that may contain base64-encoded sections.

    Returns:
        Text with base64 sections decoded.
    """
    # Pattern for base64-encoded blocks (at least 20 chars of base64)
    base64_pattern = re.compile(
        r"([A-Za-z0-9+/]{20,}={0,2})",
        re.MULTILINE,
    )

    def try_decode(match: re.Match) -> str:
        """Attempt to decode a base64 match, return original if it fails."""
        candidate = match.group(1)
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
            # Only replace if the decoded text looks like readable text
            # (at least 70% printable characters)
            printable_ratio = sum(
                1 for c in decoded if c.isprintable() or c.isspace()
            ) / max(len(decoded), 1)
            if printable_ratio > 0.7:
                return decoded
        except Exception:
            pass
        return candidate

    return base64_pattern.sub(try_decode, text)


def parse_email_mime(raw_email: str) -> str:
    """
    Parse a MIME email message and extract the plain text body.
    Handles multipart messages, content-transfer-encoding, etc.

    Args:
        raw_email: Raw email content (headers + body).

    Returns:
        Extracted plain text body.
    """
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
    except Exception:
        # If parsing fails, treat the whole thing as plain text
        return raw_email

    # Try to get plain text body
    body = msg.get_body(preferencelist=("plain", "html"))
    if body is not None:
        content = body.get_content()
        if isinstance(content, bytes):
            content = normalize_to_utf8(content)

        # If we got HTML, strip the tags
        content_type = body.get_content_type()
        if content_type == "text/html":
            content = strip_html(content)

        return content

    # Fallback: concatenate all text parts
    parts = []
    for part in msg.walk():
        if part.get_content_maintype() == "text":
            try:
                payload = part.get_content()
                if isinstance(payload, bytes):
                    payload = normalize_to_utf8(payload)
                if part.get_content_type() == "text/html":
                    payload = strip_html(payload)
                parts.append(payload)
            except Exception:
                continue

    return "\n".join(parts) if parts else raw_email


def extract_urls(text: str) -> list[str]:
    """
    Extract all URLs from text content.
    Useful for checking against phishing URL databases.

    Args:
        text: Text to extract URLs from.

    Returns:
        List of URL strings found in the text.
    """
    return URL_PATTERN.findall(text)


def sanitize_for_model(text: str, max_length: int = MAX_TEXT_LENGTH) -> str:
    """
    Full sanitization pipeline for text before passing to ML models.
    This is the main entry point — call this before any ML processing.

    Pipeline:
    1. Normalize encoding to UTF-8
    2. Strip HTML tags and decode entities
    3. Decode any base64-encoded content
    4. Remove control characters
    5. Truncate to max length

    Args:
        text: Raw text input (may contain HTML, base64, etc.).
        max_length: Maximum character length to return.

    Returns:
        Clean, normalized text ready for ML model input.
    """
    if not text:
        return ""

    # Step 1: Normalize encoding
    text = normalize_to_utf8(text)

    # Step 2: Strip HTML
    text = strip_html(text)

    # Step 3: Decode base64
    text = decode_base64_content(text)

    # Step 4: Final cleanup — collapse whitespace
    text = MULTI_WHITESPACE_PATTERN.sub(" ", text).strip()

    # Step 5: Truncate to max length
    if len(text) > max_length:
        text = text[:max_length]

    return text


def is_binary_content(text: str) -> bool:
    """
    Check if text appears to be binary content (not human-readable).
    Used to reject binary uploads disguised as text.

    Args:
        text: Text to check.

    Returns:
        True if the text appears to be binary/non-readable.
    """
    if not text:
        return False

    # Sample the first 1000 chars
    sample = text[:1000]
    printable_count = sum(1 for c in sample if c.isprintable() or c.isspace())
    return (printable_count / max(len(sample), 1)) < 0.7
