"""
email_features.py
------------------
Rule-based feature extraction for email indicators (headers + body text).

Works on a plain dict describing an email so it can be used without any
mail-parsing library, but `parse_eml` is provided to pull the same fields
out of a raw .eml file if you have one.
"""

import re
import email
from email import policy
from urllib.parse import urlparse

from .url_features import extract_url_features, SUSPICIOUS_KEYWORDS, COMMON_BRANDS

URGENCY_PHRASES = [
    "act now", "immediately", "urgent", "verify your account",
    "suspended", "unusual activity", "click here", "limited time",
    "your account will be", "final notice", "confirm your identity",
    "within 24 hours", "avoid suspension", "password will expire",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer",
    "dear account holder", "dear sir/madam",
]

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "mail.com", "gmx.com", "protonmail.com",
}

URL_PATTERN = re.compile(r"https?://[^\s\"'<>\)]+|www\.[^\s\"'<>\)]+")


def parse_eml(raw_bytes: bytes) -> dict:
    """Parse a raw .eml file into the dict format used by extract_email_features."""
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        body = msg.get_content()

    return {
        "from_addr": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "subject": msg.get("Subject", ""),
        "body": body,
        "return_path": msg.get("Return-Path", ""),
    }


def _extract_domain(addr: str) -> str:
    match = re.search(r"@([\w.\-]+)", addr or "")
    return match.group(1).lower() if match else ""


def extract_email_features(email_data: dict) -> dict:
    """
    email_data expects keys (all optional, default to ""):
        from_addr, reply_to, subject, body, return_path
    """
    from_addr = email_data.get("from_addr", "") or ""
    reply_to = email_data.get("reply_to", "") or ""
    subject = email_data.get("subject", "") or ""
    body = email_data.get("body", "") or ""
    return_path = email_data.get("return_path", "") or ""

    text = f"{subject}\n{body}".lower()

    from_domain = _extract_domain(from_addr)
    reply_domain = _extract_domain(reply_to)
    return_domain = _extract_domain(return_path)

    urls = URL_PATTERN.findall(body)
    url_feature_list = [extract_url_features(u) for u in urls]

    display_name_mismatch = _display_name_spoof(from_addr)

    features = {
        "num_links": len(urls),
        "has_links": len(urls) > 0,
        "any_link_suspicious_tld": any(f["suspicious_tld"] for f in url_feature_list),
        "any_link_is_ip": any(f["has_ip_host"] for f in url_feature_list),
        "any_link_brand_lookalike": any(f["brand_in_subdomain_or_path"] for f in url_feature_list),
        "any_link_is_shortener": any(f["is_shortener"] for f in url_feature_list),
        "reply_to_mismatch": bool(reply_domain) and reply_domain != from_domain,
        "return_path_mismatch": bool(return_domain) and return_domain != from_domain,
        "from_is_freemail": from_domain in FREE_MAIL_DOMAINS,
        "display_name_brand_spoof": display_name_mismatch,
        "count_urgency_phrases": sum(p in text for p in URGENCY_PHRASES),
        "generic_greeting": any(g in text for g in GENERIC_GREETINGS),
        "subject_has_re_fwd_spam_pattern": bool(
            re.match(r"^(re|fwd)\s*:\s*(re|fwd)\s*:", subject.lower())
        ),
        "count_suspicious_keywords_body": sum(kw in text for kw in SUSPICIOUS_KEYWORDS),
        "requests_sensitive_info": bool(
            re.search(r"(password|ssn|social security|credit card|pin number|cvv)", text)
        ),
        "num_exclamation": body.count("!"),
        "all_caps_words": len(re.findall(r"\b[A-Z]{4,}\b", body)),
        "urls": urls,
        "url_feature_list": url_feature_list,
    }
    return features


def _display_name_spoof(from_addr: str) -> bool:
    """
    Detect a spoofed display name, e.g. 'PayPal Support <security@totally-not-paypal.xyz>'
    where the visible name references a brand not present in the actual domain.
    """
    m = re.match(r'^"?([^"<]*)"?\s*<([^>]+)>$', from_addr.strip())
    if not m:
        return False
    display_name, addr = m.group(1).lower(), m.group(2).lower()
    domain = _extract_domain(addr)
    for brand in COMMON_BRANDS:
        if brand in display_name and brand not in domain:
            return True
    return False


def explain_email_features(features: dict) -> list:
    notes = []
    if features.get("reply_to_mismatch"):
        notes.append("Reply-To domain does not match the From domain.")
    if features.get("return_path_mismatch"):
        notes.append("Return-Path domain does not match the From domain.")
    if features.get("display_name_brand_spoof"):
        notes.append("Display name references a brand that doesn't match the sending domain.")
    if features.get("any_link_brand_lookalike"):
        notes.append("Email contains a link impersonating a known brand's domain.")
    if features.get("any_link_is_ip"):
        notes.append("Email contains a link pointing directly to an IP address.")
    if features.get("any_link_is_shortener"):
        notes.append("Email contains a shortened link hiding its real destination.")
    if features.get("count_urgency_phrases", 0) >= 2:
        notes.append("Multiple urgency/pressure phrases found in the message.")
    if features.get("generic_greeting"):
        notes.append("Generic greeting used instead of the recipient's name.")
    if features.get("requests_sensitive_info"):
        notes.append("Message explicitly requests sensitive information.")
    if features.get("all_caps_words", 0) >= 3:
        notes.append("Excessive use of all-caps words (common pressure tactic).")
    return notes
