"""
url_features.py
----------------
Rule-based feature extraction for URLs.

Every function in this module inspects a single URL and returns either a
boolean/numeric signal or a small dict of signals. These signals are used
both directly (rule-based scoring in rules.py) and as engineered features
fed into the ML model (ml_model.py).
"""

import re
import math
from urllib.parse import urlparse
from collections import Counter

# A short list of high-value brand names commonly impersonated in phishing.
# This is intentionally small/illustrative -- extend as needed.
COMMON_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "bankofamerica", "wellsfargo", "chase",
    "dropbox", "linkedin", "outlook", "office365", "irs", "usps",
    "fedex", "dhl", "coinbase", "binance",
]

SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work",
    "party", "gq", "link", "xyz", "tk", "top", "click", "loan", "men",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "confirm", "banking", "password", "billing", "suspended",
    "urgent", "invoice", "unlock", "reset",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly",
}

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)


def _shannon_entropy(s: str) -> float:
    """Character-level Shannon entropy of a string. Higher = more random-looking."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _safe_parse(url: str):
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    return urlparse(url)


def extract_url_features(url: str) -> dict:
    """
    Extract a dictionary of numeric/boolean features from a raw URL string.
    These feed both the rule engine and the ML model, so keep keys stable.
    """
    url = url.strip()
    parsed = _safe_parse(url)
    host = (parsed.netloc or "").lower()
    host = host.split("@")[-1].split(":")[0]  # strip userinfo/port
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.lower()

    labels = [l for l in host.split(".") if l]
    tld = labels[-1] if labels else ""

    features = {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "num_dots": host.count("."),
        "num_hyphens": full.count("-"),
        "num_at_symbols": full.count("@"),
        "num_digits": sum(c.isdigit() for c in full),
        "num_subdomains": max(len(labels) - 2, 0),
        "has_ip_host": bool(IP_PATTERN.match(host)),
        "uses_https": parsed.scheme == "https",
        "has_port": ":" in (parsed.netloc or ""),
        "double_slash_in_path": "//" in path,
        "is_shortener": host in SHORTENER_DOMAINS,
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "host_entropy": round(_shannon_entropy(host), 3),
        "count_suspicious_keywords": sum(
            kw in full for kw in SUSPICIOUS_KEYWORDS
        ),
        "brand_in_subdomain_or_path": _brand_lookalike(host, path),
        "punycode": host.startswith("xn--") or "xn--" in host,
        "excessive_length": len(url) > 90,
        "many_query_params": query.count("=") if query else 0,
    }
    return features


def _brand_lookalike(host: str, path: str) -> bool:
    """
    True if a known brand name appears somewhere in the host/path but the
    host is NOT that brand's actual registered domain (a classic phishing
    pattern: paypal.com.verify-account.xyz or secure-paypal-login.com).
    """
    labels = [l for l in host.split(".") if l]
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host

    for brand in COMMON_BRANDS:
        if brand in host or brand in path.lower():
            if not registrable.startswith(brand + "."):
                return True
    return False


def explain_features(features: dict) -> list:
    """Turn a feature dict into a list of human-readable observations."""
    notes = []
    if features.get("has_ip_host"):
        notes.append("Host is a raw IP address instead of a domain name.")
    if features.get("is_shortener"):
        notes.append("URL uses a known link-shortening service, hiding the real destination.")
    if features.get("suspicious_tld"):
        notes.append("Top-level domain is one commonly abused for cheap/disposable registrations.")
    if features.get("brand_in_subdomain_or_path"):
        notes.append("A known brand name appears in the URL but isn't the actual registered domain.")
    if not features.get("uses_https"):
        notes.append("Connection is not HTTPS.")
    if features.get("num_subdomains", 0) >= 3:
        notes.append("Unusually high number of subdomains.")
    if features.get("count_suspicious_keywords", 0) >= 2:
        notes.append("Multiple credential/urgency-related keywords found in the URL.")
    if features.get("host_entropy", 0) > 4.0:
        notes.append("Hostname looks randomly generated (high entropy).")
    if features.get("punycode"):
        notes.append("Domain uses punycode encoding, sometimes used for homograph attacks.")
    if features.get("num_at_symbols", 0) > 0:
        notes.append("URL contains an '@' symbol, which can mask the real destination.")
    if features.get("excessive_length"):
        notes.append("URL is unusually long.")
    return notes
