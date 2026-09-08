"""
rules.py
--------
Transparent, hand-tuned rule-based scoring. This is the "explainable"
half of the system: every point added to the score has a stated reason,
so results can always be justified to a human analyst even when the ML
model disagrees.

Score is 0-100. Thresholds below map score -> verdict label.
"""

from .url_features import extract_url_features, explain_features
from .email_features import extract_email_features, explain_email_features

# (weight, feature_key, condition_fn) tuples for URL scoring.
URL_RULES = [
    (20, "has_ip_host", lambda v: v is True),
    (15, "brand_in_subdomain_or_path", lambda v: v is True),
    (10, "is_shortener", lambda v: v is True),
    (10, "suspicious_tld", lambda v: v is True),
    (8, "punycode", lambda v: v is True),
    (8, "num_at_symbols", lambda v: v > 0),
    (6, "double_slash_in_path", lambda v: v is True),
    (5, "num_subdomains", lambda v: v >= 3),
    (5, "excessive_length", lambda v: v is True),
    (5, "count_suspicious_keywords", lambda v: v >= 2),
    (4, "host_entropy", lambda v: v > 4.0),
    (4, "uses_https", lambda v: v is False),
]

EMAIL_RULES = [
    (15, "display_name_brand_spoof", lambda v: v is True),
    (12, "any_link_brand_lookalike", lambda v: v is True),
    (10, "reply_to_mismatch", lambda v: v is True),
    (8, "return_path_mismatch", lambda v: v is True),
    (10, "any_link_is_ip", lambda v: v is True),
    (8, "any_link_is_shortener", lambda v: v is True),
    (10, "requests_sensitive_info", lambda v: v is True),
    (8, "count_urgency_phrases", lambda v: v >= 2),
    (5, "generic_greeting", lambda v: v is True),
    (5, "any_link_suspicious_tld", lambda v: v is True),
    (4, "all_caps_words", lambda v: v >= 3),
    (4, "subject_has_re_fwd_spam_pattern", lambda v: v is True),
]


def _apply_rules(features: dict, rules: list):
    score = 0
    hits = []
    for weight, key, cond in rules:
        value = features.get(key)
        if value is not None and cond(value):
            score += weight
            hits.append((key, weight))
    return min(score, 100), hits


def verdict_from_score(score: int) -> str:
    if score >= 55:
        return "phishing"
    if score >= 25:
        return "suspicious"
    return "likely_safe"


def score_url(url: str) -> dict:
    features = extract_url_features(url)
    score, hits = _apply_rules(features, URL_RULES)
    return {
        "input": url,
        "score": score,
        "verdict": verdict_from_score(score),
        "reasons": explain_features(features),
        "rule_hits": hits,
        "features": features,
    }


def score_email(email_data: dict) -> dict:
    features = extract_email_features(email_data)
    score, hits = _apply_rules(features, EMAIL_RULES)

    # Fold in the worst individual link score too -- a single very bad
    # link should be able to push the whole email over threshold even if
    # nothing else about the email looks off.
    worst_link_score = 0
    worst_link = None
    for url in features.get("urls", []):
        link_result = score_url(url)
        if link_result["score"] > worst_link_score:
            worst_link_score = link_result["score"]
            worst_link = url
    combined_score = min(100, max(score, round(0.6 * worst_link_score + 0.4 * score)))

    return {
        "score": combined_score,
        "verdict": verdict_from_score(combined_score),
        "reasons": explain_email_features(features) + explain_features_for_worst_link(worst_link),
        "rule_hits": hits,
        "worst_link": worst_link,
        "worst_link_score": worst_link_score,
        "features": features,
    }


def explain_features_for_worst_link(url):
    if not url:
        return []
    feats = extract_url_features(url)
    reasons = explain_features(feats)
    return [f"[link: {url}] {r}" for r in reasons]
