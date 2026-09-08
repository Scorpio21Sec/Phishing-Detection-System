"""
Basic smoke tests for the phishing detection system.
Run with: python -m pytest test_detector.py -v
"""

from phishing_detector.url_features import extract_url_features
from phishing_detector.rules import score_url, score_email, verdict_from_score
from phishing_detector.detector import PhishingDetector


def test_ip_host_detected():
    feats = extract_url_features("http://192.168.0.1/login")
    assert feats["has_ip_host"] is True


def test_brand_lookalike_detected():
    feats = extract_url_features("http://paypal-secure.totallylegit.xyz/login")
    assert feats["brand_in_subdomain_or_path"] is True


def test_legit_url_low_score():
    result = score_url("https://www.google.com/search?q=weather")
    assert result["verdict"] in ("likely_safe", "suspicious")
    assert result["score"] < 55


def test_obvious_phishing_high_score():
    result = score_url("http://192.168.1.5/paypal-secure-login.xyz/verify")
    assert result["score"] >= 40


def test_verdict_thresholds():
    assert verdict_from_score(0) == "likely_safe"
    assert verdict_from_score(30) == "suspicious"
    assert verdict_from_score(80) == "phishing"


def test_email_scoring_flags_mismatch():
    email_data = {
        "from_addr": '"PayPal Support" <security@totally-not-paypal.xyz>',
        "reply_to": "someone@another-domain.ru",
        "subject": "Urgent: verify your account",
        "body": "Click here http://bit.ly/abc123 to verify your account now!",
        "return_path": "bounce@yet-another.cn",
    }
    result = score_email(email_data)
    assert result["score"] >= 30
    assert any("reply-to" in r.lower() for r in result["reasons"])


def test_detector_end_to_end_url():
    detector = PhishingDetector()
    result = detector.check_url("http://secure-paypal-login.xyz/verify-account")
    assert result.verdict in ("suspicious", "phishing")
    assert 0 <= result.score <= 100


def test_detector_end_to_end_email():
    detector = PhishingDetector()
    result = detector.check_email({
        "from_addr": "notifications@amazon.com",
        "subject": "Your order has shipped",
        "body": "Your package is on its way. Track it at https://www.amazon.com/track",
    })
    assert 0 <= result.score <= 100
