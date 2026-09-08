#!/usr/bin/env python3
"""
cli.py
------
Command-line interface for the phishing detection system.

Examples:
    python cli.py url "http://paypal-secure-login.xyz/verify"
    python cli.py url-batch urls.txt
    python cli.py email --from "PayPal <security@totally-not-paypal.xyz>" \\
                         --subject "Urgent: verify your account" \\
                         --body "Click here http://bit.ly/abc123 to verify."
    python cli.py train
    python cli.py demo
"""

import argparse
import json
import sys

from phishing_detector import PhishingDetector
from phishing_detector.ml_model import PhishingURLModel


def cmd_url(args):
    detector = PhishingDetector()
    result = detector.check_url(args.url)
    if args.json:
        print(json.dumps(result.__dict__, indent=2, default=str))
    else:
        print(result.summary())


def cmd_url_batch(args):
    detector = PhishingDetector()
    with open(args.file) as f:
        urls = [line.strip() for line in f if line.strip()]
    for url in urls:
        result = detector.check_url(url)
        print(f"[{result.verdict.upper():>12}] ({result.score:>3}/100)  {url}")


def cmd_email(args):
    detector = PhishingDetector()
    email_data = {
        "from_addr": args.from_addr or "",
        "reply_to": args.reply_to or "",
        "subject": args.subject or "",
        "body": args.body or "",
        "return_path": args.return_path or "",
    }
    result = detector.check_email(email_data)
    if args.json:
        print(json.dumps(result.__dict__, indent=2, default=str))
    else:
        print(result.summary())


def cmd_email_file(args):
    detector = PhishingDetector()
    from phishing_detector.email_features import parse_eml
    with open(args.file, "rb") as f:
        email_data = parse_eml(f.read())
    result = detector.check_email(email_data)
    print(result.summary())


def cmd_train(args):
    model = PhishingURLModel()
    model.train(n_per_class=args.n_per_class)
    model.save()
    print(f"\nModel saved to {model.__class__.__module__}")
    print("\nTop feature importances:")
    for k, v in list(model.feature_importances().items())[:10]:
        print(f"  {k:35s} {v:.4f}")


def cmd_demo(args):
    detector = PhishingDetector()
    samples = [
        "https://www.google.com/search?q=weather",
        "http://192.168.1.5/paypal/login.php",
        "http://secure-paypal-login.xyz/verify-account",
        "https://github.com/anthropics",
        "http://bit.ly/3xK9pL2",
        "http://apple.com.account-recovery.top/signin",
    ]
    for url in samples:
        result = detector.check_url(url)
        print(f"\nURL: {url}")
        print(result.summary())

    print("\n" + "=" * 60)
    print("Sample email check")
    print("=" * 60)
    email_data = {
        "from_addr": '"PayPal Support" <security@totally-not-paypal.xyz>',
        "reply_to": "",
        "subject": "Urgent: Your account will be suspended",
        "body": (
            "Dear Customer,\n\nWe noticed unusual activity on your account. "
            "Click here to verify your identity immediately: "
            "http://bit.ly/3xK9pL2\n\nFailure to act within 24 hours will "
            "result in suspension.\n\nThank you."
        ),
        "return_path": "bounce@some-other-domain.ru",
    }
    result = detector.check_email(email_data)
    print(result.summary())


def main():
    parser = argparse.ArgumentParser(description="Phishing Detection System")
    sub = parser.add_subparsers(dest="command", required=True)

    p_url = sub.add_parser("url", help="Check a single URL")
    p_url.add_argument("url")
    p_url.add_argument("--json", action="store_true")
    p_url.set_defaults(func=cmd_url)

    p_batch = sub.add_parser("url-batch", help="Check URLs from a text file (one per line)")
    p_batch.add_argument("file")
    p_batch.set_defaults(func=cmd_url_batch)

    p_email = sub.add_parser("email", help="Check email indicators")
    p_email.add_argument("--from", dest="from_addr", default="")
    p_email.add_argument("--reply-to", dest="reply_to", default="")
    p_email.add_argument("--subject", default="")
    p_email.add_argument("--body", default="")
    p_email.add_argument("--return-path", dest="return_path", default="")
    p_email.add_argument("--json", action="store_true")
    p_email.set_defaults(func=cmd_email)

    p_email_file = sub.add_parser("email-file", help="Check a raw .eml file")
    p_email_file.add_argument("file")
    p_email_file.set_defaults(func=cmd_email_file)

    p_train = sub.add_parser("train", help="(Re)train the ML model on synthetic data")
    p_train.add_argument("--n-per-class", type=int, default=500)
    p_train.set_defaults(func=cmd_train)

    p_demo = sub.add_parser("demo", help="Run a demo over sample URLs/emails")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
