# Phishing-Detection-System

A hybrid **rule-based + machine learning** system for flagging suspicious URLs
and email indicators. Built as a defensive security tool: it helps analysts,
inboxes, or pipelines triage links and messages, with every verdict backed by
human-readable reasons.

## How it works

```
                ┌───────────────────┐
   URL / Email  │  Feature Extractor │  → 20 URL signals (entropy, IP host,
   ───────────► │ (url_features.py,  │    brand lookalikes, TLD, shorteners…)
                │  email_features.py)│  → email signals (sender mismatch,
                └─────────┬──────────┘    urgency language, link risk…)
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
     ┌───────────────┐        ┌────────────────────┐
     │  Rule Engine   │        │   ML Model          │
     │  (rules.py)    │        │   (ml_model.py)      │
     │  weighted,      │        │   RandomForest over │
     │  explainable    │        │   engineered features│
     │  0–100 score    │        │   phishing probability│
     └───────┬────────┘        └──────────┬──────────┘
             │                            │
             └───────────► Blend ◄────────┘
                     (detector.py)
                             │
                             ▼
                 Verdict: likely_safe / suspicious / phishing
                 + reasons + rule hits + ML probability
```

- **Rule engine** — deterministic, hand-tuned weights on things like "host is
  a raw IP," "brand name in a lookalike domain," "uses a link shortener,"
  "urgency language + generic greeting." Always gives a plain-English reason
  list, so a human can see exactly why something was flagged.
- **ML model** — a `RandomForestClassifier` trained on the same engineered
  features, meant to catch combinations/patterns that are hard to hand-encode
  as rules, and to generalize better to unseen phishing variants.
- **Detector** — blends the two into a single 0–100 score and a verdict
  (`likely_safe`, `suspicious`, `phishing`), so you get both an explainable
  and a learned signal.

## Project layout

```
phishing_detector/
├── phishing_detector/
│   ├── __init__.py          # public API
│   ├── url_features.py      # rule-based URL feature extraction
│   ├── email_features.py    # rule-based email indicator extraction
│   ├── rules.py              # weighted rule scoring engine
│   ├── data_gen.py           # synthetic training data generator
│   ├── ml_model.py           # RandomForest training/inference
│   └── detector.py           # combines rules + ML into final verdict
├── cli.py                     # command-line interface
├── test_detector.py           # unit tests
├── requirements.txt
└── README.md
```

## Setup

```bash
pip install -r requirements.txt
```

## Usage

### Command line

```bash
# Check a single URL
python cli.py url "http://secure-paypal-login.xyz/verify-account"

# Check a batch of URLs from a file (one per line)
python cli.py url-batch urls.txt

# Check email indicators directly
python cli.py email \
  --from '"PayPal Support" <security@totally-not-paypal.xyz>' \
  --subject "Urgent: verify your account" \
  --body "Click here http://bit.ly/abc123 to verify your account now!"

# Check a raw .eml file
python cli.py email-file suspicious_message.eml

# (Re)train the ML model
python cli.py train

# Run the built-in demo over sample URLs/emails
python cli.py demo

# Start the local browser dashboard
python dashboard.py
```

Open `http://127.0.0.1:8000` after starting the dashboard. It provides URL and
email checks backed by the same detector API as the CLI. The dashboard is
local-only and uses Python's standard library, so no web framework is needed.

### As a library

```python
from phishing_detector import PhishingDetector

detector = PhishingDetector()

result = detector.check_url("http://apple.com.account-recovery.top/signin")
print(result.summary())
# Verdict: PHISHING  (score: 67/100)
#   rule-based score: 34/100 | ML phishing probability: 99.5%
#   Reasons:
#     - Top-level domain is one commonly abused for cheap/disposable registrations.
#     - A known brand name appears in the URL but isn't the actual registered domain.
#     - Connection is not HTTPS.
#     - Multiple credential/urgency-related keywords found in the URL.

result = detector.check_email({
    "from_addr": '"PayPal Support" <security@totally-not-paypal.xyz>',
    "subject": "Urgent: Your account will be suspended",
    "body": "Click here to verify: http://bit.ly/3xK9pL2",
    "return_path": "bounce@some-other-domain.ru",
})
print(result.verdict, result.score)
```

## What it checks

**URLs:** IP-address hosts, `@` obfuscation, punycode/homograph domains,
brand names outside their real registered domain, known link shorteners,
high-risk TLDs, excessive subdomains/length, high hostname entropy,
credential/urgency keywords, missing HTTPS.

**Emails:** From/Reply-To/Return-Path domain mismatches, spoofed display
names impersonating a brand, urgency/pressure language, generic greetings,
requests for sensitive info (passwords, SSNs, card numbers), and the risk
score of every embedded link (worst link can push the whole email to
"phishing" even if the surrounding text looks clean).

## Important caveats

- **Training data is synthetic** (`data_gen.py` generates templated legit vs.
  phishing-style URLs). It's enough to make the pipeline run end-to-end and
  demonstrate the approach, but a synthetic/templated dataset is far easier
  to separate than the real world — don't read the near-perfect demo metrics
  as real-world accuracy. For production use, retrain on a real labeled
  corpus (e.g. [PhishTank](https://phishtank.org/), [OpenPhish](https://openphish.com/),
  or your own logged corpus) by passing `urls, labels` into
  `PhishingURLModel.train()`.
- **This is a triage aid, not a firewall.** Use it to prioritize analyst
  review or add a warning banner — not as the sole gate before blocking
  traffic or deleting mail, especially while running on synthetic training
  data.
- The brand and keyword lists in `url_features.py` / `email_features.py` are
  intentionally small and illustrative; extend them for your own threat
  model.

## Running tests

```bash
python -m pytest test_detector.py -v
```
