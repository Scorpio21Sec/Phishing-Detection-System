"""
data_gen.py
-----------
Generates a synthetic labeled dataset of URLs for training/demoing the
ML model. This is NOT a substitute for a real-world labeled dataset
(e.g. PhishTank, OpenPhish, or an internal corpus) -- it exists so the
project runs end-to-end out of the box. Swap load_training_urls() for
a real CSV loader when you have real data (see README).
"""

import random

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "nytimes.com",
    "amazon.com", "apple.com", "microsoft.com", "stackoverflow.com",
    "reddit.com", "linkedin.com", "spotify.com", "dropbox.com",
    "paypal.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "usps.com", "fedex.com", "irs.gov", "coinbase.com",
    "netflix.com", "instagram.com", "facebook.com", "outlook.com",
]

LEGIT_PATHS = [
    "", "/login", "/account/settings", "/help/contact", "/products",
    "/blog/2024/updates", "/user/profile", "/docs/api", "/search?q=weather",
    "/news/technology", "/watch?v=abc123", "/cart/checkout",
]

PHISH_TEMPLATES = [
    "http://{brand}-secure-login.{tld}/verify",
    "http://{brand}.account-update.{tld}/signin",
    "http://secure-{brand}-alert.{tld}/confirm",
    "http://{ip}/{brand}/login.php",
    "http://{brand}.{sub}.{tld}/verify-account",
    "http://bit.ly/{rand}",
    "http://{rand}-{brand}.{tld}",
    "http://{brand}support.{tld}/reset-password?user={rand}",
    "http://{brand}.com.{tld}/session/expired",
    "http://xn--{rand}-{brand}.{tld}/login",
]

BRANDS = ["paypal", "apple", "microsoft", "amazon", "netflix", "chase",
          "wellsfargo", "irs", "usps", "fedex", "coinbase", "instagram"]

BAD_TLDS = ["xyz", "top", "click", "loan", "kim", "review", "gq", "tk", "cricket"]


def _rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _rand_str(n=8):
    import string
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def generate_synthetic_dataset(n_per_class: int = 400):
    """Returns (urls: list[str], labels: list[int]) where 1 = phishing, 0 = legit."""
    urls, labels = [], []

    for _ in range(n_per_class):
        domain = random.choice(LEGIT_DOMAINS)
        path = random.choice(LEGIT_PATHS)
        scheme = "https"
        urls.append(f"{scheme}://{domain}{path}")
        labels.append(0)

    for _ in range(n_per_class):
        template = random.choice(PHISH_TEMPLATES)
        url = template.format(
            brand=random.choice(BRANDS),
            tld=random.choice(BAD_TLDS),
            ip=_rand_ip(),
            sub=_rand_str(5),
            rand=_rand_str(6),
        )
        urls.append(url)
        labels.append(1)

    combined = list(zip(urls, labels))
    random.shuffle(combined)
    urls, labels = zip(*combined)
    return list(urls), list(labels)
