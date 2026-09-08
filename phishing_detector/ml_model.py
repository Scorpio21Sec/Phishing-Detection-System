"""
ml_model.py
-----------
Trains a scikit-learn classifier on engineered URL features and exposes
predict_proba-style scoring. Complements (does not replace) the rule
engine in rules.py -- see detector.py for how the two are combined.
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

from .url_features import extract_url_features
from .data_gen import generate_synthetic_dataset

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.joblib")

# Fixed feature order -- must match keys returned by extract_url_features.
FEATURE_KEYS = [
    "url_length", "host_length", "path_length", "num_dots", "num_hyphens",
    "num_at_symbols", "num_digits", "num_subdomains", "has_ip_host",
    "uses_https", "has_port", "double_slash_in_path", "is_shortener",
    "suspicious_tld", "host_entropy", "count_suspicious_keywords",
    "brand_in_subdomain_or_path", "punycode", "excessive_length",
    "many_query_params",
]


def featurize(url: str) -> np.ndarray:
    feats = extract_url_features(url)
    return np.array([_to_num(feats[k]) for k in FEATURE_KEYS], dtype=float)


def _to_num(v):
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    return float(v)


def featurize_batch(urls) -> np.ndarray:
    return np.vstack([featurize(u) for u in urls])


class PhishingURLModel:
    def __init__(self, clf=None):
        self.clf = clf

    def train(self, urls=None, labels=None, n_per_class=500, test_size=0.2, verbose=True):
        if urls is None or labels is None:
            urls, labels = generate_synthetic_dataset(n_per_class=n_per_class)

        X = featurize_batch(urls)
        y = np.array(labels)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        self.clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42,
            class_weight="balanced",
        )
        self.clf.fit(X_train, y_train)

        if verbose:
            preds = self.clf.predict(X_test)
            probs = self.clf.predict_proba(X_test)[:, 1]
            print("=== Held-out test performance ===")
            print(classification_report(y_test, preds, target_names=["legit", "phishing"]))
            print(f"ROC-AUC: {roc_auc_score(y_test, probs):.4f}")

        return self

    def predict_proba(self, url: str) -> float:
        if self.clf is None:
            raise RuntimeError("Model not trained/loaded. Call train() or load().")
        X = featurize(url).reshape(1, -1)
        return float(self.clf.predict_proba(X)[0, 1])

    def predict_proba_batch(self, urls) -> np.ndarray:
        X = featurize_batch(urls)
        return self.clf.predict_proba(X)[:, 1]

    def feature_importances(self) -> dict:
        if self.clf is None:
            raise RuntimeError("Model not trained/loaded.")
        return dict(sorted(
            zip(FEATURE_KEYS, self.clf.feature_importances_),
            key=lambda kv: kv[1], reverse=True,
        ))

    def save(self, path: str = MODEL_PATH):
        joblib.dump(self.clf, path)

    def load(self, path: str = MODEL_PATH):
        self.clf = joblib.load(path)
        return self

    @classmethod
    def load_or_train(cls, path: str = MODEL_PATH):
        model = cls()
        if os.path.exists(path):
            model.load(path)
        else:
            model.train(verbose=False)
            model.save(path)
        return model
