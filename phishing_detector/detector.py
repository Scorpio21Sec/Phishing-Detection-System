"""
detector.py
-----------
Public entry point for the system. Combines:

  1. Rule-based scoring (rules.py) -- transparent, deterministic, fast.
  2. ML model probability (ml_model.py) -- catches patterns too subtle
     or numerous for hand-written rules.

Final score is a weighted blend, and the verdict + reasons are always
traceable back to concrete signals.
"""

from dataclasses import dataclass, field
from typing import Optional

from .rules import score_url as rule_score_url, score_email as rule_score_email, verdict_from_score
from .ml_model import PhishingURLModel


@dataclass
class DetectionResult:
    input_type: str
    score: int
    verdict: str
    rule_score: int
    ml_probability: Optional[float]
    reasons: list = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def summary(self) -> str:
        lines = [
            f"Verdict: {self.verdict.upper()}  (score: {self.score}/100)",
            f"  rule-based score: {self.rule_score}/100"
            + (f" | ML phishing probability: {self.ml_probability:.1%}" if self.ml_probability is not None else ""),
        ]
        if self.reasons:
            lines.append("  Reasons:")
            lines.extend(f"    - {r}" for r in self.reasons)
        return "\n".join(lines)


class PhishingDetector:
    """
    Usage:
        detector = PhishingDetector()          # trains/loads ML model automatically
        result = detector.check_url("http://paypal-verify.xyz/login")
        result = detector.check_email({...})
        print(result.summary())
    """

    def __init__(self, ml_weight: float = 0.5, use_ml: bool = True):
        self.ml_weight = ml_weight
        self.use_ml = use_ml
        self._model = PhishingURLModel.load_or_train() if use_ml else None

    def check_url(self, url: str) -> DetectionResult:
        rule_result = rule_score_url(url)
        ml_prob = self._model.predict_proba(url) if self.use_ml else None
        final_score = self._blend(rule_result["score"], ml_prob)

        return DetectionResult(
            input_type="url",
            score=final_score,
            verdict=verdict_from_score(final_score),
            rule_score=rule_result["score"],
            ml_probability=ml_prob,
            reasons=rule_result["reasons"],
            details={"features": rule_result["features"], "rule_hits": rule_result["rule_hits"]},
        )

    def check_email(self, email_data: dict) -> DetectionResult:
        rule_result = rule_email = rule_score_email(email_data)

        ml_prob = None
        if self.use_ml:
            urls = rule_result["features"].get("urls", [])
            if urls:
                probs = [self._model.predict_proba(u) for u in urls]
                ml_prob = max(probs)

        final_score = self._blend(rule_result["score"], ml_prob)

        return DetectionResult(
            input_type="email",
            score=final_score,
            verdict=verdict_from_score(final_score),
            rule_score=rule_result["score"],
            ml_probability=ml_prob,
            reasons=rule_result["reasons"],
            details={
                "features": {k: v for k, v in rule_result["features"].items()
                             if k not in ("url_feature_list",)},
                "rule_hits": rule_result["rule_hits"],
                "worst_link": rule_result.get("worst_link"),
            },
        )

    def _blend(self, rule_score: int, ml_prob) -> int:
        if ml_prob is None:
            return rule_score
        ml_score = round(ml_prob * 100)
        blended = (1 - self.ml_weight) * rule_score + self.ml_weight * ml_score
        return int(round(min(100, max(0, blended))))
