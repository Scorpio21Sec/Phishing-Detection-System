from .detector import PhishingDetector, DetectionResult
from .rules import score_url, score_email
from .ml_model import PhishingURLModel

__all__ = [
    "PhishingDetector",
    "DetectionResult",
    "score_url",
    "score_email",
    "PhishingURLModel",
]

__version__ = "0.1.0"
