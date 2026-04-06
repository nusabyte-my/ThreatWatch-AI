"""
Loads model bundle and exposes predict().
Lazy-loaded singleton — no cold-start on import.
"""
import os
import joblib
import numpy as np
from typing import Optional
from app.config import settings
from app.ml.preprocessor import preprocess

_bundle: Optional[dict] = None


def _load():
    global _bundle
    if _bundle is None:
        if not os.path.exists(settings.model_path):
            raise FileNotFoundError(
                f"Model not found at {settings.model_path}. Run: python -m app.ml.train"
            )
        _bundle = joblib.load(settings.model_path)
    return _bundle


def predict_ml(text: str) -> dict:
    """
    Returns:
        {
            "scam_prob": float,   # 0.0–1.0
            "label": int,         # 0=safe, 1=scam
            "confidence": float,  # max class probability
        }
    """
    bundle = _load()
    processed = preprocess(text)

    lr_prob = bundle["lr"].predict_proba([processed])[0]
    nb_prob = bundle["nb"].predict_proba([processed])[0]

    # Weighted ensemble: LR 70%, NB 30%
    ensemble_prob = 0.7 * lr_prob + 0.3 * nb_prob
    scam_prob = float(ensemble_prob[1])
    label = int(scam_prob >= 0.5)

    return {
        "scam_prob": round(scam_prob, 4),
        "label": label,
        "confidence": round(float(max(ensemble_prob)), 4),
    }
