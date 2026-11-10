import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from app.core.config import Settings, get_settings
from app.services.feature_extractor import FEATURE_NAMES, ExtractedFeatures


@dataclass
class MLPredictionResult:
    model_loaded: bool
    model_name: Optional[str]
    model_version: Optional[str]
    phishing_probability: Optional[float]  # P(phishing) in [0, 1], or None if untrained
    model_confidence: Optional[float]      # Classifier certainty max(p, 1-p) in [0.5, 1.0], separate from risk score
    predicted_label: Optional[str]         # "phishing" | "benign" | None
    status_message: str


class MLModelPredictor:
    """Loads a trained scikit-learn / XGBoost Joblib pipeline and runs static URL feature inference."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        artifacts_dir = Path(__file__).resolve().parent / "artifacts"
        self.model_path = Path(self.settings.ml_model_path) if self.settings.ml_model_path else artifacts_dir / "phishing_url_model.joblib"
        self.metadata_path = Path(self.settings.ml_metadata_path) if self.settings.ml_metadata_path else artifacts_dir / "model_metadata.json"

        self.pipeline: Any = None
        self.metadata: Dict[str, Any] = {}
        self._load_error: Optional[str] = None
        self._load()

    def _load(self) -> None:
        if not self.model_path.exists():
            self._load_error = "ML model artifact not yet trained or available."
            return
        try:
            self.pipeline = joblib.load(self.model_path)
            if self.metadata_path.exists():
                self.metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.pipeline = None
            self._load_error = f"Failed to load ML model artifact: {type(exc).__name__}"

    def reload(self) -> None:
        self.pipeline = None
        self.metadata = {}
        self._load_error = None
        self._load()

    @property
    def is_ready(self) -> bool:
        return self.pipeline is not None

    def get_status(self) -> Dict[str, Any]:
        return {
            "model_loaded": self.is_ready,
            "status": "trained" if self.is_ready else "not_trained",
            "message": (
                "Trained phishing URL classifier is active."
                if self.is_ready
                else (self._load_error or "ML model not yet trained.")
            ),
            "model_name": self.metadata.get("selected_model") if self.is_ready else None,
            "model_version": self.metadata.get("model_version") if self.is_ready else None,
            "trained_at": self.metadata.get("trained_at") if self.is_ready else None,
            "dataset": self.metadata.get("dataset") if self.is_ready else None,
            "feature_names": list(self.metadata.get("feature_names", FEATURE_NAMES)),
            "metrics": self.metadata.get("test_metrics") if self.is_ready else None,
        }

    def predict(self, features: ExtractedFeatures) -> MLPredictionResult:
        if not self.is_ready:
            return MLPredictionResult(
                model_loaded=False,
                model_name=None,
                model_version=None,
                phishing_probability=None,
                model_confidence=None,
                predicted_label=None,
                status_message=self._load_error or "ML model not yet trained; classification skipped.",
            )

        ordered_names: List[str] = self.metadata.get("feature_names") or list(FEATURE_NAMES)
        vector = np.array([[float(features.numeric[name]) for name in ordered_names]], dtype=np.float64)

        if hasattr(self.pipeline, "predict_proba"):
            probs = self.pipeline.predict_proba(vector)[0]
            # Assume class 1 = phishing, class 0 = benign
            classes = list(getattr(self.pipeline, "classes_", [0, 1]))
            pos_idx = classes.index(1) if 1 in classes else 1
            phishing_prob = float(np.clip(probs[pos_idx], 0.0, 1.0))
        else:
            pred = int(self.pipeline.predict(vector)[0])
            phishing_prob = 1.0 if pred == 1 else 0.0

        confidence = float(max(phishing_prob, 1.0 - phishing_prob))
        predicted_label = "phishing" if phishing_prob >= 0.5 else "benign"

        return MLPredictionResult(
            model_loaded=True,
            model_name=self.metadata.get("selected_model"),
            model_version=self.metadata.get("model_version"),
            phishing_probability=round(phishing_prob, 4),
            model_confidence=round(confidence, 4),
            predicted_label=predicted_label,
            status_message="ML inference completed.",
        )

