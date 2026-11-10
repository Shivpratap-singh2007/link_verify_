from pathlib import Path

from app.core.config import Settings
from app.ml.predictor import MLModelPredictor
from app.services.feature_extractor import extract_url_features


def test_predictor_handles_missing_model_honestly(tmp_path: Path):
    settings = Settings(
        ml_model_path=str(tmp_path / "missing_model.joblib"),
        ml_metadata_path=str(tmp_path / "missing_meta.json"),
    )
    predictor = MLModelPredictor(settings)
    assert predictor.is_ready is False
    status = predictor.get_status()
    assert status["model_loaded"] is False
    assert status["status"] == "not_trained"

    feat = extract_url_features("https://example.com")
    res = predictor.predict(feat)
    assert res.model_loaded is False
    assert res.phishing_probability is None
    assert res.model_confidence is None

