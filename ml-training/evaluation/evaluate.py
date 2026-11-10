"""Independent evaluation script for the persisted phishing URL classifier."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
ARTIFACTS_DIR = ROOT_DIR / "backend" / "app" / "ml" / "artifacts"
TEST_SPLIT_PATH = Path(__file__).resolve().parent.parent / "datasets" / "heldout_test_split.csv"


def main() -> None:
    model_path = ARTIFACTS_DIR / "phishing_url_model.joblib"
    metadata_path = ARTIFACTS_DIR / "model_metadata.json"

    if not model_path.exists():
        print("Model not yet trained: phishing_url_model.joblib does not exist.")
        return

    model = joblib.load(model_path)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {}
    print(f"Loaded model: {metadata.get('selected_model', 'unknown')} (version {metadata.get('model_version', 'n/a')})")

    if not TEST_SPLIT_PATH.exists():
        print("Held-out test split CSV not found; displaying stored test metrics:")
        print(json.dumps(metadata.get("test_metrics", {}), indent=2))
        return

    test_df = pd.read_csv(TEST_SPLIT_PATH)
    feature_names = metadata.get("feature_names", [c for c in test_df.columns if c != "label"])
    X_test = test_df[feature_names].to_numpy(dtype=np.float64)
    y_test = test_df["label"].to_numpy()

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\nClassification Report (0=benign, 1=phishing):")
    print(classification_report(y_test, y_pred, digits=4))
    print("Confusion Matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(y_test, y_pred))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")


if __name__ == "__main__":
    main()

