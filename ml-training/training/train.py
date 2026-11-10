"""Train, compare, select, and persist the phishing URL classifier with strict leakage prevention."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from fetch_dataset import VALIDATED_CSV, download_benchmark_dataset, validate_and_normalize_dataset
from preprocess import FEATURE_NAMES, build_feature_matrix, split_train_val_test

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
ARTIFACTS_DIR = ROOT_DIR / "backend" / "app" / "ml" / "artifacts"
DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"
TEST_SPLIT_OUT = DATASETS_DIR / "heldout_test_split.csv"


def compute_metrics(y_true: pd.Series, y_pred: np.ndarray, y_prob: np.ndarray | None) -> Dict[str, Any]:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    metrics: Dict[str, Any] = {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "confusion_matrix": {
            "tn": int(cm[0][0]),
            "fp": int(cm[0][1]),
            "fn": int(cm[1][0]),
            "tp": int(cm[1][1]),
        },
    }
    if y_prob is not None:
        metrics["roc_auc"] = round(float(roc_auc_score(y_true, y_prob)), 4)
    return metrics


def evaluate_model(model: Pipeline, x_data: pd.DataFrame, y_data: pd.Series) -> Dict[str, Any]:
    y_pred = model.predict(x_data.to_numpy(dtype=np.float64))
    y_prob = (
        model.predict_proba(x_data.to_numpy(dtype=np.float64))[:, 1]
        if hasattr(model, "predict_proba")
        else None
    )
    return compute_metrics(y_data, y_pred, y_prob)


def run_training(max_rows: int | None = None) -> Dict[str, Any]:
    if not VALIDATED_CSV.exists():
        raw_path = download_benchmark_dataset()
        df = validate_and_normalize_dataset(raw_path)
    else:
        df = pd.read_csv(VALIDATED_CSV)

    x_df, y_ser, meta_df = build_feature_matrix(df, max_rows=max_rows)
    splits = split_train_val_test(x_df, y_ser, meta_df, seed=42)

    X_train, y_train = splits["X_train"], splits["y_train"]
    X_val, y_val = splits["X_val"], splits["y_val"]
    X_test, y_test = splits["X_test"], splits["y_test"]

    print(f"Split sizes -> train: {len(X_train)}, val: {len(X_val)}, test: {len(X_test)}")

    # Candidate pipelines (fitted ONLY on X_train)
    candidates: dict[str, Pipeline] = {
        "majority_baseline": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("clf", DummyClassifier(strategy="most_frequent")),
        ]),
        "logistic_regression": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, random_state=42)),
        ]),
        "random_forest": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("clf", RandomForestClassifier(
                n_estimators=200,
                max_depth=18,
                min_samples_leaf=2,
                n_jobs=-1,
                random_state=42,
            )),
        ]),
        "xgboost": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("clf", XGBClassifier(
                n_estimators=250,
                max_depth=6,
                learning_rate=0.08,
                subsample=0.85,
                colsample_bytree=0.85,
                eval_metric="logloss",
                random_state=42,
                n_jobs=-1,
            )),
        ]),
    }

    val_results: dict[str, Dict[str, Any]] = {}
    for name, pipe in candidates.items():
        print(f"Training {name} ...")
        pipe.fit(X_train.to_numpy(dtype=np.float64), y_train.to_numpy())
        metrics = evaluate_model(pipe, X_val, y_val)
        val_results[name] = metrics
        print(f"  Validation metrics ({name}): {metrics}")

    # Select best real ML model (exclude naive majority baseline) by validation F1 then ROC-AUC
    real_models = [k for k in candidates if k != "majority_baseline"]
    best_name = max(
        real_models,
        key=lambda k: (val_results[k]["f1_score"], val_results[k].get("roc_auc", 0.0)),
    )
    best_pipeline = candidates[best_name]
    print(f"\nSelected best model: {best_name}")

    # Evaluate selected model ONCE on held-out test set
    test_metrics = evaluate_model(best_pipeline, X_test, y_test)
    print(f"Held-out TEST metrics ({best_name}): {test_metrics}")

    # Slice evaluation on test set (HTTPS vs HTTP)
    https_mask = X_test["is_https"] == 1.0
    http_mask = X_test["is_https"] == 0.0
    slice_metrics = {}
    if https_mask.sum() > 10 and y_test[https_mask].nunique() > 1:
        slice_metrics["https_urls"] = {
            "count": int(https_mask.sum()),
            **evaluate_model(best_pipeline, X_test[https_mask], y_test[https_mask]),
        }
    if http_mask.sum() > 10 and y_test[http_mask].nunique() > 1:
        slice_metrics["http_urls"] = {
            "count": int(http_mask.sum()),
            **evaluate_model(best_pipeline, X_test[http_mask], y_test[http_mask]),
        }

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = ARTIFACTS_DIR / "phishing_url_model.joblib"
    metadata_path = ARTIFACTS_DIR / "model_metadata.json"

    joblib.dump(best_pipeline, model_path)

    # Save held-out test features+labels for independent evaluation script
    test_export = X_test.copy()
    test_export["label"] = y_test.values
    test_export.to_csv(TEST_SPLIT_OUT, index=False)

    metadata = {
        "selected_model": best_name,
        "model_version": "1.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "name": "Hannousse & Yahiouche (2021) Phishing URL Benchmark Dataset",
            "source_url": "https://huggingface.co/datasets/pirocheto/phishing-url",
            "total_evaluated_rows": int(len(x_df)),
            "train_rows": int(len(X_train)),
            "validation_rows": int(len(X_val)),
            "test_rows": int(len(X_test)),
            "phishing_rate_test": round(float(y_test.mean()), 4),
        },
        "feature_names": list(FEATURE_NAMES),
        "validation_comparison": val_results,
        "test_metrics": test_metrics,
        "slice_metrics": slice_metrics,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Saved trained model to {model_path}")
    print(f"Saved metadata to {metadata_path}")
    return metadata


if __name__ == "__main__":
    run_training()
