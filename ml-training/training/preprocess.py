"""Feature extraction & leakage-free preprocessing using the backend's exact URL feature extractor."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.security.ssrf import URLValidationError, validate_submitted_url  # noqa: E402
from app.services.feature_extractor import FEATURE_NAMES, extract_url_features  # noqa: E402


def build_feature_matrix(df: pd.DataFrame, max_rows: int | None = None) -> Tuple[pd.DataFrame, pd.Series, pd.DataFrame]:
    """Extract static lexical URL features cleanly; drop invalid/unparseable URLs."""
    work = df.copy()
    if max_rows is not None and len(work) > max_rows:
        # Stratified sample so class balance is preserved if subsampling for speed
        work, _ = train_test_split(
            work,
            train_size=max_rows,
            stratify=work["label"],
            random_state=42,
        )
        work = work.reset_index(drop=True)

    rows = []
    labels = []
    kept_urls = []
    skipped = 0

    for url, label in zip(work["url"], work["label"]):
        try:
            validated = validate_submitted_url(str(url))
            feat = extract_url_features(validated)
            rows.append(feat.to_feature_vector())
            labels.append(int(label))
            kept_urls.append(validated)
        except (URLValidationError, ValueError):
            skipped += 1
            continue

    print(f"Extracted features for {len(rows)} URLs (skipped {skipped} invalid/restricted URLs).")
    x_df = pd.DataFrame(rows, columns=list(FEATURE_NAMES))
    y_ser = pd.Series(labels, name="label")
    meta_df = pd.DataFrame({"url": kept_urls, "label": labels})
    return x_df, y_ser, meta_df


def split_train_val_test(
    x_df: pd.DataFrame,
    y_ser: pd.Series,
    meta_df: pd.DataFrame,
    seed: int = 42,
):
    """Strict 70% train / 15% val / 15% test stratified split BEFORE any scaler fitting."""
    idx = np.arange(len(x_df))
    idx_train, idx_temp, y_train, y_temp = train_test_split(
        idx, y_ser, test_size=0.30, stratify=y_ser, random_state=seed
    )
    idx_val, idx_test, y_val, y_test = train_test_split(
        idx_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=seed
    )

    return {
        "X_train": x_df.iloc[idx_train].reset_index(drop=True),
        "y_train": y_train.reset_index(drop=True),
        "X_val": x_df.iloc[idx_val].reset_index(drop=True),
        "y_val": y_val.reset_index(drop=True),
        "X_test": x_df.iloc[idx_test].reset_index(drop=True),
        "y_test": y_test.reset_index(drop=True),
        "meta_test": meta_df.iloc[idx_test].reset_index(drop=True),
    }

