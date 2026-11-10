"""Download and validate the Hannousse & Yahiouche (2021) Phishing URL Benchmark Dataset.

Dataset Reference:
  Hannousse, A., & Yahiouche, S. (2021). Towards benchmark datasets for machine learning
  based website phishing detection. Engineering Applications of Artificial Intelligence, 104, 104347.
  Source: https://huggingface.co/datasets/pirocheto/phishing-url (CC-BY-4.0)
"""

from __future__ import annotations

import io
from pathlib import Path

import httpx
import pandas as pd

TRAIN_PARQUET_URL = "https://huggingface.co/datasets/pirocheto/phishing-url/resolve/main/data/train.parquet"
TEST_PARQUET_URL = "https://huggingface.co/datasets/pirocheto/phishing-url/resolve/main/data/test.parquet"

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"
RAW_DIR = DATASETS_DIR / "raw"
VALIDATED_CSV = DATASETS_DIR / "validated_urls.csv"


def download_benchmark_dataset(output_dir: Path = RAW_DIR, timeout_seconds: float = 60.0) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    target_csv = output_dir / "hannousse_phishing_urls_raw.csv"
    if target_csv.exists() and target_csv.stat().st_size > 100_000:
        print(f"Found existing dataset CSV: {target_csv}")
        return target_csv

    print("Downloading Hannousse & Yahiouche (2021) phishing URL benchmark dataset...")
    with httpx.Client(timeout=timeout_seconds, follow_redirects=True) as client:
        r_train = client.get(TRAIN_PARQUET_URL)
        r_train.raise_for_status()
        r_test = client.get(TEST_PARQUET_URL)
        r_test.raise_for_status()

    df_train = pd.read_parquet(io.BytesIO(r_train.content))
    df_test = pd.read_parquet(io.BytesIO(r_test.content))
    df_all = pd.concat([df_train, df_test], ignore_index=True)
    df_all.to_csv(target_csv, index=False)
    print(f"Saved raw benchmark dataset ({len(df_all)} rows) to {target_csv}")
    return target_csv


def validate_and_normalize_dataset(raw_csv_path: Path, out_csv_path: Path = VALIDATED_CSV) -> pd.DataFrame:
    """Validate URLs and label semantics, remove duplicates, and export clean (url, label) CSV."""
    df = pd.read_csv(raw_csv_path)
    print(f"Raw dataset shape: {df.shape}")

    if "url" not in df.columns or "status" not in df.columns:
        raise ValueError(f"Expected 'url' and 'status' columns; found {list(df.columns)[:15]}")

    clean = df[["url", "status"]].dropna(subset=["url", "status"]).copy()
    clean["url"] = clean["url"].astype(str).str.strip()
    clean["status"] = clean["status"].astype(str).str.strip().str.lower()
    clean = clean[clean["url"].str.startswith(("http://", "https://"))]
    clean = clean[clean["status"].isin(["legitimate", "phishing"])].copy()

    # Target: 1 = phishing, 0 = benign/legitimate
    clean["label"] = (clean["status"] == "phishing").astype(int)
    clean = clean[["url", "label"]]

    # Deduplicate normalized URLs prior to any splitting to prevent leakage
    clean["url_norm"] = clean["url"].str.lower()
    before_dedup = len(clean)
    clean = clean.drop_duplicates(subset=["url_norm"]).drop(columns=["url_norm"]).reset_index(drop=True)
    print(f"Removed {before_dedup - len(clean)} duplicate URLs. Clean rows: {len(clean)}")
    print(f"Class balance (1=phishing, 0=benign): {clean['label'].value_counts().to_dict()}")

    out_csv_path.parent.mkdir(parents=True, exist_ok=True)
    clean.to_csv(out_csv_path, index=False)
    print(f"Saved validated dataset to {out_csv_path}")
    return clean


if __name__ == "__main__":
    raw_path = download_benchmark_dataset()
    validate_and_normalize_dataset(raw_path)
