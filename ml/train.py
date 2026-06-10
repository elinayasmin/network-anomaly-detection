"""
P3 — ML Anomaly Detection Model
Random Forest classifier trained on CICIDS dataset
Saves model to ml/model.pkl + posts predictions to Flask API

Usage:
    python ml/train.py

Requirements:
    pip install pandas scikit-learn requests joblib
"""

import os
import glob
import json
import requests
import pandas as pd
import numpy as np
import joblib
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# ─── CONFIG ────────────────────────────────────────────────────────────────────

CAPTURE_DIR  = os.path.join(os.path.dirname(__file__), "..", "capture")
MODEL_DIR    = os.path.dirname(__file__)          # ml/
MODEL_PATH   = os.path.join(MODEL_DIR, "model.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.pkl")
API_URL      = "http://127.0.0.1:5000/api/anomalies"

# CICIDS label column (trailing space is intentional — it exists in the raw CSV)
LABEL_COL = " Label"

# Features selected from CICIDS that map well to real traffic patterns
# Chosen for: availability across all CICIDS CSVs + relevance to attack types
FEATURES = [
    " Flow Duration",
    " Total Fwd Packets",
    " Total Backward Packets",
    "Total Length of Fwd Packets",
    " Total Length of Bwd Packets",
    " Fwd Packet Length Max",
    " Fwd Packet Length Min",
    " Fwd Packet Length Mean",
    " Bwd Packet Length Max",
    " Bwd Packet Length Min",
    " Bwd Packet Length Mean",
    " Flow Bytes/s",
    " Flow Packets/s",
    " Flow IAT Mean",
    " Flow IAT Std",
    " Fwd IAT Total",
    " Fwd IAT Mean",
    " Bwd IAT Total",
    " Bwd IAT Mean",
    " Fwd PSH Flags",
    " Fwd URG Flags",
    " Bwd URG Flags",
    " Fwd Header Length",
    " Bwd Header Length",
    " Fwd Packets/s",
    " Bwd Packets/s",
    " Min Packet Length",
    " Max Packet Length",
    " Packet Length Mean",
    " Packet Length Std",
    " Packet Length Variance",
    " FIN Flag Count",
    " SYN Flag Count",
    " RST Flag Count",
    " PSH Flag Count",
    " ACK Flag Count",
    " URG Flag Count",
    " CWE Flag Count",
    " ECE Flag Count",
    " Down/Up Ratio",
    " Average Packet Size",
    " Avg Fwd Segment Size",
    " Avg Bwd Segment Size",
    " Subflow Fwd Packets",
    " Subflow Fwd Bytes",
    " Subflow Bwd Packets",
    " Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    " Init_Win_bytes_backward",
    " act_data_pkt_fwd",
    " min_seg_size_forward",
    "Active Mean",
    " Active Std",
    " Active Max",
    " Active Min",
    "Idle Mean",
    " Idle Std",
    " Idle Max",
    " Idle Min",
]

# Binary label: BENIGN = 0, everything else = 1 (anomaly)
BINARY_MODE = True


# ─── STEP 1: LOAD & MERGE CSVS ─────────────────────────────────────────────────

def load_cicids_data(capture_dir):
    csv_files = glob.glob(os.path.join(capture_dir, "*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {capture_dir}\n"
            f"Expected CICIDS files like Monday-WorkingHours.pcap_ISCX.csv"
        )

    print(f"[1/5] Loading {len(csv_files)} CSV file(s)...")
    frames = []
    for f in csv_files:
        print(f"      → {os.path.basename(f)}")
        df = pd.read_csv(f, low_memory=False)
        frames.append(df)

    data = pd.concat(frames, ignore_index=True)
    print(f"      Total rows loaded: {len(data):,}")
    return data


# ─── STEP 2: CLEAN & FEATURE-SELECT ────────────────────────────────────────────

def preprocess(data):
    print(f"[2/5] Preprocessing...")

    # Keep only columns we need
    available_features = [f for f in FEATURES if f in data.columns]
    missing = [f for f in FEATURES if f not in data.columns]
    if missing:
        print(f"      Warning: {len(missing)} features not found in CSV, skipping: {missing[:3]}...")

    if LABEL_COL not in data.columns:
        raise KeyError(
            f"Label column '{LABEL_COL}' not found. "
            f"Columns: {list(data.columns[:5])}"
        )

    df = data[available_features + [LABEL_COL]].copy()

    # Replace inf values (common in CICIDS flow rate columns)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop rows with NaN
    before = len(df)
    df.dropna(inplace=True)
    dropped = before - len(df)
    if dropped:
        print(f"      Dropped {dropped:,} rows with NaN/inf values")

    # Build binary label: BENIGN=0, anomaly=1
    if BINARY_MODE:
        df["binary_label"] = (df[LABEL_COL].str.strip() != "BENIGN").astype(int)
        y = df["binary_label"]
    else:
        le = LabelEncoder()
        y = le.fit_transform(df[LABEL_COL].str.strip())
        joblib.dump(le, ENCODER_PATH)
        print(f"      Saved label encoder → {ENCODER_PATH}")

    X = df[available_features]

    label_counts = df[LABEL_COL].str.strip().value_counts()
    print(f"      Label distribution:")
    for label, count in label_counts.items():
        tag = "  [BENIGN]" if label == "BENIGN" else "  [ATTACK]"
        print(f"        {tag} {label}: {count:,}")

    print(f"      Features used: {len(available_features)}")
    print(f"      Final dataset: {len(X):,} rows")
    return X, y, available_features


# ─── STEP 3: TRAIN ─────────────────────────────────────────────────────────────

def train_model(X, y):
    print(f"[3/5] Training Random Forest...")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Train: {len(X_train):,} | Test: {len(X_test):,}")

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,          # use all CPU cores
        random_state=42,
        class_weight="balanced",   # handles imbalanced BENIGN vs attack ratio
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"\n      ── Evaluation Results ──")
    print(f"      Accuracy : {acc:.4f} ({acc*100:.2f}%)")
    print(f"\n      Classification Report:")
    labels = ["BENIGN", "ANOMALY"] if BINARY_MODE else None
    report = classification_report(
        y_test, y_pred,
        target_names=labels,
        zero_division=0
    )
    for line in report.split("\n"):
        print(f"        {line}")

    print(f"\n      Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"        {cm}")

    # Top 10 most important features
    importances = sorted(
        zip(X.columns, clf.feature_importances_),
        key=lambda x: x[1], reverse=True
    )[:10]
    print(f"\n      Top 10 Feature Importances:")
    for feat, imp in importances:
        bar = "█" * int(imp * 50)
        print(f"        {feat.strip():35s} {imp:.4f}  {bar}")

    return clf, X_test, y_test, y_pred, acc


# ─── STEP 4: SAVE MODEL ────────────────────────────────────────────────────────

def save_model(clf, feature_names, accuracy):
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"\n[4/5] Model saved → {MODEL_PATH}")

    # Save metadata alongside model
    meta = {
        "trained_at": datetime.now().isoformat(),
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "accuracy": round(accuracy, 4),
        "binary_mode": BINARY_MODE,
        "feature_count": len(feature_names),
        "features": feature_names,
        "label_map": {"0": "BENIGN", "1": "ANOMALY"} if BINARY_MODE else "multiclass"
    }
    meta_path = os.path.join(MODEL_DIR, "model_meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"      Metadata saved → {meta_path}")


# ─── STEP 5: POST ANOMALIES TO FLASK API ───────────────────────────────────────

def post_anomalies_to_api(X_test, y_test, y_pred, clf):
    """
    Post detected anomalies (predicted=1) to Flask API at /api/anomalies
    Uses anomaly_score = probability of class 1 from Random Forest
    """
    print(f"\n[5/5] Posting anomalies to Flask API ({API_URL})...")

    # Check if API is alive
    try:
        health = requests.get("http://127.0.0.1:5000/api/health", timeout=3)
        if health.status_code != 200:
            print(f"      API health check failed (status {health.status_code}) — skipping POST")
            return
    except requests.exceptions.ConnectionError:
        print(f"      Flask API not reachable — skipping POST (start api/app.py first)")
        return

    proba = clf.predict_proba(X_test)[:, 1]   # probability of anomaly class
    X_reset = X_test.reset_index(drop=True)

    posted = 0
    skipped = 0
    errors = 0

    for i in range(len(X_reset)):
        predicted = int(y_pred[i])
        if predicted != 1:          # only post anomalies, not BENIGN
            skipped += 1
            continue

        score = float(round(proba[i], 4))
        actual = int(y_test.iloc[i])

        payload = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": "CICIDS-dataset",
            "dst_ip": "CICIDS-dataset",
            "protocol": "ML-prediction",
            "anomaly_score": score,
            "label": "anomaly" if predicted == 1 else "normal"
        }

        try:
            r = requests.post(API_URL, json=payload, timeout=5)
            if r.status_code == 201:
                posted += 1
            else:
                errors += 1
        except Exception as e:
            errors += 1
            if errors <= 3:
                print(f"      POST error: {e}")

    print(f"      Anomalies posted : {posted}")
    print(f"      BENIGN skipped   : {skipped}")
    print(f"      Errors           : {errors}")


# ─── predict() — for P4 dashboard / real-time use ──────────────────────────────

def predict(feature_dict: dict) -> dict:
    """
    Called by external code (P4 dashboard or live pipeline).
    Input:  dict of {feature_name: value}
    Output: {"label": "anomaly"|"normal", "anomaly_score": float}

    Example:
        from ml.train import predict
        result = predict({" Flow Duration": 1234, " SYN Flag Count": 10, ...})
    """
    clf = joblib.load(MODEL_PATH)
    meta_path = os.path.join(MODEL_DIR, "model_meta.json")
    with open(meta_path) as f:
        meta = json.load(f)

    features = meta["features"]
    row = pd.DataFrame([[feature_dict.get(f, 0) for f in features]], columns=features)
    row.replace([np.inf, -np.inf], 0, inplace=True)
    row.fillna(0, inplace=True)

    pred = clf.predict(row)[0]
    score = float(clf.predict_proba(row)[0][1])

    return {
        "label": "anomaly" if pred == 1 else "normal",
        "anomaly_score": round(score, 4)
    }


# ─── MAIN ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Network Anomaly Detection — P3 ML Model Training")
    print("  Random Forest on CICIDS Dataset")
    print("=" * 60)

    data = load_cicids_data(CAPTURE_DIR)
    X, y, feature_names = preprocess(data)
    clf, X_test, y_test, y_pred, acc = train_model(X, y)
    save_model(clf, feature_names, acc)
    post_anomalies_to_api(X_test, y_test, y_pred, clf)

    print("\n" + "=" * 60)
    print(f"  Done. Model accuracy: {acc*100:.2f}%")
    print(f"  To use: from ml.train import predict")
    print("=" * 60)