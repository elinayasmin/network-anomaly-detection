import os
import numpy as np
import pandas as pd
import joblib

_model    = None
_features = None

def _load():
    global _model, _features
    if _model is None:
        path = os.path.join(os.path.dirname(__file__), "model.pkl")
        _model = joblib.load(path)
        if hasattr(_model, "feature_names_in_"):
            _features = list(_model.feature_names_in_)
        print(f"[ML] Model loaded — {len(_features) if _features else '?'} features")
    return _model, _features


def predict_row(raw: dict) -> dict:
    """
    raw  — one row dict from the CSV (keys may or may not have leading spaces)
    returns {"label": "BENIGN" | "ATTACK", "anomaly_score": float 0-1}

    The CICIDS model's feature_names_in_ keeps original leading spaces
    (e.g. ' Flow Duration') but load_rows() strips column names.
    We resolve each feature by trying the exact name first, then stripped.
    """
    model, features = _load()

    # also build a stripped-key version for fallback lookup
    stripped = {k.strip(): v for k, v in raw.items()}

    if features:
        row = {}
        for f in features:
            if f in raw:
                row[f] = raw[f]          # exact match (original key with space)
            elif f.strip() in stripped:
                row[f] = stripped[f.strip()]  # stripped key → matched
            else:
                row[f] = 0               # feature absent — fill with 0
        X = pd.DataFrame([row])
    else:
        # no feature list: drop known non-numeric columns, use everything else
        for col in ("Label", " Label", "Flow ID", "Source IP", " Source IP",
                    "Destination IP", " Destination IP", "Timestamp", " Timestamp"):
            stripped.pop(col, None)
        X = pd.DataFrame([stripped])

    X = (X.apply(pd.to_numeric, errors="coerce")
           .replace([np.inf, -np.inf], 0)
           .fillna(0))

    pred  = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    score = round(float(proba[1]), 4)
    label = "BENIGN" if pred == 0 else "ATTACK"

    return {"label": label, "anomaly_score": score}
