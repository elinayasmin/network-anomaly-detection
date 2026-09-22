import pandas as pd
import requests
import time
import random
import threading
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from ml.predict import predict_row
    ML_ENABLED = True
    print("[ML] predict_row loaded — model will classify each packet")
except Exception as e:
    ML_ENABLED = False
    print(f"[ML] WARNING: could not load ml/predict.py ({e}). Falling back to CSV labels.")

API_URL = "http://127.0.0.1:5000/api/anomalies"

NORMAL_CSV  = "capture/Monday-WorkingHours.pcap_ISCX.csv"
ATTACK_CSV  = "capture/Tuesday-WorkingHours.pcap_ISCX.csv"

NORMAL_DELAY  = 0.1   # seconds between each normal packet
ATTACK_BURST  = 20    # how many attack rows per burst
ATTACK_EVERY  = (15, 30)  # random interval in seconds between bursts


def load_rows(filepath, label_filter=None):
    print(f"Loading {filepath} ...")
    df = pd.read_csv(filepath, low_memory=False)
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].str.strip()
    if label_filter == "BENIGN":
        df = df[df["Label"] == "BENIGN"]
    elif label_filter == "ATTACK":
        df = df[df["Label"] != "BENIGN"]
    print(f"  → {len(df)} rows loaded ({label_filter})")
    return df.reset_index(drop=True)


def make_payload(row):
    def safe(col, default="unknown"):
        val = row.get(col, default)
        try:
            return str(val).strip() if pd.notna(val) else default
        except Exception:
            return default

    src_ip   = safe("Source IP")
    dst_ip   = safe("Destination IP")
    protocol = safe("Protocol")

    csv_label = safe("Label")

    if ML_ENABLED:
        result        = predict_row(row.to_dict())
        anomaly_score = result["anomaly_score"]
        if result["label"] == "ATTACK":
            # keep specific attack type from CSV (e.g. "DoS Hulk", "SSH-Patator")
            label = csv_label if csv_label.upper() != "BENIGN" else "ATTACK"
        else:
            label = "BENIGN"
    else:
        label         = csv_label
        anomaly_score = 0.0

    return {
        "src_ip":        src_ip,
        "dst_ip":        dst_ip,
        "protocol":      protocol,
        "anomaly_score": anomaly_score,
        "label":         label,
    }


def send(payload):
    try:
        r = requests.post(API_URL, json=payload, timeout=2)
        return r.status_code
    except Exception as e:
        print(f"  [send error] {e}")
        return None


# ── Attack injector thread ──────────────────────────────────────────────────
attack_flag = threading.Event()

def attack_injector(attack_df):
    while True:
        wait = random.randint(*ATTACK_EVERY)
        print(f"\n[ATTACK] Next burst in {wait}s ...")
        time.sleep(wait)

        burst = attack_df.sample(n=min(ATTACK_BURST, len(attack_df)))
        print(f"[ATTACK] Injecting {len(burst)} attack packets ──────────────")
        for _, row in burst.iterrows():
            payload = make_payload(row)
            status = send(payload)
            print(f"  [ATTACK] {payload['label']:<30} → {status}")
            time.sleep(0.02)   # fast burst — this creates the spike
        print("[ATTACK] Burst done ─────────────────────────────────────────\n")


# ── Main normal traffic loop ────────────────────────────────────────────────
def normal_stream(normal_df):
    idx = 0
    total = len(normal_df)
    print(f"[NORMAL] Streaming {total} BENIGN rows (looping forever) ...")
    while True:
        row = normal_df.iloc[idx % total]
        payload = make_payload(row)
        status = send(payload)
        print(f"  [NORMAL] row {idx % total:<6} BENIGN → {status}")
        idx += 1
        time.sleep(NORMAL_DELAY)


# ── Entry point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    normal_df = load_rows(NORMAL_CSV,  label_filter="BENIGN")
    attack_df = load_rows(ATTACK_CSV,  label_filter="ATTACK")

    # Start attack injector in background thread
    t = threading.Thread(target=attack_injector, args=(attack_df,), daemon=True)
    t.start()

    # Run normal stream in main thread (Ctrl+C to stop)
    try:
        normal_stream(normal_df)
    except KeyboardInterrupt:
        print("\n[STOPPED] Traffic generator stopped.")
