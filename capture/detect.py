import pandas as pd
import requests
import json

API_URL = "http://127.0.0.1:5000/api/anomalies"

files = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
]

# ─── RULE-BASED DETECTION ─────────────────────────────────────
# Purpose: Apply network security rules to flag anomalies
# Each rule targets a specific attack pattern from CICIDS dataset

def apply_rules(row):
    """
    Returns (is_anomaly: bool, rule_triggered: str, confidence: float)
    Rules based on known attack signatures in CICIDS dataset.
    """

    flow_pkts_s     = row.get("Flow Packets/s", 0)
    flow_bytes_s    = row.get("Flow Bytes/s", 0)
    flow_duration   = row.get("Flow Duration", 0)
    syn_flags       = row.get("SYN Flag Count", 0)
    rst_flags       = row.get("RST Flag Count", 0)
    fwd_packets     = row.get("Total Fwd Packets", 0)
    bwd_packets     = row.get("Total Backward Packets", 0)
    dst_port        = row.get("Destination Port", 0)
    pkt_len_mean    = row.get("Packet Length Mean", 0)
    fwd_pkt_s       = row.get("Fwd Packets/s", 0)
    label           = str(row.get("Label", "BENIGN")).strip()

    # ── Rule 1: Port Scan Detection ──────────────────────────
    # Signature: High packet rate, many SYN flags, short flows,
    #            low bytes per packet (just probing ports)
    if (flow_pkts_s > 1000 and
        syn_flags >= 1 and
        flow_duration < 500000 and
        pkt_len_mean < 100):
        return True, "PortScan", 0.92

    # ── Rule 2: DoS / Flood Detection ────────────────────────
    # Signature: Extremely high byte rate, very high packet rate
    if (flow_bytes_s > 1000000 and flow_pkts_s > 5000):
        return True, "DoS-Flood", 0.95

    # ── Rule 3: SYN Flood Detection ──────────────────────────
    # Signature: Many SYN flags, almost no responses (low bwd packets)
    if (syn_flags > 5 and bwd_packets == 0 and fwd_packets > 10):
        return True, "SYN-Flood", 0.88

    # ── Rule 4: FTP Brute Force Detection ────────────────────
    # Signature: Repeated connections to port 21, high RST count
    if (dst_port == 21 and rst_flags > 3 and flow_pkts_s > 100):
        return True, "FTP-BruteForce", 0.85

    # ── Rule 5: SSH Brute Force Detection ────────────────────
    # Signature: Repeated short connections to port 22
    if (dst_port == 22 and
        flow_duration < 1000000 and
        fwd_packets < 10 and
        flow_pkts_s > 50):
        return True, "SSH-BruteForce", 0.83

    # ── Rule 6: Abnormal Traffic Ratio ───────────────────────
    # Signature: Forward packets >> Backward (one-directional flood)
    if (fwd_packets > 500 and bwd_packets == 0):
        return True, "One-Way-Flood", 0.78

    # No rule triggered → normal traffic
    return False, "BENIGN", 0.05


# ─── MAIN PIPELINE ────────────────────────────────────────────

total_sent = 0
total_anomalies = 0
total_benign = 0
rule_counts = {}

for file in files:
    print(f"\n{'='*60}")
    print(f" Processing: {file}")
    print(f"{'='*60}")

    df = pd.read_csv(file)
    df.columns = df.columns.str.strip()

    # Replace inf values with 0 (common in CICIDS)
    df.replace([float('inf'), float('-inf')], 0, inplace=True)
    df.fillna(0, inplace=True)

    file_anomalies = 0
    file_benign = 0

    # Sample: take max 300 rows per file to avoid overloading API
    # (100 attacks + 100 before/after context + 100 benign baseline)
    attack_rows = df[df['Label'].str.strip() != 'BENIGN'].head(100)
    benign_rows = df[df['Label'].str.strip() == 'BENIGN'].head(100)
    sample = pd.concat([attack_rows, benign_rows]).drop_duplicates()

    for index, row in sample.iterrows():
        is_anomaly, rule_name, confidence = apply_rules(row)
        actual_label = str(row.get("Label", "BENIGN")).strip()

        # Build payload for Flask API
        payload = {
            "src_ip":         str(row.get("Source IP", f"10.0.{index%255}.1")),
            "dst_ip":         str(row.get("Destination IP", "192.168.1.10")),
            "protocol":       str(int(row.get("Destination Port", 0))),
            "anomaly_score":  round(confidence, 3),
            "label":          rule_name if is_anomaly else "BENIGN"
        }

        try:
            response = requests.post(API_URL, json=payload, timeout=5)
            status = response.status_code

            if is_anomaly:
                file_anomalies += 1
                total_anomalies += 1
                rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
                print(f"  [ANOMALY] Row {index:5d} | Rule: {rule_name:20s} | Score: {confidence} | API: {status}")
            else:
                file_benign += 1
                total_benign += 1

            total_sent += 1

        except Exception as e:
            print(f"  [ERROR]   Row {index} → {e}")

    print(f"\n  File Summary: {file_anomalies} anomalies | {file_benign} benign | sent to API")

# ─── FINAL REPORT ─────────────────────────────────────────────
print(f"\n{'='*60}")
print(f" DETECTION SUMMARY REPORT")
print(f"{'='*60}")
print(f"  Total rows processed : {total_sent}")
print(f"  Anomalies detected   : {total_anomalies}")
print(f"  Benign traffic       : {total_benign}")
print(f"\n  Rules Triggered:")
for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
    print(f"    {rule:25s} : {count} detections")
print(f"{'='*60}")