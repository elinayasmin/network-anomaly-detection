import pandas as pd
import requests

API_URL = "http://127.0.0.1:5000/api/anomalies"

files = [
    "capture/Monday-WorkingHours.pcap_ISCX.csv",
    "capture/Tuesday-WorkingHours.pcap_ISCX.csv",
    "capture/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
]

for file in files:
    print(f"\n Reading: {file}")
    df = pd.read_csv(file)
    df.columns = df.columns.str.strip()

    # find attack row indexes
    attack_indexes = df[df['Label'].str.strip() != 'BENIGN'].index.tolist()

    rows_to_send = set()
    for idx in attack_indexes:
        if idx - 1 >= 0:
            rows_to_send.add(idx - 1)  # row before attack
        rows_to_send.add(idx)           # attack row
        if idx + 1 < len(df):
            rows_to_send.add(idx + 1)  # row after attack

    sample = df.loc[sorted(rows_to_send)]

    for index, row in sample.iterrows():
        label = str(row.get("Label", "unknown")).strip()

        payload = {
            "src_ip": str(row.get(" Source IP", "unknown")),
            "dst_ip": str(row.get(" Destination IP", "unknown")),
            "protocol": str(row.get(" Protocol", "unknown")),
            "anomaly_score": float(row.get(" Flow Duration", 0)),
            "label": label
        }

        try:
            response = requests.post(API_URL, json=payload)
            print(f"Row {index} → {response.status_code} | Label: {label}")
        except Exception as e:
            print(f"Row {index} → ERROR: {e}")