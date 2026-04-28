from flask import Flask, request, jsonify
import sqlite3
import datetime

app = Flask(__name__)
DB = "anomalies.db"

# --- Database setup ---
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            anomaly_score REAL,
            label TEXT
        )
    ''')
    conn.commit()
    conn.close()

# --- Health check ---
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "API is running"})

# --- Get all anomalies ---
@app.route('/api/anomalies', methods=['GET'])
def get_anomalies():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM anomalies")
    rows = c.fetchall()
    conn.close()
    result = []
    for row in rows:
        result.append({
            "id": row[0],
            "timestamp": row[1],
            "src_ip": row[2],
            "dst_ip": row[3],
            "protocol": row[4],
            "anomaly_score": row[5],
            "label": row[6]
        })
    return jsonify(result)

# --- Post a new anomaly ---
@app.route('/api/anomalies', methods=['POST'])
def post_anomaly():
    data = request.get_json()
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''
        INSERT INTO anomalies (timestamp, src_ip, dst_ip, protocol, anomaly_score, label)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        datetime.datetime.now().isoformat(),
        data['src_ip'],
        data['dst_ip'],
        data['protocol'],
        data['anomaly_score'],
        data['label']
    ))
    conn.commit()
    conn.close()
    return jsonify({"message": "Anomaly recorded"}), 201

if __name__ == '__main__':
    init_db()
    app.run(debug=True)