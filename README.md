# Network-anomaly-detection

A real-time network anomaly detection system that captures live network traffic, runs it through a machine learning model, and displays alerts on a web dashboard — all working together as one end-to-end pipeline.

# What This Project Does
This system simulates a mini Intrusion Detection System (IDS) built from scratch. It:

Simulates a real network topology using GNS3 (routers, switches, OSPF routing)
Captures live packet traffic using pyshark / tshark
Trains a machine learning model on labeled normal vs. anomalous traffic
Detects anomalies in real time using a 10-second sliding window
Exposes detection results via a Flask REST API
Displays live alerts on a web dashboard

# System Pipeline
Network Traffic →  Capture   → ML Model   → API →     Dashboard
  (GNS3 sim)      (pyshark)    (anomaly     (Flask)   (live alerts)
                               detection)               


#Project Structure
network-anomaly-detection/
├── capture/        # P1 — pyshark live capture pipeline
├── ml/             # P2 & P3 — model training and prediction
├── api/            # P1 — Flask REST API + SQLite storage
├── dashboard/      # P4 — Frontend anomaly alert dashboard
├── docs/           # Architecture diagrams, report, slides
├── .gitignore
└── README.md


#Team & Roles
P1  : Network Engineer + Team Lead   : GNS3 topology, pyshark pipeline, Flask API, GitHub owner
P2  : Data Engineer                  : Traffic generation (Scapy), pcap → CSV labeling, baseline captures
P3  : ML Engineer                    : Model training, predict() function, real-time inference
P4  : Frontend Engineer              : Dashboard UI, live anomaly visualization

#Tech Stack
1. Network Simulation : GNS3, Cisco Packet Tracer
2. Traffic Capture    : tshark, pyshark, Scapy
3. Data Processing    : Python, pandas, CSV
4. Machine Learning   : scikit-learn
5. Backend API        : Flask, SQLite
6. Frontend           : (Dashboard framework — P4)
7. DevOps             : GitHub Actions (CI), Git, GitHub
8. Documentation      : draw.io, Google Slides, Overleaf

# Setup & Installation
Prerequisites
1. Python 3.8+
2. GNS3 installed
3. tshark / Wireshark installed
4. Git

#Branching Strategy
1. main : Stable, production-ready code only
2. feature/capture-pipeline : P1 — live pyshark capture
3. feature/traffic-generator : P2 — Scapy traffic generation
4. feature/ml-model : P3 — ML training and inference
5. feature/dashboard : P4 — frontend dashboard
   
