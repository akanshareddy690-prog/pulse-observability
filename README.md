# Pulse: Two-Tier Telemetry Mesh & Autonomous Observability Platform

A production-grade, two-tier observability platform designed for enterprise privacy compliance. Monitored nodes scrub secrets and sensitive records locally before transmission, shipping allow-listed metadata to a centralized multi-tenant platform.

---

## 🏛️ Architecture Overview

```
[ Customer Local Environment (Tier 1) ]
  ├── Sources: Host Metrics, Auth Daemons, Network Probes
  ├── Privacy Engine: Regex Secret Redaction & Field Allow-Listing
  ├── Local Ledger: collector_local.db (raw logs stay on-premise)
  ├── Outage Buffer: Persistent SQLite FIFO queue
  └── Egress Proof Panel: Live audit dashboard at http://localhost:8001

              │ (Encrypted Metadata Only / TLS / Bearer Auth)
              ▼

[ Central Operations Hub (Tier 2) ]
  ├── Ingestion Router: Multi-tenant partitioning (tenant-alpha / tenant-beta)
  ├── Idempotency Engine: In-memory & DB payload deduplication
  ├── Statistical Engine: Dynamic sliding-window Z-Score anomaly detector
  ├── Correlation Core: Multi-signal alert clustering into unified incidents
  ├── Operations Console: Dark-mode real-time dashboard at http://localhost:8000
  └── Remediation Workflow: Human-in-the-loop action approval & audit ledger
```

---

## 🚀 Quick Start Guide

The entire platform runs on standard Python 3. No third-party packages or compilation steps required.

### 1. Launch Central Operations Hub (Terminal 1)
```powershell
python run_saas.py
```
* **Operations Console**: [http://localhost:8000](http://localhost:8000)

### 2. Launch Local Collector Daemon (Terminal 2)
```powershell
python run_collector.py
```
* **Local Egress Proof Panel**: [http://localhost:8001](http://localhost:8001)

### 3. Run Live Scenario Test Harness (Terminal 3)
```powershell
python demo/inject_scenarios.py
```
Use the interactive menu to trigger test cases (secret redaction, network outages, credential brute-force, resource saturation).

---

## 📊 Live Verification Checklist

### 1. Privacy Boundary & Secret Scrubbing
- Inject a raw log containing AWS credentials and tokens (`demo/inject_scenarios.py` option 1).
- Inspect `http://localhost:8001`: Raw payload containing plain credentials is displayed on the left (retained in `collector_local.db`).
- The right panel shows the egress payload containing only masked values (`[REDACTED_AWS_KEY]`).
- Verify `http://localhost:8000`: No credentials or raw logs appear in the central database.

### 2. Network Outage & Reconnection Resiliency
- In the Egress Proof Panel (`http://localhost:8001`), click **"Simulate SaaS Link Outage"**.
- New telemetry records automatically queue in the local SQLite buffer.
- Click **"Reconnect to SaaS"**: The backlog drains in FIFO order without lost records or duplicates (idempotency tokens enforced).

### 3. Statistical Anomaly & Incident Correlation
- Inject multi-signal stress (`demo/inject_scenarios.py` option 6).
- Observe `http://localhost:8000`: Co-occurring CPU saturation, elevated latency, and packet loss are synthesized into a single correlated incident with confidence scoring.
- Review the explainability breakdown (Why Flagged, Contributing Signals, Recommended Mitigation).
- Click **"Approve Remediation"** to test policy evaluation and the audit trail.

---

## 📂 Project Structure

```
pulse-observability/
├── collector/
│   ├── collector.py           # Collector daemon & local web server
│   ├── data_policy.json       # Allow-list definition & redaction rules
│   └── templates/
│       └── egress_proof.html  # Local Egress Proof user interface
├── saas/
│   ├── server.py              # Central ingest API & correlation engine
│   └── templates/
│       └── dashboard.html     # Operations Hub management console
├── demo/
│   └── inject_scenarios.py    # Automated test scenario runner
├── run_collector.py           # Collector daemon entrypoint
├── run_saas.py                # Operations Hub entrypoint
└── .gitignore                 # Standard Python ignores
```
