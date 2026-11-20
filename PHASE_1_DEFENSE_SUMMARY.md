# Phase 1 Evaluation Defense Guide: Problem Understanding & Ideation
**Target: 10 / 10 Marks** | CICADA 2026 24-Hour Hackathon

---

## 🎯 1. What the Judge Evaluates in Phase 1

From Page 4 & Page 6 of the Judge's Reference Document:
1. **Problem Understanding**: Why raw telemetry must stay on-premise and why SaaS receives metadata only.
2. **Use Cases**: Infrastructure health, network performance, repeated failed logins, collector fleet health.
3. **Proposed Features & 24h Plan**: Realistic scope, team roles, and minimum viable demo.
4. **Local Data Protection (Evidence Checklist)**:
   - What stays local vs what is redacted vs what is transmitted.
   - Field allow-list definition.
   - Trust boundary architecture diagram.

---

## 🗣️ 2. The 60-Second Opening Pitch to the Judges

> *"Good morning judges. Our project addresses a fundamental conflict in enterprise monitoring: organizations must monitor infrastructure without exposing customer credentials, database queries, and private payloads to third-party clouds.*
>
> *We have engineered a **two-tier architecture**:*
> *1. **Tier 1 (Customer Local Collector)** runs inside the customer perimeter. Raw logs and secrets stay locked in local SQLite storage. Our policy engine strips credentials, pseudonymizes hostnames, and sends strictly allow-listed metadata over TLS.*
> *2. **Tier 2 (Central Platform)** operates on metadata only, evaluating 4 health states (Excellent, Good, Fair, Poor) and performing statistical Z-Score anomaly correlation to eliminate alert fatigue.*
>
> *We also provide an **Egress Proof Panel** that mathematically proves to compliance auditors and judges exactly what leaves the customer network."*

---

## 📋 3. The 3 Pieces of Evidence Required by Judges

### Evidence 1: The Trust Boundary Data Flow Diagram
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

### Evidence 2: Field Allow-List & Redaction Policy
| Field Name | Status | Purpose |
| :--- | :--- | :--- |
| `payload_id` | **Allow-Listed** | UUID token for idempotent deduplication during retries. |
| `timestamp_utc` | **Allow-Listed** | ISO 8601 UTC timestamp for global time synchronization. |
| `pseudonym_source_id` | **Allow-Listed** | Masked identifier (e.g. `srv-node-db01` replaces `prod-db.internal`). |
| `metrics.*` | **Allow-Listed** | Numeric CPU %, Latency ms, Packet Loss %, Auth Failures. |
| `raw_log` / `payload` | **STRICTLY BLOCKED** | Stored on-premise in local SQLite. Never leaves. |
| `credentials` / `keys` | **SCRUBBED / DROPPED** | Regex scrubber masks AWS keys and passwords before egress. |

### Evidence 3: 24-Hour Scope, Feasibility & Roles
| Component | Owner | Deliverable Status |
| :--- | :--- | :--- |
| Tier 1 Collector & Egress Proof | Systems Lead | **Ready** (Local daemon, SQLite buffer, Port 8001) |
| Tier 2 Central SaaS & Correlation | Backend Lead | **Ready** (REST ingest, Z-Score engine, Port 8000) |
| Multi-Signal Scenario Injector | QA / Automation Lead | **Ready** (Interactive CLI with all 8 live scenarios) |
| Operations Console | Frontend Lead | **Ready** (Live charts, 4-state health, incident cards) |

---

## 💡 4. How to Generate the Printable PDF

A high-resolution, print-ready document has been created at:
📁 **`C:\Users\akans\pulse-observability\PHASE_1_REVIEW_SUBMISSION.html`**

1. Double-click **`PHASE_1_REVIEW_SUBMISSION.html`** to open it in Chrome or Edge.
2. Click the blue **"Save as PDF / Print"** button in the top-right corner (or press **`Ctrl + P`**).
3. In the print dialog, select **"Save as PDF"** $\rightarrow$ Click **Save**!
