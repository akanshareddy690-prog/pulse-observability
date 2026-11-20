# Technical Architecture & Defense Specification

Evaluation Guide & System Defense Documentation:

---

### 🔒 1. Security and Data Handling

**Q: Exactly what data leaves the local environment, and what stays behind?**
> **Answer**: 
> - **Stays behind**: Raw log messages, database queries, credentials, passwords, raw IP addresses, internal hostnames, and customer PII stay strictly inside the local SQLite database (`raw_telemetry` table) on the collector.
> - **Leaves the environment**: Only strictly allow-listed metadata fields defined in `data_policy.json` (UTC timestamps, pseudonymized source ID like `srv-node-db01`, numeric metrics like CPU/latency, health state, and scrubbed summaries).

**Q: How does the collector decide which fields are allowed to be sent to SaaS?**
> **Answer**: 
> The collector runs a strict allow-list filter against `data_policy.json`. Even if raw telemetry contains 50 internal fields, only the approved metadata keys are extracted. Any unapproved field is dropped before egress serialization.

**Q: How do you prevent secrets or raw log content from being transmitted accidentally?**
> **Answer**: 
> Two lines of defense: 
> 1. Field allow-listing drops raw log objects completely.
> 2. Summary text passes through regex scrubbing engines targeting AWS keys (`AKIA...`), bearer tokens, API keys, passwords, and private IP patterns.

**Q: Can you open the egress proof panel and show the last payload?**
> **Answer**: 
> Yes! Navigate to `http://localhost:8001`. The Egress Proof Panel displays the live side-by-side comparison between the raw unredacted record stored locally and the exact JSON payload transmitted to SaaS.

---

### 🧠 2. AIOps and Operations

**Q: How do you distinguish a real anomaly from a normal usage spike?**
> **Answer**: 
> We use dynamic rolling baseline calculation instead of static hardcoded thresholds. We compute the moving average and standard deviation ($\sigma$) over a 30-sample sliding window to obtain a Z-Score ($Z = \frac{x - \mu}{\sigma}$). Only deviations exceeding $Z > 2.5$ or reaching critical thresholds trigger anomaly classification.

**Q: How do you correlate multiple alerts into one incident?**
> **Answer**: 
> Our AIOps correlation engine evaluates co-occurring anomalies across compute, network, and security within a time window. If a node exhibits high CPU alongside high round-trip latency and packet loss, rather than firing three separate noisy alerts, the engine merges them into a single incident: *"Correlated Incident: Service Congestion & Compute Saturation"* with 96% confidence.

**Q: Can you explain why the platform recommends a particular action?**
> **Answer**: 
> Every incident card includes an **Explainability Matrix**:
> 1. **Why Flagged**: Details the statistical anomaly and Z-Score deviation.
> 2. **Contributing Signals**: Lists the exact metrics responsible.
> 3. **Recommended Action**: Provides the exact operational step (e.g., auto-scale pod, reroute traffic, rate-limit brute force).

**Q: What safeguards are needed before automated remediation?**
> **Answer**: 
> We implement **Stage 4: Assisted Operations**. Before any action executes, it requires:
> 1. Policy check (ensuring the action is non-destructive and within bounds).
> 2. Human approval click.
> 3. Immutable audit trail entry (`remediation_audit` table).
> 4. Instant rollback control.

---

### 🌐 3. Architecture and Reliability

**Q: What happens when SaaS is unreachable?**
> **Answer**: 
> The collector catches connection errors and automatically switches into local buffering mode. Payloads are persisted in the local SQLite `outage_buffer` queue.

**Q: How do you avoid losing or duplicating metadata after reconnection?**
> **Answer**: 
> 1. **Zero Loss**: The FIFO queue persists records on disk until the SaaS server returns HTTP 200 OK.
> 2. **Zero Duplicates**: Every payload has a unique UUID `payload_id`. The SaaS platform tracks received IDs; if a retried record arrives, SaaS acknowledges it without duplicating the entry or corrupting metric charts.

**Q: How do you handle regions, tenant data residency, UTC time, and out-of-order events?**
> **Answer**: 
> - **Regional Ingest & Residency**: Ingestion includes regional headers (`X-Region: ap-south-1`) and enforces strict database query isolation by `tenant_id`.
> - **UTC Timestamps**: All telemetry records store ISO 8601 UTC timestamps alongside source timezones (`source_timezone`).
> - **Out-of-Order Handling**: Ingested records are sorted and indexed by event `timestamp_utc`, ensuring delayed arrivals are plotted accurately along historical timelines.
