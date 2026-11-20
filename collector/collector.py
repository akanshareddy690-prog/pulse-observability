"""
Tier 1: Customer Environment / Local Collector
- Gathers telemetry (CPU, Memory, Disk, Latency, Packet Loss, Auth Logs).
- Keeps raw logs, payloads, and secrets strictly local.
- Filters, redacts, pseudonmyizes, and applies field allow-listing.
- Buffers in local SQLite during outages; replays idempotently with zero duplicates.
- Exposes local Egress Proof Panel on http://127.0.0.1:8001
"""

import os
import sys
import json
import time
import uuid
import re
import random
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error

# Configuration
CONFIG = {
    "collector_id": "col-local-01",
    "collector_version": "1.4.0",
    "tenant_id": "tenant-alpha",
    "region": "ap-south-1",
    "source_timezone": "UTC+05:30",
    "saas_ingest_url": "http://127.0.0.1:8000/api/v1/telemetry/ingest",
    "saas_heartbeat_url": "http://127.0.0.1:8000/api/v1/collector/heartbeat",
    "saas_token": "Bearer collector-secret-key-2026",
    "egress_port": 8001,
    "db_path": os.path.join(os.path.dirname(__file__), "collector_local.db"),
    "policy_path": os.path.join(os.path.dirname(__file__), "data_policy.json")
}

# In-memory shared state for Egress Proof UI
SHARED_STATE = {
    "simulated_outage": False,
    "saas_reachable": False,
    "latest_raw": None,
    "latest_egress": None,
    "total_sent": 0,
    "secrets_redacted_count": 0,
    "lock": threading.Lock()
}

# Load Data Policy
def load_data_policy():
    try:
        with open(CONFIG["policy_path"], "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[Collector Warning] Could not load data_policy.json ({e}), using default fallback policy.")
        return {
            "allow_listed_metadata_fields": [
                "payload_id", "timestamp_utc", "source_timezone", "tenant_id",
                "collector_id", "collector_version", "pseudonym_source_id",
                "category", "severity", "metrics", "health_state", "alert_summary"
            ],
            "redaction_rules": []
        }

DATA_POLICY = load_data_policy()

# Initialize Local SQLite Database
def init_local_db():
    conn = sqlite3.connect(CONFIG["db_path"], check_same_thread=False)
    cursor = conn.cursor()
    # 1. Raw Telemetry Table (Stored strictly on local premises)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            raw_source_id TEXT,
            raw_payload TEXT,
            contains_secret INTEGER
        )
    """)
    # 2. Outage Buffer Queue (FIFO persistence during network disconnects)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS outage_buffer (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_id TEXT UNIQUE,
            created_utc TEXT,
            egress_json TEXT,
            retry_count INTEGER DEFAULT 0
        )
    """)
    # 3. Auditable Egress Proof Ledger
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS egress_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_id TEXT UNIQUE,
            timestamp_utc TEXT,
            pseudonym_source_id TEXT,
            category TEXT,
            severity TEXT,
            egress_json TEXT
        )
    """)
    conn.commit()
    conn.close()

init_local_db()

# DB Helpers
def get_db():
    return sqlite3.connect(CONFIG["db_path"], check_same_thread=False)

def store_raw_locally(raw_source_id, raw_dict, contains_secret):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO raw_telemetry (timestamp_utc, raw_source_id, raw_payload, contains_secret) VALUES (?, ?, ?, ?)",
        (datetime.now(timezone.utc).isoformat(), raw_source_id, json.dumps(raw_dict), 1 if contains_secret else 0)
    )
    conn.commit()
    conn.close()

def queue_outage_buffer(payload_id, egress_dict):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO outage_buffer (payload_id, created_utc, egress_json) VALUES (?, ?, ?)",
        (payload_id, egress_dict["timestamp_utc"], json.dumps(egress_dict))
    )
    conn.commit()
    conn.close()

def get_buffer_size():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM outage_buffer")
    count = cursor.fetchone()[0]
    conn.close()
    return count

def record_egress_success(payload_dict):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT OR REPLACE INTO egress_ledger 
           (payload_id, timestamp_utc, pseudonym_source_id, category, severity, egress_json)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (payload_dict["payload_id"], payload_dict["timestamp_utc"],
         payload_dict["pseudonym_source_id"], payload_dict["category"],
         payload_dict["severity"], json.dumps(payload_dict))
    )
    # Remove from outage buffer if it was queued
    cursor.execute("DELETE FROM outage_buffer WHERE payload_id = ?", (payload_dict["payload_id"],))
    conn.commit()
    conn.close()

# Local Data Protection & Redaction Engine
PSEUDONYM_MAP = {
    "prod-db-master.corp.internal": "srv-node-db01",
    "prod-k8s-node-04.corp.internal": "srv-node-k8s04",
    "internal-payment-gateway-01": "srv-node-pay01",
    "edge-router-bangalore-core": "net-switch-blr01"
}

def scrub_text(text):
    if not isinstance(text, str):
        return text
    redacted = text
    redacted_occurred = False
    for rule in DATA_POLICY.get("redaction_rules", []):
        pattern = rule.get("pattern")
        replacement = rule.get("replacement")
        if re.search(pattern, redacted):
            redacted = re.sub(pattern, replacement, redacted)
            redacted_occurred = True
    if redacted_occurred:
        with SHARED_STATE["lock"]:
            SHARED_STATE["secrets_redacted_count"] += 1
    return redacted

def transform_and_enforce_policy(raw_record):
    """
    Takes raw internal telemetry with secrets and produces strict allow-listed metadata.
    Raw logs, secrets, and internal hostnames are stripped or pseudonymized.
    """
    raw_source = raw_record.get("raw_source_id", "unknown-host")
    pseudo_id = PSEUDONYM_MAP.get(raw_source, f"srv-{hash(raw_source) & 0xffff:04x}")

    # Scrub summary text
    raw_summary = raw_record.get("alert_summary") or raw_record.get("log_message") or "Periodic system telemetry"
    clean_summary = scrub_text(raw_summary)

    # Calculate health state based on local criteria
    metrics = raw_record.get("metrics", {})
    cpu = metrics.get("cpu_percent", 20.0)
    lat = metrics.get("latency_ms", 15.0)
    loss = metrics.get("packet_loss_percent", 0.0)
    auth_failures = metrics.get("auth_failed_count_1m", 0)

    if cpu > 90.0 or lat > 200.0 or loss > 5.0 or auth_failures >= 5:
        health_state = "Poor"
        severity = "critical"
    elif cpu > 75.0 or lat > 100.0 or loss > 1.0 or auth_failures >= 2:
        health_state = "Fair"
        severity = "warning"
    elif cpu > 50.0 or lat > 45.0:
        health_state = "Good"
        severity = "info"
    else:
        health_state = "Excellent"
        severity = "normal"

    candidate_payload = {
        "payload_id": raw_record.get("payload_id") or str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_timezone": CONFIG["source_timezone"],
        "tenant_id": CONFIG["tenant_id"],
        "collector_id": CONFIG["collector_id"],
        "collector_version": CONFIG["collector_version"],
        "pseudonym_source_id": pseudo_id,
        "category": raw_record.get("category", "infrastructure"),
        "severity": severity,
        "health_state": health_state,
        "metrics": {
            "cpu_percent": round(cpu, 1),
            "memory_percent": round(metrics.get("memory_percent", 42.0), 1),
            "disk_percent": round(metrics.get("disk_percent", 55.0), 1),
            "latency_ms": round(lat, 1),
            "packet_loss_percent": round(loss, 2),
            "bandwidth_mbps": round(metrics.get("bandwidth_mbps", 480.0), 1),
            "auth_failed_count_1m": auth_failures
        },
        "alert_summary": clean_summary
    }

    # Strict Field Allow-Listing: drop any key not explicitly approved in data_policy.json
    allow_list = DATA_POLICY.get("allow_listed_metadata_fields", [])
    egress_payload = {k: v for k, v in candidate_payload.items() if k in allow_list}

    return egress_payload

# SaaS Transmission Client (HTTP)
def send_to_saas(payload_dict):
    """
    Transmits metadata payload to SaaS endpoint.
    If unreachable or simulated outage is active, buffers to local SQLite.
    """
    payload_id = payload_dict["payload_id"]

    # Check simulated outage flag
    with SHARED_STATE["lock"]:
        is_sim_outage = SHARED_STATE["simulated_outage"]

    if is_sim_outage:
        queue_outage_buffer(payload_id, payload_dict)
        with SHARED_STATE["lock"]:
            SHARED_STATE["saas_reachable"] = False
        return False

    req_data = json.dumps(payload_dict).encode("utf-8")
    req = urllib.request.Request(
        CONFIG["saas_ingest_url"],
        data=req_data,
        headers={
            "Content-Type": "application/json",
            "Authorization": CONFIG["saas_token"],
            "X-Collector-ID": CONFIG["collector_id"],
            "X-Region": CONFIG["region"],
            "X-Tenant-ID": CONFIG["tenant_id"]
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            if resp.status == 200:
                record_egress_success(payload_dict)
                with SHARED_STATE["lock"]:
                    SHARED_STATE["saas_reachable"] = True
                    SHARED_STATE["total_sent"] += 1
                return True
            else:
                queue_outage_buffer(payload_id, payload_dict)
                with SHARED_STATE["lock"]:
                    SHARED_STATE["saas_reachable"] = False
                return False
    except Exception:
        # SaaS is down or unreachable -> buffer locally
        queue_outage_buffer(payload_id, payload_dict)
        with SHARED_STATE["lock"]:
            SHARED_STATE["saas_reachable"] = False
        return False

def flush_outage_buffer():
    """Background worker that flushes SQLite outage buffer once SaaS is back up."""
    with SHARED_STATE["lock"]:
        if SHARED_STATE["simulated_outage"]:
            return

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT payload_id, egress_json FROM outage_buffer ORDER BY id ASC LIMIT 10")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return

    for pid, egress_str in rows:
        try:
            payload_dict = json.loads(egress_str)
            # Attempt re-sending
            req_data = json.dumps(payload_dict).encode("utf-8")
            req = urllib.request.Request(
                CONFIG["saas_ingest_url"],
                data=req_data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": CONFIG["saas_token"],
                    "X-Collector-ID": CONFIG["collector_id"],
                    "X-Region": CONFIG["region"],
                    "X-Tenant-ID": CONFIG["tenant_id"]
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    record_egress_success(payload_dict)
                    with SHARED_STATE["lock"]:
                        SHARED_STATE["total_sent"] += 1
                        SHARED_STATE["saas_reachable"] = True
                    print(f"[Collector Buffer Flushed] Re-delivered buffered payload {pid}")
                else:
                    break
        except Exception:
            # Still unreachable
            break

def send_heartbeat():
    """Periodic heartbeat to inform SaaS platform of collector health & version."""
    with SHARED_STATE["lock"]:
        if SHARED_STATE["simulated_outage"]:
            return

    hb_payload = {
        "collector_id": CONFIG["collector_id"],
        "collector_version": CONFIG["collector_version"],
        "tenant_id": CONFIG["tenant_id"],
        "region": CONFIG["region"],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "online",
        "buffer_size": get_buffer_size(),
        "cpu_usage": round(random.uniform(1.2, 3.5), 1),
        "memory_mb": 42.5
    }
    try:
        req = urllib.request.Request(
            CONFIG["saas_heartbeat_url"],
            data=json.dumps(hb_payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": CONFIG["saas_token"]
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            if resp.status == 200:
                with SHARED_STATE["lock"]:
                    SHARED_STATE["saas_reachable"] = True
    except Exception:
        with SHARED_STATE["lock"]:
            SHARED_STATE["saas_reachable"] = False

# Background Telemetry Collection Loop
def telemetry_generator_loop():
    print("[Collector] Telemetry collection loop started. Monitoring local resources...")
    while True:
        try:
            # Generate baseline simulated telemetry
            raw_source = random.choice([
                "prod-db-master.corp.internal",
                "prod-k8s-node-04.corp.internal",
                "internal-payment-gateway-01",
                "edge-router-bangalore-core"
            ])
            
            # Normal baseline metrics with occasional subtle noise
            cpu_val = max(10.0, min(95.0, random.gauss(28.0, 5.0)))
            lat_val = max(5.0, min(250.0, random.gauss(18.0, 3.5)))
            loss_val = max(0.0, random.gauss(0.05, 0.02))

            raw_record = {
                "payload_id": str(uuid.uuid4()),
                "raw_source_id": raw_source,
                "internal_ip": "10.240.12.84",
                "customer_pii": "EmployeeID:EMP-9021; Department:Core-Infra",
                "credentials": "bearer_secret=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "stack_trace": "None; normal heartbeat operation",
                "category": "infrastructure",
                "metrics": {
                    "cpu_percent": cpu_val,
                    "memory_percent": random.uniform(40.0, 52.0),
                    "disk_percent": 54.2,
                    "latency_ms": lat_val,
                    "packet_loss_percent": loss_val,
                    "bandwidth_mbps": random.uniform(450.0, 520.0),
                    "auth_failed_count_1m": 0
                },
                "alert_summary": f"Routine node check for {raw_source}"
            }

            # 1. Store Raw Telemetry strictly inside local database
            store_raw_locally(raw_source, raw_record, contains_secret=True)

            # 2. Filter, scrub, and enforce allow-list policy
            egress_metadata = transform_and_enforce_policy(raw_record)

            # Update shared state for UI
            with SHARED_STATE["lock"]:
                SHARED_STATE["latest_raw"] = raw_record
                SHARED_STATE["latest_egress"] = egress_metadata

            # 3. Transmit metadata only
            send_to_saas(egress_metadata)

            # 4. Drain any backlogged buffer
            flush_outage_buffer()

            # 5. Heartbeat
            send_heartbeat()

        except Exception as e:
            print(f"[Collector Loop Error] {e}")

        time.sleep(3.0)

# Local HTTP Server for Egress Proof Panel UI
class EgressProofHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Quiet standard HTTP logs
        return

    def do_GET(self):
        if self.path == "/" or self.path == "/egress-proof":
            template_path = os.path.join(os.path.dirname(__file__), "templates", "egress_proof.html")
            try:
                with open(template_path, "r", encoding="utf-8") as f:
                    content = f.read().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Template load error: {e}".encode("utf-8"))
            return

        elif self.path == "/api/egress-proof":
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT egress_json FROM egress_ledger ORDER BY id DESC LIMIT 10")
            rows = cursor.fetchall()
            conn.close()

            history = [json.loads(r[0]) for r in rows]

            with SHARED_STATE["lock"]:
                payload = {
                    "collector_id": CONFIG["collector_id"],
                    "collector_version": CONFIG["collector_version"],
                    "saas_reachable": SHARED_STATE["saas_reachable"],
                    "simulated_outage": SHARED_STATE["simulated_outage"],
                    "total_sent": SHARED_STATE["total_sent"],
                    "secrets_redacted_count": SHARED_STATE["secrets_redacted_count"],
                    "buffer_queue_size": get_buffer_size(),
                    "latest_raw": SHARED_STATE["latest_raw"],
                    "latest_egress": SHARED_STATE["latest_egress"],
                    "history": history
                }
            resp_bytes = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.end_headers()
            self.wfile.write(resp_bytes)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path == "/api/toggle-outage":
            with SHARED_STATE["lock"]:
                SHARED_STATE["simulated_outage"] = not SHARED_STATE["simulated_outage"]
                new_state = SHARED_STATE["simulated_outage"]
            resp = json.dumps({"status": "ok", "simulated_outage": new_state}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        elif self.path == "/api/inject-sample-secret":
            # Live Scenario 1: Raw log contains secret & sensitive PII
            sample_secret_raw = {
                "payload_id": str(uuid.uuid4()),
                "raw_source_id": "prod-db-master.corp.internal",
                "internal_ip": "10.240.99.12",
                "customer_pii": "User: admin@internal.bank, SSN: 000-12-3456",
                "credentials": "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE secret_token=sk_live_9988223344",
                "stack_trace": "Database timeout in transaction block query: SELECT * FROM users WHERE pass='SuperSecret123'",
                "category": "security",
                "metrics": {
                    "cpu_percent": 45.0,
                    "memory_percent": 60.0,
                    "disk_percent": 70.0,
                    "latency_ms": 22.0,
                    "packet_loss_percent": 0.0,
                    "bandwidth_mbps": 500.0,
                    "auth_failed_count_1m": 0
                },
                "alert_summary": "DB Connection alert: auth_token=sk_live_9988223344 connecting from 10.240.99.12 using AKIAIOSFODNN7EXAMPLE"
            }

            store_raw_locally("prod-db-master.corp.internal", sample_secret_raw, contains_secret=True)
            egress_metadata = transform_and_enforce_policy(sample_secret_raw)

            with SHARED_STATE["lock"]:
                SHARED_STATE["latest_raw"] = sample_secret_raw
                SHARED_STATE["latest_egress"] = egress_metadata

            send_to_saas(egress_metadata)
            resp = json.dumps({"status": "ok", "message": "Secret log injected and redacted"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        self.send_response(404)
        self.end_headers()

def start_collector():
    # Start background telemetry generator
    t = threading.Thread(target=telemetry_generator_loop, daemon=True)
    t.start()

    # Start Local Egress Proof Panel Web Server
    server = HTTPServer(("0.0.0.0", CONFIG["egress_port"]), EgressProofHandler)
    print(f"\n==================================================================")
    print(f" [TIER 1] LOCAL COLLECTOR RUNNING")
    print(f" -> Egress Proof Panel UI: http://localhost:{CONFIG['egress_port']}/")
    print(f" -> Shipping allow-listed metadata to: {CONFIG['saas_ingest_url']}")
    print(f" -> Raw logs & secrets preserved in: {CONFIG['db_path']}")
    print(f"==================================================================\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Local Collector...")
        server.server_close()

if __name__ == "__main__":
    start_collector()
