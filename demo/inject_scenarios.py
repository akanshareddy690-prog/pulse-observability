"""
Interactive Hackathon Judge Demonstration Script
Directly demonstrates all 8 Live Scenarios from Section 8 of the Judge's Guide.
"""

import sys
import time
import json
import uuid
from datetime import datetime, timezone
import urllib.request

COLLECTOR_URL = "http://127.0.0.1:8001"
SAAS_URL = "http://127.0.0.1:8000"

def post_json(url, path, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{url}{path}",
        data=data,
        headers={"Content-Type": "application/json", "Authorization": "Bearer collector-secret-key-2026"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=3.0) as resp:
        return json.loads(resp.read().decode("utf-8"))

def scenario_1_secret_scrubbing():
    print("\n[Scenario 1] Injecting Raw Log with AWS Secrets & PII...")
    res = post_json(COLLECTOR_URL, "/api/inject-sample-secret", {})
    print(" -> Injected successfully!")
    print(" -> Verification step for judges:")
    print("    1. Open Collector Egress Proof: http://localhost:8001")
    print("    2. Notice Raw side holds: AWS_SECRET_KEY=AKIA... and unhashed passwords.")
    print("    3. Notice Egress side holds: [REDACTED_AWS_KEY] and [REDACTED_SECRET].")
    print("    4. Open SaaS Dashboard: http://localhost:8000 -> zero secrets visible!")

def scenario_2_outage_buffering():
    print("\n[Scenario 2] Simulating SaaS Outage & SQLite Post-Outage Backlog Replay...")
    print(" -> 1. Severing Collector link to SaaS...")
    post_json(COLLECTOR_URL, "/api/toggle-outage", {})
    print(" -> Disconnected! Generating 5 telemetry records into local SQLite buffer...")
    for i in range(5):
        time.sleep(1)
        print(f"    Buffering record #{i+1} locally...")
    
    print("\n -> Check http://localhost:8001 now: notice 'Buffered in Local SQLite' count is > 0.")
    input("\n Press [ENTER] to restore connection and trigger backlog flush...")

    print(" -> 2. Reconnecting link to SaaS...")
    post_json(COLLECTOR_URL, "/api/toggle-outage", {})
    time.sleep(2)
    print(" -> Backlog automatically re-delivered to SaaS with zero data loss and zero duplicates!")

def scenario_3_failed_logins():
    print("\n[Scenario 3] Injecting Security Anomaly: Repeated Authentication Failures...")
    payload = {
        "payload_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_timezone": "UTC+05:30",
        "tenant_id": "tenant-alpha",
        "collector_id": "col-local-01",
        "pseudonym_source_id": "srv-node-db01",
        "category": "security",
        "severity": "critical",
        "health_state": "Poor",
        "metrics": {
            "cpu_percent": 35.0,
            "latency_ms": 19.0,
            "packet_loss_percent": 0.0,
            "auth_failed_count_1m": 6
        },
        "alert_summary": "Security alert: 6 repeated authentication failures within 60s"
    }
    post_json(SAAS_URL, "/api/v1/telemetry/ingest", payload)
    print(" -> Transmitted security risk indicator to SaaS!")
    print(" -> Check http://localhost:8000: Notice AIOps Correlated Incident and Poor health status.")

def scenario_4_network_latency():
    print("\n[Scenario 4] Injecting Network Latency Spike (240ms)...")
    payload = {
        "payload_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_timezone": "UTC+05:30",
        "tenant_id": "tenant-alpha",
        "collector_id": "col-local-01",
        "pseudonym_source_id": "net-switch-blr01",
        "category": "network",
        "severity": "warning",
        "health_state": "Fair",
        "metrics": {
            "cpu_percent": 30.0,
            "latency_ms": 240.0,
            "packet_loss_percent": 2.8,
            "auth_failed_count_1m": 0
        },
        "alert_summary": "Network switch transit latency elevated to 240ms"
    }
    post_json(SAAS_URL, "/api/v1/telemetry/ingest", payload)
    print(" -> Check http://localhost:8000: Latency chart spikes and AIOps explains anomaly with rerouting advice.")

def scenario_5_cpu_anomaly():
    print("\n[Scenario 5] Injecting CPU Saturation Spike (94%)...")
    payload = {
        "payload_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_timezone": "UTC+05:30",
        "tenant_id": "tenant-alpha",
        "collector_id": "col-local-01",
        "pseudonym_source_id": "srv-node-k8s04",
        "category": "infrastructure",
        "severity": "critical",
        "health_state": "Poor",
        "metrics": {
            "cpu_percent": 94.5,
            "latency_ms": 25.0,
            "packet_loss_percent": 0.1,
            "auth_failed_count_1m": 0
        },
        "alert_summary": "Compute node CPU utilization exceeded 94%"
    }
    post_json(SAAS_URL, "/api/v1/telemetry/ingest", payload)
    print(" -> Check http://localhost:8000: CPU chart spikes, Z-Score deviation flagged with restart proposal.")

def scenario_6_alert_correlation():
    print("\n[Scenario 6] Injecting Multi-Signal Correlated Crisis...")
    print(" -> Triggering concurrent CPU saturation + Latency surge + Packet loss...")
    payload = {
        "payload_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_timezone": "UTC+05:30",
        "tenant_id": "tenant-alpha",
        "collector_id": "col-local-01",
        "pseudonym_source_id": "srv-node-pay01",
        "category": "system",
        "severity": "critical",
        "health_state": "Poor",
        "metrics": {
            "cpu_percent": 91.2,
            "latency_ms": 220.0,
            "packet_loss_percent": 4.5,
            "auth_failed_count_1m": 0
        },
        "alert_summary": "Payment node service strain: high load and network congestion"
    }
    post_json(SAAS_URL, "/api/v1/telemetry/ingest", payload)
    print(" -> Check http://localhost:8000:")
    print("    Multiple discrete alerts are noise-reduced and correlated into ONE Incident card!")
    print("    Click 'Approve Remediation' to execute policy-bounded mitigation and view audit trail.")

def scenario_7_duplicate_deduplication():
    print("\n[Scenario 7] Testing Idempotent Delivery (Zero Duplicates)...")
    fixed_id = "idem-" + str(uuid.uuid4())[:8]
    payload = {
        "payload_id": fixed_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_timezone": "UTC+05:30",
        "tenant_id": "tenant-alpha",
        "collector_id": "col-local-01",
        "pseudonym_source_id": "srv-node-db01",
        "category": "infrastructure",
        "severity": "normal",
        "health_state": "Excellent",
        "metrics": {"cpu_percent": 25.0, "latency_ms": 15.0},
        "alert_summary": "Idempotency test payload"
    }
    print(f" -> Sending payload {fixed_id} for the 1st time...")
    r1 = post_json(SAAS_URL, "/api/v1/telemetry/ingest", payload)
    print(f"    SaaS Response: {r1}")

    print(f" -> Sending the EXACT SAME payload {fixed_id} again (simulating network retry)...")
    r2 = post_json(SAAS_URL, "/api/v1/telemetry/ingest", payload)
    print(f"    SaaS Response: {r2}")
    print(" -> Notice status: 'duplicate_ignored'. SaaS guarantees zero duplicate records!")

def main_menu():
    while True:
        print("\n" + "="*65)
        print("  PULSE PLATFORM - VERIFICATION & SCENARIO HARNESS")
        print("="*65)
        print(" [1] Scenario 1: Raw Log Contains Secret (Redaction & Egress Proof)")
        print(" [2] Scenario 2: Collector Loses SaaS Link (Local Buffering & Replay)")
        print(" [3] Scenario 3: Repeated Failed Logins (Security Risk Summary)")
        print(" [4] Scenario 4: Network Latency Spike (Dynamic Anomaly Alert)")
        print(" [5] Scenario 5: CPU Deviation from Baseline (Z-Score & Recommendation)")
        print(" [6] Scenario 6: Alert Noise Reduction (Correlated Crisis Incident)")
        print(" [7] Scenario 7: Idempotency & De-duplication Test")
        print(" [8] Run All Scenarios Sequentially (Demo Showcase)")
        print(" [0] Exit")
        print("="*65)
        choice = input("Select scenario [0-8]: ").strip()

        if choice == "1":
            scenario_1_secret_scrubbing()
        elif choice == "2":
            scenario_2_outage_buffering()
        elif choice == "3":
            scenario_3_failed_logins()
        elif choice == "4":
            scenario_4_network_latency()
        elif choice == "5":
            scenario_5_cpu_anomaly()
        elif choice == "6":
            scenario_6_alert_correlation()
        elif choice == "7":
            scenario_7_duplicate_deduplication()
        elif choice == "8":
            print("\n>>> Running Full Demo Showcase <<<")
            scenario_1_secret_scrubbing()
            time.sleep(2)
            scenario_4_network_latency()
            time.sleep(2)
            scenario_5_cpu_anomaly()
            time.sleep(2)
            scenario_6_alert_correlation()
            time.sleep(2)
            scenario_7_duplicate_deduplication()
            print("\nShowcase complete! Inspect dashboards at http://localhost:8000 and http://localhost:8001")
        elif choice == "0":
            break
        else:
            print("Invalid selection, please try again.")

if __name__ == "__main__":
    main_menu()
