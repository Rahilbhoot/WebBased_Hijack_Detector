"""Direct Attack Simulation & Telemetry Injector.

Generates realistic NormalizedEvents for all browser hijacking scenarios (BH001-BH008, CR01-CR03)
and transmits them through the cloud ingestion API (`POST /events`) so they immediately
evaluate, correlate, and populate the SOC Dashboard.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path


# Load environment configuration
def load_env() -> dict:
    env = {}
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.exists():
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip("'\"")
    return env

CONFIG = load_env()
API_ENDPOINT = CONFIG.get("API_ENDPOINT", "https://2w4n8ta2ri.execute-api.ap-south-1.amazonaws.com")
API_KEY = CONFIG.get("API_KEY", "91199758c8f924c357fe82d099453e61ec4eb6c744ca1bc3230513951efae74d")
DEVICE_ID = CONFIG.get("DEVICE_ID", "PC-LAB-01")


def create_attack_events(attack_type: str) -> list[dict]:
    """Generates synthetic normalized attack events matching specified scenario."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if attack_type == "BH001":
        # Chrome launched with proxy flag
        return [{
            "event_id": str(uuid.uuid4()),
            "device_id": DEVICE_ID,
            "timestamp": now_iso,
            "type": "process_create",
            "source_event_id": 4688,
            "process_image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "command_line": r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --headless --proxy-server="127.0.0.1:9999" --load-extension="C:\Users\Student\AppData\Local\Temp\ad_injector"',
            "parent_image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "user": rf"{DEVICE_ID}\Analyst",
        }]

    elif attack_type == "BH002":
        # Chrome Policy modified in Registry
        return [{
            "event_id": str(uuid.uuid4()),
            "device_id": DEVICE_ID,
            "timestamp": now_iso,
            "type": "registry_set",
            "source_event_id": 13,
            "process_image": r"C:\Users\Student\AppData\Local\Temp\dropper.exe",
            "registry_key": r"HKLM\SOFTWARE\Policies\Google\Chrome",
            "registry_value_name": "HomepageLocation",
            "registry_value": "http://malicious-hijack-search.top",
            "user": rf"{DEVICE_ID}\Analyst",
        }]

    elif attack_type == "BH003":
        # System proxy / PAC setting modified
        return [{
            "event_id": str(uuid.uuid4()),
            "device_id": DEVICE_ID,
            "timestamp": now_iso,
            "type": "registry_set",
            "source_event_id": 13,
            "process_image": r"C:\Windows\System32\cmd.exe",
            "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "registry_value_name": "ProxyServer",
            "registry_value": "127.0.0.1:8888",
            "user": rf"{DEVICE_ID}\Analyst",
        }]

    elif attack_type == "BH004":
        # Hosts file modification
        return [{
            "event_id": str(uuid.uuid4()),
            "device_id": DEVICE_ID,
            "timestamp": now_iso,
            "type": "file_create",
            "source_event_id": 11,
            "file_path": r"C:\Windows\System32\drivers\etc\hosts",
            "process_image": r"C:\Windows\System32\notepad.exe",
            "user": rf"{DEVICE_ID}\Administrator",
        }]

    elif attack_type == "BH005":
        # Browser shortcut modification
        return [{
            "event_id": str(uuid.uuid4()),
            "device_id": DEVICE_ID,
            "timestamp": now_iso,
            "type": "file_create",
            "source_event_id": 11,
            "file_path": r"C:\Users\Analyst\Desktop\Google Chrome.lnk",
            "process_image": r"C:\Users\Analyst\Downloads\updater.exe",
            "user": rf"{DEVICE_ID}\Analyst",
        }]

    elif attack_type == "BH006":
        # Suspicious scheduled task created
        return [{
            "event_id": str(uuid.uuid4()),
            "device_id": DEVICE_ID,
            "timestamp": now_iso,
            "type": "task_create",
            "source_event_id": 4698,
            "command_line": r"C:\Windows\System32\cmd.exe /c start chrome.exe http://evil-search.com",
            "registry_value_name": "GoogleChromeUpdateTaskDaily",
            "user": rf"{DEVICE_ID}\System",
        }]

    elif attack_type == "CR01":
        # Correlated multi-stage attack: Policy modified followed immediately by browser launch with proxy flag!
        return [
            {
                "event_id": str(uuid.uuid4()),
                "device_id": DEVICE_ID,
                "timestamp": now_iso,
                "type": "registry_set",
                "source_event_id": 13,
                "process_image": r"C:\Users\Analyst\AppData\Local\Temp\dropper.exe",
                "registry_key": r"HKLM\SOFTWARE\Policies\Google\Chrome",
                "registry_value_name": "DefaultSearchProviderSearchURL",
                "registry_value": "http://hijack.portal/search?q={searchTerms}",
                "user": rf"{DEVICE_ID}\Analyst",
            },
            {
                "event_id": str(uuid.uuid4()),
                "device_id": DEVICE_ID,
                "timestamp": now_iso,
                "type": "process_create",
                "source_event_id": 4688,
                "process_image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "command_line": r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --proxy-server="127.0.0.1:9999"',
                "parent_image": r"C:\Users\Analyst\AppData\Local\Temp\dropper.exe",
                "user": rf"{DEVICE_ID}\Analyst",
            }
        ]

    else:
        raise ValueError(f"Unknown attack type: {attack_type}")


def send_batch(events: list[dict]) -> dict:
    """Posts event batch to cloud API Gateway."""
    url = f"{API_ENDPOINT.rstrip('/')}/events"
    payload = {
        "device_id": DEVICE_ID,
        "agent_version": "1.0.0",
        "events": events,
    }
    data_bytes = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=data_bytes,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=15) as res:
        return json.loads(res.read().decode())


def fetch_latest_alerts() -> list[dict]:
    """Fetches alerts from API Gateway."""
    url = f"{API_ENDPOINT.rstrip('/')}/alerts?device_id={DEVICE_ID}"
    req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as res:
        data = json.loads(res.read().decode())
        return data.get("alerts", [])


def main():
    parser = argparse.ArgumentParser(description="Simulate and inject browser hijack attack events.")
    parser.add_argument(
        "--scenario",
        default="CR01",
        choices=["BH001", "BH002", "BH003", "BH004", "BH005", "BH006", "CR01", "ALL"],
        help="Attack scenario to simulate (default: CR01 multi-stage correlation)",
    )
    args = parser.parse_args()

    scenarios = ["BH001", "BH002", "BH003", "BH004", "BH006", "CR01"] if args.scenario == "ALL" else [args.scenario]

    print("=" * 60)
    print("  BROWSER HIJACK DETECTION - LIVE ATTACK INJECTOR")
    print(f"  Target Device: {DEVICE_ID}")
    print(f"  API Endpoint:  {API_ENDPOINT}")
    print("=" * 60)

    for sc in scenarios:
        events = create_attack_events(sc)
        print(f"\n[*] Injecting scenario [{sc}] ({len(events)} event(s))...")
        try:
            res = send_batch(events)
            print(f" [+] Cloud Ingestion response: {res.get('status', 'OK')} (Batch: {res.get('batch_id', 'N/A')})")
        except Exception as e:
            print(f" [!] Ingestion failed: {e}")

    print("\n[*] Waiting 2 seconds for cloud detection engine to process...")
    time.sleep(2)

    alerts = fetch_latest_alerts()
    print(f"\n[OK] Current Active Incidents on Device '{DEVICE_ID}': {len(alerts)}")
    for a in alerts[:5]:
        print(f"  * [{a.get('severity', 'UNKNOWN')}] Alert ID: {a.get('alert_id')} | Rules: {a.get('rule_ids')} | Score: {a.get('score')}")
        print(f"    Narrative: {a.get('explanation', '')[:95]}...")

    print("\n" + "=" * 60)
    print("  VIEW LIVE DASHBOARD:")
    print("  -> http://localhost:3000/alerts")
    print("=" * 60)


if __name__ == "__main__":
    main()
