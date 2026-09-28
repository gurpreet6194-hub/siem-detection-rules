#!/usr/bin/env python3
"""Generate synthetic Windows/Sysmon-style and syslog events for rule testing.

All IPs are from RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) — no real hosts are referenced. A labels file (expected.json)
records which rules SHOULD fire so validate_rules.py can score true/false
positives.

Usage:
    python3 generate_logs.py [--out logs]
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_TIME = datetime(2026, 9, 28, 4, 0, 0, tzinfo=timezone.utc)
rng = random.Random(20260928)  # deterministic output

# Documentation-range IPs with fictional geo labels used by the lab
GEO = {
    "203.0.113.45": "Canada",
    "203.0.113.10": "Canada",
    "198.51.100.77": "United Kingdom",
    "198.51.100.10": "United Kingdom",
    "192.0.2.60": "United States",
    "10.0.5.21": "Internal",
    "10.0.5.22": "Internal",
}


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ev_4625(ts, user, ip, logon_type=3):
    return {
        "LogSourceProduct": "windows",
        "LogSourceCategory": "authentication",
        "EventID": 4625,
        "TimeCreated": iso(ts),
        "TargetUserName": user,
        "IpAddress": ip,
        "LogonType": logon_type,
        "WorkstationName": "WORKSTATION-01",
        "Country": GEO.get(ip, "Unknown"),
    }


def ev_4624(ts, user, ip, logon_type=3):
    e = ev_4625(ts, user, ip, logon_type)
    e["EventID"] = 4624
    return e


def ev_process(ts, image, cmdline, parent="C:\\Windows\\explorer.exe"):
    return {
        "LogSourceProduct": "windows",
        "LogSourceCategory": "process_creation",
        "EventID": 4688,
        "TimeCreated": iso(ts),
        "Image": image,
        "CommandLine": cmdline,
        "ParentImage": parent,
    }


def syslog_failed(ts, user, ip):
    ts_s = ts.strftime("%b %d %H:%M:%S")
    return (
        f"{ts_s} webserver sshd[2481]: Failed password for invalid user "
        f"{user} from {ip} port {rng.randint(40000, 60000)} ssh2"
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="logs")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    sec_events: list[dict] = []   # 4624/4625
    proc_events: list[dict] = []  # 4688
    auth_lines: list[str] = []    # syslog sshd

    t = BASE_TIME

    # --- Scenario 1: RDP brute force — 25 failures, 1 IP, 3 minutes ----------
    for i in range(25):
        sec_events.append(ev_4625(t + timedelta(seconds=i * 7),
                                  "administrator", "203.0.113.45", logon_type=10))

    # --- Scenario 2: password spraying — 1 IP, 8 users x 2 attempts, 12 min --
    spray_users = ["jdoe", "asmith", "bwayne", "ckent", "pparker",
                   "nromanoff", "tstark", "brogers"]
    for i, user in enumerate(spray_users):
        for k in range(2):
            sec_events.append(ev_4625(t + timedelta(minutes=20 + i * 1.5 + k * 0.4),
                                      user, "198.51.100.77", logon_type=3))

    # --- Benign 4625 noise (should NOT fire anything) -------------------------
    for i in range(3):
        sec_events.append(ev_4625(t + timedelta(minutes=5 + i * 47),
                                  "jdoe", "10.0.5.21", logon_type=2))

    # --- Scenario 3: SSH brute force — 14 failures, 1 IP, 4 minutes -----------
    for i in range(14):
        auth_lines.append(syslog_failed(t + timedelta(seconds=i * 17),
                                        rng.choice(["admin", "root", "test"]),
                                        "192.0.2.60"))
    # benign ssh noise
    auth_lines.append(syslog_failed(t + timedelta(minutes=40), "jdoe", "10.0.5.22"))
    auth_lines.append("Sep 28 04:41:02 webserver sshd[2481]: Accepted password "
                      "for jdoe from 10.0.5.22 port 51234 ssh2")

    # --- Scenario 4: credential dumping tooling -------------------------------
    proc_events.append(ev_process(
        t + timedelta(minutes=55),
        "C:\\Windows\\Temp\\mimikatz.exe",
        'mimikatz.exe "sekurlsa::logonpasswords" "exit"'))
    proc_events.append(ev_process(
        t + timedelta(minutes=57),
        "C:\\Tools\\procdump64.exe",
        "procdump64.exe -ma lsass.exe C:\\Temp\\lsass.dmp"))
    # benign processes
    proc_events.append(ev_process(t + timedelta(minutes=10),
                                  "C:\\Windows\\System32\\notepad.exe", "notepad.exe"))
    proc_events.append(ev_process(t + timedelta(minutes=30),
                                  "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                                  "chrome.exe --renderer"))

    # --- Scenario 5: impossible travel — Toronto then London, 22 min apart ----
    sec_events.append(ev_4624(t + timedelta(minutes=70), "gsingh", "203.0.113.10"))
    sec_events.append(ev_4624(t + timedelta(minutes=92), "gsingh", "198.51.100.10"))
    # normal logons for another user (same country — no alert)
    sec_events.append(ev_4624(t + timedelta(minutes=75), "jdoe", "10.0.5.21", logon_type=2))
    sec_events.append(ev_4624(t + timedelta(minutes=120), "jdoe", "10.0.5.21", logon_type=2))

    sec_events.sort(key=lambda e: e["TimeCreated"])
    proc_events.sort(key=lambda e: e["TimeCreated"])

    (out / "security_events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in sec_events) + "\n")
    (out / "process_events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in proc_events) + "\n")
    (out / "auth.log").write_text("\n".join(sorted(auth_lines)) + "\n")

    expected = {
        # rule file stem -> expected number of findings
        "windows_rdp_brute_force": 1,
        "linux_ssh_brute_force": 1,
        "password_spraying": 1,
        "credential_dumping_mimikatz": 2,
        "impossible_travel_logon": 1,
    }
    (out / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")

    print(f"wrote {len(sec_events)} security events, "
          f"{len(proc_events)} process events, "
          f"{len(auth_lines)} syslog lines -> {out}/")


if __name__ == "__main__":
    main()
