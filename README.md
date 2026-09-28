# SIEM Detection Rules Lab

Sigma-format detection rules for common credential-access and intrusion
techniques, each mapped to MITRE ATT&CK. Includes a synthetic log generator
and an offline validator that executes the rules against the logs and scores
true/false positives — so the detections can be demonstrated without a live
SIEM.

## Skills demonstrated

- Sigma rule authoring (logsource, selection, aggregation, correlation)
- MITRE ATT&CK mapping (T1110.001, T1110.003, T1003.001, T1078)
- Threshold tuning to separate brute force from password spraying
- Building a test harness: synthetic data generation + detection validation

## Rule catalog

| File | Detects | ATT&CK | Logic |
|---|---|---|---|
| `rules/windows_rdp_brute_force.yml` | RDP password guessing | T1110.001 | >10 Event ID 4625 (LogonType 10) per source IP in 5 min |
| `rules/linux_ssh_brute_force.yml` | SSH password guessing | T1110.001 | >10 sshd "Failed password" per source IP in 5 min |
| `rules/password_spraying.yml` | Password spraying | T1110.003 | >5 **distinct** usernames with failed logons per source IP in 15 min |
| `rules/credential_dumping_mimikatz.yml` | Mimikatz / LSASS dumping tools | T1003.001 | Process creation: known bad image names or dumping command lines (`sekurlsa::logonpasswords`, `procdump -ma lsass`, …) |
| `rules/impossible_travel_logon.yml` | Hijacked session / stolen credentials | T1078 | Successful logons (4624) for one account from two countries within 60 min |

## How to run the demo

```bash
python3 generate_logs.py    # build synthetic logs in ./logs (deterministic)
python3 validate_rules.py   # run every rule, print findings, score vs expected
```

Requirements: Python 3.8+ and PyYAML (`pip install pyyaml`). No SIEM needed.

## Sample output

```
[windows_rdp_brute_force] RDP Brute Force - Multiple Failed Remote Logons
  ATT&CK: attack.t1110.001 | level=high
  fired 1 finding(s), expected 1 -> TRUE POSITIVE
    - IpAddress=203.0.113.45 count=25 at 2026-09-28T04:00:00Z

[password_spraying] Password Spraying - One Source Against Many Accounts
  ATT&CK: attack.t1110.003 | level=high
  fired 1 finding(s), expected 1 -> TRUE POSITIVE
    - IpAddress=198.51.100.77 count=8 at 2026-09-28T04:20:00Z

[credential_dumping_mimikatz] Credential Dumping Indicators - Mimikatz and LSASS Access Tools
  ATT&CK: attack.t1003.001 | level=critical
  fired 2 finding(s), expected 2 -> TRUE POSITIVE

[impossible_travel_logon] Impossible Travel - Successful Logons From Distant Locations
  ATT&CK: attack.t1078 | level=high
  fired 1 finding(s), expected 1 -> TRUE POSITIVE
    - TargetUserName=gsingh count=2 at 2026-09-28T05:10:00Z

rules: 5 TP, 0 FP, 0 FN
```

The generator also plants benign noise (scattered mistyped passwords, normal
processes, same-country logons) — the 0 FP / 0 FN score shows the thresholds
hold against it.

## Validator coverage (honest scope)

`validate_rules.py` implements a documented subset of Sigma: field matching
with `|contains`, `|startswith`, `|endswith`, `|re`, `|windash`; boolean
conditions (`and`/`or`/`not`, `1 of selection_*`); and threshold aggregation
(`count(...) by ...`, `count_distinct(...) by ...` with `timeframe`).

Two things need a live backend and are emulated, not executed, here:

1. **Full Sigma compilation** — in production these rules compile via pySigma
   (e.g. `pysigma-backend-splunk`, `pysigma-backend-qradar`) or import
   natively into Sentinel/Elastic. The YAML files are standard Sigma otherwise.
2. **Impossible travel** — stock Sigma correlation types cannot express
   geo-velocity. The rule carries the lab-only extension
   `x-lab-emulation: geo_velocity`, which the validator emulates against the
   `Country` field. A production equivalent is a SIEM analytics rule over
   IP-geolocation-enriched sign-in logs.

## Lab notes

- All IP addresses are RFC 5737 documentation ranges; countries are fictional
  labels for the demo.
- Thresholds (10 failures / 5 min, 5 users / 15 min) are lab baselines — tune
  per environment; the validator makes re-tuning testable.
