#!/usr/bin/env python3
"""Offline validator for the Sigma rules in ./rules against synthetic logs.

Implements a documented SUBSET of Sigma (see README "Validator coverage"):
  - field matching with |contains, |startswith, |endswith, |re, |windash
  - boolean conditions: and / or / not / parentheses / `1 of selection_*`
  - aggregations: count(sel) by F > N, count_distinct(sel, F) by G > N + timeframe
  - lab-only correlation emulation for rules carrying x-lab-emulation: geo_velocity

Compares findings against logs/expected.json and scores TP/FP/FN.

Usage:
    python3 generate_logs.py          # (re)build the synthetic logs first
    python3 validate_rules.py [--rules rules] [--logs logs]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

# ---------------------------------------------------------------- parsing ---

TIME_RE = re.compile(r"^(\d+)([smhd])$")
SSH_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<msg>Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+.*)$"
)
MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_timeframe(s: str) -> int:
    m = TIME_RE.match(s.strip())
    if not m:
        raise ValueError(f"bad timeframe: {s!r}")
    n, unit = int(m.group(1)), m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def parse_ts(value: str) -> float:
    value = value.strip()
    try:  # ISO-8601 as produced by generate_logs.py
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ") \
            .replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        pass
    m = re.match(r"(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)", value)  # syslog
    if m:
        mon, day, hh, mm, ss = m.groups()
        return datetime(2026, MONTHS[mon], int(day),
                        int(hh), int(mm), int(ss),
                        tzinfo=timezone.utc).timestamp()
    raise ValueError(f"unparseable timestamp: {value!r}")


def load_events(log_dir: Path) -> list[dict]:
    events: list[dict] = []
    for name in ("security_events.jsonl", "process_events.jsonl"):
        p = log_dir / name
        if p.exists():
            for line in p.read_text().splitlines():
                if line.strip():
                    events.append(json.loads(line))
    auth = log_dir / "auth.log"
    if auth.exists():
        for line in auth.read_text().splitlines():
            m = SSH_RE.match(line)
            if not m:
                continue
            events.append({
                "LogSourceProduct": "linux",
                "LogSourceService": "sshd",
                "TimeCreated": f"2026-{MONTHS[m.group('mon')]:02d}-"
                               f"{int(m.group('day')):02d}T{m.group('time')}Z",
                "message": m.group("msg"),
                "user": m.group("user"),
                "src_ip": m.group("ip"),
            })
    for e in events:
        e["_ts"] = parse_ts(str(e["TimeCreated"]))
    events.sort(key=lambda e: e["_ts"])
    return events


# ------------------------------------------------------- selection matching ---

def _variants(pattern: str) -> list[str]:
    """windash: match both '-' and '/' spellings of a Windows command line."""
    return list({pattern, pattern.replace("-", "/"), pattern.replace("/", "-")})


def field_match(event: dict, field: str, patterns) -> bool:
    parts = field.split("|")
    name, mods = parts[0], parts[1:]
    if name not in event:
        return False
    value = str(event[name])
    if not isinstance(patterns, list):
        patterns = [patterns]
    for pat in patterns:
        cand = [str(pat)]
        if "windash" in mods:
            cand = _variants(str(pat))
        for c in cand:
            v, p = value, c
            if "re" in mods:
                if re.search(p, v):
                    return True
            elif "contains" in mods:
                if p.lower() in v.lower():
                    return True
            elif "startswith" in mods:
                if v.lower().startswith(p.lower()):
                    return True
            elif "endswith" in mods:
                if v.lower().endswith(p.lower()):
                    return True
            else:
                if v == p or (isinstance(event[name], int) and event[name] == pat):
                    return True
    return False


def selection_match(event: dict, selection: dict) -> bool:
    return all(field_match(event, f, p) for f, p in selection.items())


def logsource_match(rule_ls: dict, event: dict) -> bool:
    for key, want in (rule_ls or {}).items():
        got = event.get("LogSource" + key.capitalize(), "")
        if str(got).lower() != str(want).lower():
            return False
    return True


# ------------------------------------------------------------- conditions ---

TOKEN_RE = re.compile(r"\(|\)|,|>=|<=|>|<|==|[A-Za-z_][\w.*]*|\d+")


def tokenize(cond: str) -> list[str]:
    return TOKEN_RE.findall(cond)


class Parser:
    def __init__(self, tokens: list[str]):
        self.toks = tokens
        self.pos = 0

    def peek(self):
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def next(self):
        t = self.peek()
        self.pos += 1
        return t

    def parse(self):
        node = self.parse_or()
        if self.peek() is not None:
            raise ValueError(f"unexpected token {self.peek()!r}")
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek() == "or":
            self.next()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_unary()
        while self.peek() == "and":
            self.next()
            node = ("and", node, self.parse_unary())
        return node

    def parse_unary(self):
        if self.peek() == "not":
            self.next()
            return ("not", self.parse_unary())
        if self.peek() == "1" :
            # `1 of selection_*`
            self.next()
            assert self.next() == "of", "expected 'of' after '1'"
            pattern = self.next()
            return ("oneof", pattern)
        if self.peek() in ("count", "count_distinct"):
            return self.parse_agg()
        if self.peek() == "(":
            self.next()
            node = self.parse_or()
            assert self.next() == ")", "expected ')'"
            return node
        name = self.next()
        return ("sel", name)

    def parse_agg(self):
        kind = self.next()                      # count | count_distinct
        assert self.next() == "("
        sel = self.next()
        field = None
        if self.peek() == ",":
            self.next()
            field = self.next()
        assert self.next() == ")"
        assert self.next() == "by", "expected 'by' in aggregation"
        by = self.next()
        op = self.next()
        assert op in (">", ">=", "=="), f"unsupported operator {op!r}"
        threshold = int(self.next())
        return ("agg", kind, sel, field, by, op, threshold)


def eval_agg(matched: list[tuple[int, dict]], node, timeframe_s):
    _, kind, _sel, field, by, op, threshold = node
    findings = []
    seen: set = set()
    for i, (_idx, ev) in enumerate(matched):
        t0 = ev["_ts"]
        window = [(j, e) for j, e in matched[i:] if e["_ts"] - t0 <= timeframe_s]
        groups: dict = {}
        for j, e in window:
            groups.setdefault(e.get(by), []).append((j, e))
        for key, members in groups.items():
            val = (len(members) if kind == "count"
                   else len({m[1].get(field) for m in members}))
            ok = val > threshold if op == ">" else (
                val >= threshold if op == ">=" else val == threshold)
            if ok and key not in seen:
                seen.add(key)
                findings.append({
                    "group": f"{by}={key}",
                    "count": val,
                    "window_start": datetime.fromtimestamp(
                        t0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "sample_event": {k: v for k, v in members[0][1].items()
                                     if not k.startswith("_")},
                })
    return findings


def evaluate(rule: dict, events: list[dict]):
    """Return (findings, matched_index_sets)."""
    cands = [(i, e) for i, e in enumerate(events)
             if logsource_match(rule.get("logsource"), e)]
    det = rule.get("detection", {})
    sel_sets: dict[str, set[int]] = {}
    for name, sel in det.items():
        if name in ("timeframe", "condition"):
            continue
        sel_sets[name] = {i for i, e in cands if selection_match(e, sel)}

    cond = det.get("condition", "")
    node = Parser(tokenize(cond)).parse() if cond else ("sel", next(iter(sel_sets)))

    def ev_sets(n):
        kind = n[0]
        if kind == "sel":
            return sel_sets[n[1]]
        if kind == "oneof":
            prefix = n[1].rstrip("*")
            out: set[int] = set()
            for name, s in sel_sets.items():
                if name.startswith(prefix):
                    out |= s
            return out
        if kind == "and":
            return ev_sets(n[1]) & ev_sets(n[2])
        if kind == "or":
            return ev_sets(n[1]) | ev_sets(n[2])
        if kind == "not":
            all_idx = {i for i, _ in cands}
            return all_idx - ev_sets(n[1])
        raise ValueError(f"unexpected node {n}")

    findings: list[dict] = []
    if node[0] == "agg":
        _, _, sel_name, *_ = node
        matched = sorted(((i, events[i]) for i in sel_sets[sel_name]),
                         key=lambda t: t[1]["_ts"])
        tf = parse_timeframe(str(det.get("timeframe", "5m")))
        findings = eval_agg(matched, node, tf)
    else:
        for i in sorted(ev_sets(node)):
            e = events[i]
            findings.append({
                "group": f"event#{i}",
                "count": 1,
                "window_start": e["TimeCreated"],
                "sample_event": {k: v for k, v in e.items()
                                 if not k.startswith("_")},
            })
    return findings


def evaluate_correlation(rule: dict, events: list[dict]):
    """Lab emulation of geo-velocity for rules with x-lab-emulation: geo_velocity."""
    det = rule.get("detection", {})
    base_name = rule["correlation"]["rules"][0]
    base_sel = det[base_name]
    cands = [e for e in events
             if logsource_match(rule.get("logsource"), e)
             and selection_match(e, base_sel)]
    group_fields = rule["correlation"]["group-by"]
    timespan = parse_timeframe(rule["correlation"]["timespan"])
    groups: dict = {}
    for e in cands:
        groups.setdefault(tuple(e.get(f) for f in group_fields), []).append(e)
    findings = []
    for key, members in groups.items():
        members.sort(key=lambda e: e["_ts"])
        for a, b in zip(members, members[1:]):
            if (b["_ts"] - a["_ts"] <= timespan
                    and a.get("Country") != b.get("Country")):
                findings.append({
                    "group": f"{group_fields[0]}={key[0]}",
                    "count": 2,
                    "window_start": a["TimeCreated"],
                    "sample_event": {
                        "first": {k: v for k, v in a.items() if not k.startswith("_")},
                        "second": {k: v for k, v in b.items() if not k.startswith("_")},
                    },
                })
    return findings


# ------------------------------------------------------------------- main ---

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="rules")
    ap.add_argument("--logs", default="logs")
    args = ap.parse_args()

    rule_dir, log_dir = Path(args.rules), Path(args.logs)
    events = load_events(log_dir)
    expected = json.loads((log_dir / "expected.json").read_text())
    print(f"loaded {len(events)} events from {log_dir}/\n")

    total_tp = total_fp = total_fn = 0
    all_ok = True
    for path in sorted(rule_dir.glob("*.yml")):
        rule = yaml.safe_load(path.read_text())
        stem = path.stem
        tags = rule.get("tags", [])
        attack = next((t for t in tags if t.startswith("attack.t")), "n/a")
        if rule.get("correlation", {}).get("x-lab-emulation") == "geo_velocity":
            findings = evaluate_correlation(rule, events)
        else:
            findings = evaluate(rule, events)
        exp = expected.get(stem, 0)
        got = len(findings)
        if got == exp:
            verdict, ok = "TRUE POSITIVE", True
            total_tp += 1
        elif got > exp:
            verdict, ok = f"FALSE POSITIVE (+{got - exp})", False
            total_fp += 1
        else:
            verdict, ok = f"FALSE NEGATIVE ({exp - got} missed)", False
            total_fn += 1
        all_ok &= ok
        print(f"[{stem}] {rule.get('title')}")
        print(f"  ATT&CK: {attack} | level={rule.get('level')}")
        print(f"  fired {got} finding(s), expected {exp} -> {verdict}")
        for f in findings[:3]:
            print(f"    - {f['group']} count={f['count']} at {f['window_start']}")
        print()
    print(f"rules: {total_tp} TP, {total_fp} FP, {total_fn} FN")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
