#!/usr/bin/env python3
"""
audit.py - NetCheck security audit.

Reads the running configuration saved in a snapshot and checks every device
against a short list of hardening rules: SSH-only access, hashed passwords,
management access lists, idle timeouts, logging and so on.

    python audit.py                 audit the most recent snapshot
    python audit.py pre             audit the latest snapshot with that label
    python audit.py runs\\A          audit a specific snapshot folder
    python audit.py --verbose       show the evidence for every failed check

It reads only saved snapshot files. It never connects to a device and never
changes anything. The snapshot must include "show running-config", which
collect.py saves with passwords and keys already redacted.

The exit code is 1 if any HIGH severity check fails.
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

CONFIG_FILE = "show_running_config.txt"
HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"


class Config:
    """A running configuration split into top-level lines and their indented children."""

    def __init__(self, text):
        self.blocks = []
        for raw in text.splitlines():
            if not raw.strip() or raw.strip() == "!":
                continue
            if raw.startswith(" ") and self.blocks:
                self.blocks[-1][1].append(raw.strip())
            else:
                self.blocks.append((raw.strip(), []))
        self.top = [line for line, _children in self.blocks]

    def has(self, pattern):
        return any(re.search(pattern, line) for line in self.top)

    def find(self, pattern):
        return [line for line in self.top if re.search(pattern, line)]

    def sections(self, prefix):
        return [(line, children) for line, children in self.blocks if line.startswith(prefix)]


# --------------------------------------------------------------------------
# Rules. Each returns (passed, evidence). Evidence says what was found.
# --------------------------------------------------------------------------
def rule_ssh_only(cfg):
    bad = []
    for line, children in cfg.sections("line vty"):
        transport = [c for c in children if c.startswith("transport input")]
        if not transport or transport[0] not in ("transport input ssh", "transport input none"):
            bad.append("%s: %s" % (line, transport[0] if transport else "no 'transport input' set, so telnet is allowed"))
    return not bad, "; ".join(bad) or "all VTY lines accept SSH only"


def rule_enable_secret(cfg):
    if cfg.has(r"^enable password"):
        return False, "'enable password' is set (weak, reversible)"
    if not cfg.has(r"^enable secret"):
        return False, "no 'enable secret' is set"
    return True, "'enable secret' is set"


def rule_user_secrets(cfg):
    weak = [line.split()[1] for line in cfg.find(r"^username \S+ .*\bpassword\b")]
    if weak:
        return False, "accounts using 'password' instead of 'secret': %s" % ", ".join(weak)
    return True, "local accounts use 'secret'" if cfg.has(r"^username ") else "no local accounts"


def rule_ssh_v2(cfg):
    ok = cfg.has(r"^ip ssh version 2")
    return ok, "'ip ssh version 2' is set" if ok else "'ip ssh version 2' is missing, so SSH version 1 is allowed"


def rule_http_off(cfg):
    on = cfg.find(r"^ip http (secure-)?server")
    return not on, "enabled: %s" % ", ".join(on) if on else "HTTP and HTTPS servers are off"


def rule_vty_acl(cfg):
    bad = [line for line, children in cfg.sections("line vty")
           if not any(re.match(r"access-class \S+ in", c) for c in children)]
    return not bad, "no 'access-class ... in' on: %s" % ", ".join(bad) if bad else "all VTY lines have an access list"


def rule_idle_timeout(cfg):
    bad = [line for line, children in cfg.sections("line ")
           if any(re.match(r"exec-timeout 0( 0)?$", c) for c in children)]
    return not bad, "sessions never time out on: %s" % ", ".join(bad) if bad else "no line has the timeout disabled"


def rule_password_encryption(cfg):
    ok = cfg.has(r"^service password-encryption")
    return ok, "'service password-encryption' is on" if ok else "'service password-encryption' is off"


def rule_banner(cfg):
    ok = cfg.has(r"^banner (login|motd)")
    return ok, "a login banner is set" if ok else "no login banner"


def rule_syslog(cfg):
    ok = cfg.has(r"^logging (host )?\d+\.\d+\.\d+\.\d+")
    return ok, "a syslog server is configured" if ok else "no syslog server, so logs are lost when the device restarts"


def rule_ntp(cfg):
    ok = cfg.has(r"^ntp (server|master)")
    return ok, "an NTP source is configured" if ok else "no NTP server, so log timestamps cannot be trusted"


def rule_snmp(cfg):
    found = cfg.find(r"^snmp-server community")
    return not found, "%d SNMP v1/v2c community string(s) in use" % len(found) if found else "no SNMP v1/v2c communities"


RULES = [
    ("ssh-only",       HIGH,   "Remote access is SSH only (no telnet)",     rule_ssh_only),
    ("enable-secret",  HIGH,   "Privileged password is stored as a hash",   rule_enable_secret),
    ("user-secrets",   HIGH,   "Local accounts use hashed secrets",         rule_user_secrets),
    ("ssh-v2",         MEDIUM, "SSH version 2 only",                        rule_ssh_v2),
    ("http-off",       MEDIUM, "Web management interface is off",           rule_http_off),
    ("vty-acl",        MEDIUM, "Management access is limited by an ACL",    rule_vty_acl),
    ("idle-timeout",   MEDIUM, "Idle sessions time out",                    rule_idle_timeout),
    ("pw-encryption",  LOW,    "Passwords are obscured in the config",      rule_password_encryption),
    ("banner",         LOW,    "Login banner is present",                   rule_banner),
    ("syslog",         LOW,    "Logs are sent to a central server",         rule_syslog),
    ("ntp",            LOW,    "Clock is synchronised with NTP",            rule_ntp),
    ("snmp",           LOW,    "No SNMP v1/v2c community strings",          rule_snmp),
]


# --------------------------------------------------------------------------
# Finding the snapshot
# --------------------------------------------------------------------------
def all_runs():
    return sorted(p for p in Path("runs").glob("*") if p.is_dir()) if Path("runs").is_dir() else []


def resolve_run(value):
    if value:
        if Path(value).is_dir():
            return Path(value)
        matches = [p for p in all_runs() if p.name.endswith("_" + value)]
        if not matches:
            sys.exit("No snapshot folder or label called '%s'." % value)
        return matches[-1]
    with_config = [p for p in all_runs() if any(p.glob("*/" + CONFIG_FILE))]
    if not with_config:
        sys.exit("No snapshot contains 'show running-config'. Add it to commands.yml and run collect.py again.")
    return with_config[-1]


def device_order(run_dir):
    names = sorted(p.name for p in run_dir.iterdir() if p.is_dir())
    summary = run_dir / "summary.json"
    if summary.exists():
        listed = [d["name"] for d in json.loads(summary.read_text(encoding="utf-8")).get("devices", [])]
        names = [n for n in listed if n in names] + [n for n in names if n not in listed]
    return names


# --------------------------------------------------------------------------
# Running the audit
# --------------------------------------------------------------------------
def audit(run_dir):
    devices, skipped = [], []
    for name in device_order(run_dir):
        path = run_dir / name / CONFIG_FILE
        if not path.exists():
            skipped.append(name)
            continue
        cfg = Config(path.read_text(encoding="utf-8"))
        results = []
        for rule_id, level, title, check in RULES:
            passed, evidence = check(cfg)
            results.append({"id": rule_id, "severity": level, "title": title, "passed": passed, "evidence": evidence})
        devices.append({"name": name, "passed": sum(1 for r in results if r["passed"]), "total": len(results), "results": results})
    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "snapshot": run_dir.name,
        "devices": devices,
        "not_audited": skipped,
        "failed": {level: sum(1 for d in devices for r in d["results"] if not r["passed"] and r["severity"] == level)
                   for level in (HIGH, MEDIUM, LOW)},
    }


def print_result(result, verbose):
    devices = result["devices"]
    print("\nSecurity audit of snapshot %s  (%d devices, %d checks each)\n" % (result["snapshot"], len(devices), len(RULES)))
    print("  %-7s %-9s %-42s %s" % ("Result", "Severity", "Check", "Failing devices"))
    for index, (_rule_id, level, title, _check) in enumerate(RULES):
        failing = [d["name"] for d in devices if not d["results"][index]["passed"]]
        where = "-" if not failing else "all %d" % len(devices) if len(failing) == len(devices) else ", ".join(failing)
        print("  %-7s %-9s %-42s %s" % ("FAIL" if failing else "PASS", level, title, where))

    print("\n  %-7s %-7s %-6s %-8s %s" % ("Device", "Score", "High", "Medium", "Low"))
    for d in devices:
        failed = {level: sum(1 for r in d["results"] if not r["passed"] and r["severity"] == level) for level in (HIGH, MEDIUM, LOW)}
        print("  %-7s %-7s %-6d %-8d %d" % (d["name"], "%d/%d" % (d["passed"], d["total"]), failed[HIGH], failed[MEDIUM], failed[LOW]))

    if verbose:
        for d in devices:
            problems = [r for r in d["results"] if not r["passed"]]
            if problems:
                print("\n%s" % d["name"])
                for r in problems:
                    print("  [%s] %s" % (r["severity"], r["title"]))
                    print("         %s" % r["evidence"])
    if result["not_audited"]:
        print("\nNot audited (no running-config in the snapshot): %s" % ", ".join(result["not_audited"]))
    f = result["failed"]
    print("\nFailed checks: %d high, %d medium, %d low" % (f[HIGH], f[MEDIUM], f[LOW]))
    if not verbose and sum(f.values()):
        print("Add --verbose to see the evidence for each failure.")


def main():
    parser = argparse.ArgumentParser(description="Check saved device configurations against hardening rules.")
    parser.add_argument("snapshot", nargs="?", help="snapshot folder or label (default: most recent with a running-config)")
    parser.add_argument("--verbose", action="store_true", help="show the evidence for every failed check")
    parser.add_argument("--out", default="reports", help="folder for the JSON result (default: reports)")
    args = parser.parse_args()

    run_dir = resolve_run(args.snapshot)
    result = audit(run_dir)
    if not result["devices"]:
        sys.exit("Snapshot %s has no 'show running-config' output. Add it to commands.yml and run collect.py again." % run_dir.name)
    print_result(result, args.verbose)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / ("audit_%s.json" % result["snapshot"])
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("Saved: %s" % out_file)

    if result["failed"][HIGH]:
        sys.exit(1)


if __name__ == "__main__":
    main()
