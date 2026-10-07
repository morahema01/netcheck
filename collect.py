#!/usr/bin/env python3
"""
collect.py - NetCheck collector.

Connects to every device in the inventory at the same time, runs a standard
set of read-only "show" commands, and saves the output as a dated snapshot.
It never changes device configuration.

    python collect.py --dry-run             show what would run, connect to nothing
    python collect.py --only R1             test against one device first
    python collect.py --label pre           take a snapshot before a change
    python collect.py --label post          take a snapshot after the change

Credentials are read from the NETCHECK_USER and NETCHECK_PASSWORD environment
variables. If they are not set, the script asks for them. They are never
written to disk.

Each run creates  runs/<date>_<time>_<label>/  containing:
    <device>/<command>.txt    raw output, one file per command
                              (configurations are saved with secrets redacted)
    summary.json              status, timings and retries for every device
    failed_devices.txt        device names to rerun (only if something failed)
    bundle.txt                all output in one file, handy for sharing
"""

import argparse
import getpass
import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import paramiko
import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException

# Paramiko prints a full traceback for every failed connection. The status
# table already reports failures, so keep the screen readable.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

# Text IOS prints when it does not accept a command.
IOS_ERRORS = ("% Invalid input", "% Incomplete command", "% Ambiguous command", "% Unknown command")


# Passwords, hashes, keys and SNMP communities in a saved configuration.
SECRET_RE = re.compile(r"\b(secret|password|key-string|authentication-key|community|md5)((?: \d{1,2})?) (\S+)")
# A bare "key" (TACACS, RADIUS). Skips "key chain NAME" and key numbers such as "key 1".
KEY_RE = re.compile(r"(?<![\w-])(key)((?: \d{1,2})?) (?!chain\b)(?!\d+\s*$)(\S+)", re.M)


def redact(text):
    """Replace secrets with <redacted> so snapshots are safe to keep and share."""
    for pattern in (SECRET_RE, KEY_RE):
        text = pattern.sub(lambda m: "%s%s <redacted>" % (m.group(1), m.group(2)), text)
    return text


def slug(command):
    """'show ip ospf neighbor' -> 'show_ip_ospf_neighbor' (safe as a file name)."""
    return re.sub(r"[^a-z0-9]+", "_", command.lower()).strip("_")


def load_yaml(path):
    path = Path(path)
    if not path.exists():
        sys.exit("File not found: %s" % path)
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_devices(path, only):
    devices = load_yaml(path).get("devices") or []
    if not devices:
        sys.exit("No devices found in %s" % path)
    if only:
        wanted = {item.strip().lower() for item in only.split(",") if item.strip()}
        devices = [d for d in devices if d["name"].lower() in wanted or d["role"].lower() in wanted]
        if not devices:
            sys.exit("--only %s matched no device name or role" % only)
    return devices


def commands_for(device, command_set):
    """Common commands plus the ones for this device's role, without duplicates."""
    commands = list(command_set.get("common") or [])
    for command in (command_set.get("by_role") or {}).get(device["role"], []):
        if command not in commands:
            commands.append(command)
    return commands


def short_error(err):
    """Netmiko errors span many lines; keep the useful part on one line."""
    lines = [line.strip() for line in str(err).splitlines() if line.strip()]
    text = " ".join(lines[:2]) or "no details"
    return "%s: %s" % (type(err).__name__, text[:160])


def warn_if_legacy_ssh_unsupported():
    """Paramiko 5 removed the SHA-1 key exchange that IOS 15.x still needs."""
    if int(paramiko.__version__.split(".")[0]) >= 5:
        print("Warning: Paramiko %s cannot connect to older IOS devices such as this lab's." % paramiko.__version__)
        print("         Install the pinned versions with:  python -m pip install -r requirements.txt\n")


def get_credentials():
    username = os.environ.get("NETCHECK_USER") or input("Username: ")
    password = os.environ.get("NETCHECK_PASSWORD") or getpass.getpass("Password: ")
    return username, password


def collect_device(device, commands, username, password, run_dir, retries, timeout):
    """Collect one device. A failure here never affects any other device."""
    result = {
        "name": device["name"],
        "host": device["mgmt_ip"],
        "role": device["role"],
        "status": "failed",
        "attempts": 0,
        "connect_seconds": None,
        "total_seconds": None,
        "error": None,
        "commands": [],
    }
    started = time.perf_counter()

    for attempt in range(1, retries + 2):
        result["attempts"] = attempt
        try:
            connect_started = time.perf_counter()
            with ConnectHandler(
                device_type=device.get("platform", "cisco_ios"),
                host=device["mgmt_ip"],
                port=device.get("port", 22),
                username=username,
                password=password,
                secret=password,
                conn_timeout=timeout,
            ) as conn:
                result["connect_seconds"] = round(time.perf_counter() - connect_started, 2)
                if not conn.check_enable_mode():
                    conn.enable()

                device_dir = run_dir / device["name"]
                device_dir.mkdir(parents=True, exist_ok=True)
                result["commands"] = []

                for command in commands:
                    entry = {"command": command, "file": None, "ok": False, "seconds": None, "error": None}
                    command_started = time.perf_counter()
                    # One bad command must not end the session for the rest.
                    try:
                        output = conn.send_command(command, read_timeout=60)
                        if "-config" in command:   # running-config or startup-config
                            output = redact(output)
                        file_name = slug(command) + ".txt"
                        (device_dir / file_name).write_text(output + "\n", encoding="utf-8")
                        entry["file"] = "%s/%s" % (device["name"], file_name)
                        if any(marker in output for marker in IOS_ERRORS):
                            entry["error"] = "device rejected the command"
                        else:
                            entry["ok"] = True
                    except Exception as err:
                        entry["error"] = short_error(err)
                    entry["seconds"] = round(time.perf_counter() - command_started, 2)
                    result["commands"].append(entry)

            failed = [c for c in result["commands"] if not c["ok"]]
            result["status"] = "partial" if failed else "ok"
            result["error"] = None
            break
        except NetmikoAuthenticationException:
            # Never retry a rejected login: repeated attempts can lock an account.
            result["error"] = "authentication failed"
            break
        except Exception as err:
            result["error"] = short_error(err)

    result["total_seconds"] = round(time.perf_counter() - started, 2)
    return result


def write_bundle(run_dir, results):
    lines = []
    for result in results:
        for entry in result["commands"]:
            if not entry["file"]:
                continue
            lines.append("=" * 78)
            lines.append("%s | %s" % (result["name"], entry["command"]))
            lines.append("=" * 78)
            lines.append((run_dir / entry["file"]).read_text(encoding="utf-8").rstrip())
            lines.append("")
    (run_dir / "bundle.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_table(results):
    print("")
    print("  %-7s %-16s %-8s %-9s %-9s %s" % ("Device", "Address", "Status", "Commands", "Seconds", "Note"))
    for r in results:
        ok = sum(1 for c in r["commands"] if c["ok"])
        note = r["error"] or ""
        if r["status"] == "partial":
            note = "rejected: " + ", ".join(c["command"] for c in r["commands"] if not c["ok"])
        if r["attempts"] > 1 and r["status"] != "failed":
            note = ("needed %d attempts. " % r["attempts"]) + note
        print("  %-7s %-16s %-8s %-9s %-9s %s" % (
            r["name"], r["host"], r["status"].upper(),
            "%d/%d" % (ok, len(r["commands"])) if r["commands"] else "-",
            r["total_seconds"], note,
        ))
    print("")


def main():
    parser = argparse.ArgumentParser(description="Collect read-only health data from every device in parallel.")
    parser.add_argument("--inventory", default="inventory.yml", help="device list (default: inventory.yml)")
    parser.add_argument("--commands", default="commands.yml", help="command list (default: commands.yml)")
    parser.add_argument("--label", default="snapshot", help="name for this run, for example pre or post")
    parser.add_argument("--only", help="comma-separated device names or roles, for example R1,core")
    parser.add_argument("--workers", type=int, default=8, help="devices to talk to at once (default: 8)")
    parser.add_argument("--retries", type=int, default=1, help="extra attempts if a device cannot be reached (default: 1)")
    parser.add_argument("--timeout", type=int, default=15, help="seconds to wait for a connection (default: 15)")
    parser.add_argument("--dry-run", action="store_true", help="list devices and commands, then stop")
    args = parser.parse_args()

    devices = load_devices(args.inventory, args.only)
    command_set = load_yaml(args.commands)
    plan = {d["name"]: commands_for(d, command_set) for d in devices}

    # Safety brake: this tool collects evidence, it does not change anything.
    unsafe = sorted({c for cmds in plan.values() for c in cmds if not c.strip().lower().startswith("show ")})
    if unsafe:
        sys.exit("Refusing to run. Only 'show' commands are allowed, but found: %s" % "; ".join(unsafe))

    if args.dry_run:
        for d in devices:
            print("%s (%s, %s)" % (d["name"], d["role"], d["mgmt_ip"]))
            for command in plan[d["name"]]:
                print("    " + command)
        print("\nDry run only. Nothing was connected to.")
        return

    warn_if_legacy_ssh_unsupported()
    username, password = get_credentials()
    label = re.sub(r"[^A-Za-z0-9_-]+", "-", args.label)
    run_dir = Path("runs") / ("%s_%s" % (datetime.now().strftime("%Y%m%d_%H%M%S"), label))
    run_dir.mkdir(parents=True, exist_ok=True)

    workers = max(1, min(args.workers, len(devices)))
    print("Collecting from %d device(s) with %d worker(s)..." % (len(devices), workers))
    started = time.perf_counter()

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(collect_device, d, plan[d["name"]], username, password, run_dir, args.retries, args.timeout): d
            for d in devices
        }
        for future in as_completed(futures):
            device = futures[future]
            try:
                results.append(future.result())
            except Exception as err:  # safety net: a worker should never take the run down
                results.append({
                    "name": device["name"], "host": device["mgmt_ip"], "role": device["role"],
                    "status": "failed", "attempts": 1, "connect_seconds": None, "total_seconds": None,
                    "error": "unexpected error: %s" % err, "commands": [],
                })

    order = {d["name"]: i for i, d in enumerate(devices)}
    results.sort(key=lambda r: order[r["name"]])
    elapsed = round(time.perf_counter() - started, 2)

    not_ok = [r["name"] for r in results if r["status"] != "ok"]
    summary = {
        "label": label,
        "finished": datetime.now().isoformat(timespec="seconds"),
        "elapsed_seconds": elapsed,
        "device_count": len(results),
        "ok": sum(1 for r in results if r["status"] == "ok"),
        "partial": sum(1 for r in results if r["status"] == "partial"),
        "failed": sum(1 for r in results if r["status"] == "failed"),
        "devices": results,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if not_ok:
        (run_dir / "failed_devices.txt").write_text("\n".join(not_ok) + "\n", encoding="utf-8")
    write_bundle(run_dir, results)

    print_table(results)
    print("%d ok, %d partial, %d failed in %s seconds" % (summary["ok"], summary["partial"], summary["failed"], elapsed))
    print("Snapshot saved to: %s" % run_dir)
    if not_ok:
        print("Rerun just the problem devices with:  --only %s" % ",".join(not_ok))
        sys.exit(1)


if __name__ == "__main__":
    main()
