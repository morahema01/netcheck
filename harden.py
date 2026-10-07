#!/usr/bin/env python3
"""
harden.py - NetCheck remediation.

Pushes a small, reviewed set of hardening lines (hardening.yml) to every
device to close the gaps that audit.py reports. This is the only NetCheck
script that changes device configuration, so it is deliberately cautious:

  * It does nothing unless you add --apply. Without it you get a dry run
    that prints exactly which lines would go to which device.
  * After pushing, it opens a second login to the device before saving. If
    that login fails (for example an access list locked us out), it pushes
    the rollback lines through the session that is still open and saves
    nothing, so a reboot would bring the old configuration back in full.
  * A failure on one device never stops the others.

    python harden.py                     dry run: show the plan, change nothing
    python harden.py --only R1 --apply   apply to one device first
    python harden.py --apply             apply to every device

Recommended order: collect.py --label pre-harden, harden.py --apply,
collect.py --label post-harden, then compare.py and audit.py to prove the
change fixed the findings and broke nothing.
"""

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException

from collect import IOS_ERRORS, get_credentials, load_devices, load_yaml, short_error, warn_if_legacy_ssh_unsupported

# Commands that must never be pushed by this tool.
FORBIDDEN = ("reload", "erase", "delete", "format", "write erase", "no username", "crypto key zeroize")


def lines_for(device, plan):
    """Common lines, then the lines for this role, then the lines for this device."""
    lines = list(plan.get("common") or [])
    lines += (plan.get("by_role") or {}).get(device["role"], [])
    lines += (plan.get("by_device") or {}).get(device["name"], [])
    return lines


def connect(device, username, password, timeout):
    return ConnectHandler(
        device_type=device.get("platform", "cisco_ios"),
        host=device["mgmt_ip"],
        port=device.get("port", 22),
        username=username,
        password=password,
        secret=password,
        conn_timeout=timeout,
    )


def harden_device(device, lines, rollback, username, password, timeout):
    result = {"name": device["name"], "host": device["mgmt_ip"], "status": "FAILED", "lines": len(lines), "note": ""}
    started = time.perf_counter()
    try:
        with connect(device, username, password, timeout) as conn:
            if not conn.check_enable_mode():
                conn.enable()
            output = conn.send_config_set(lines)
            rejected = [marker for marker in IOS_ERRORS if marker in output]
            if rejected:
                if rollback:
                    conn.send_config_set(rollback)
                result["status"] = "ROLLED BACK"
                result["note"] = "the device rejected a line (%s); rollback lines pushed, nothing saved" % rejected[0]
                return result

            # Safety net: prove we can still log in before making the change permanent.
            try:
                with connect(device, username, password, timeout):
                    pass
            except Exception as err:
                if rollback:
                    conn.send_config_set(rollback)
                result["status"] = "ROLLED BACK"
                result["note"] = "a new login failed after the change (%s); rollback lines pushed, nothing saved" % short_error(err)
                return result

            conn.save_config()
            result["status"] = "APPLIED"
            result["note"] = "new login verified, configuration saved"
    except NetmikoAuthenticationException:
        result["note"] = "authentication failed"
    except Exception as err:
        result["note"] = short_error(err)
    finally:
        result["seconds"] = round(time.perf_counter() - started, 2)
    return result


def main():
    parser = argparse.ArgumentParser(description="Push reviewed hardening lines to every device, with a lockout safety net.")
    parser.add_argument("--inventory", default="inventory.yml", help="device list (default: inventory.yml)")
    parser.add_argument("--plan", default="hardening.yml", help="hardening lines (default: hardening.yml)")
    parser.add_argument("--only", help="comma-separated device names or roles, for example R1,core")
    parser.add_argument("--apply", action="store_true", help="actually change the devices (default is a dry run)")
    parser.add_argument("--workers", type=int, default=4, help="devices to change at once (default: 4)")
    parser.add_argument("--timeout", type=int, default=15, help="seconds to wait for a connection (default: 15)")
    args = parser.parse_args()

    devices = load_devices(args.inventory, args.only)
    plan = load_yaml(args.plan)
    rollback = list(plan.get("rollback") or [])
    per_device = {d["name"]: lines_for(d, plan) for d in devices}

    unsafe = sorted({line for lines in per_device.values() for line in lines
                     if any(line.strip().lower().startswith(word) for word in FORBIDDEN)})
    if unsafe:
        sys.exit("Refusing to run. The plan contains destructive commands: %s" % "; ".join(unsafe))

    if not args.apply:
        for d in devices:
            print("%s (%s, %s)" % (d["name"], d["role"], d["mgmt_ip"]))
            for line in per_device[d["name"]]:
                print("    " + line)
        if rollback:
            print("\nIf a new login fails after the change, these lines undo it:")
            for line in rollback:
                print("    " + line)
        print("\nDry run only. Nothing was connected to. Add --apply to make the change.")
        return

    warn_if_legacy_ssh_unsupported()
    username, password = get_credentials()
    workers = max(1, min(args.workers, len(devices)))
    print("Applying hardening to %d device(s) with %d worker(s)..." % (len(devices), workers))

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(harden_device, d, per_device[d["name"]], rollback, username, password, args.timeout): d
                   for d in devices}
        for future in as_completed(futures):
            results.append(future.result())
    order = {d["name"]: i for i, d in enumerate(devices)}
    results.sort(key=lambda r: order[r["name"]])

    print("")
    print("  %-7s %-16s %-12s %-6s %-8s %s" % ("Device", "Address", "Status", "Lines", "Seconds", "Note"))
    for r in results:
        print("  %-7s %-16s %-12s %-6d %-8s %s" % (r["name"], r["host"], r["status"], r["lines"], r["seconds"], r["note"]))
    applied = sum(1 for r in results if r["status"] == "APPLIED")
    print("\n%d applied, %d not applied" % (applied, len(results) - applied))
    if applied != len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
