#!/usr/bin/env python3
"""
compare.py - NetCheck change validation.

Compares two snapshots taken by collect.py (one before a change, one after),
reports exactly what is different, and gives every device a verdict:

    PASS   nothing that was working has been lost
    WARN   something changed and a person should look at it
    FAIL   something that was working before is missing or down now

    python compare.py                      compare the two most recent snapshots
    python compare.py pre post             compare the latest snapshots with those labels
    python compare.py runs\\A runs\\B        compare two specific snapshot folders
    python compare.py pre post --open      open the HTML report when done
    python compare.py --verbose            also list harmless (INFO) differences

It reads only the saved snapshot files. It never connects to a device.
Each comparison writes an HTML report and a JSON file to the reports folder.
The exit code is 1 if any device failed, so it can gate a change in a pipeline.
"""

import argparse
import html
import json
import re
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

from ntc_templates.parse import parse_output

FAIL, WARN, INFO, PASS = "FAIL", "WARN", "INFO", "PASS"
RANK = {PASS: 0, INFO: 0, WARN: 1, FAIL: 2}

# Check name -> (title shown in the report, command whose output feeds it)
CHECKS = {
    "interfaces":   ("Interface state",     "show ip interface brief"),
    "ospf":         ("OSPF neighbors",      "show ip ospf neighbor"),
    "routes":       ("Routing table",       "show ip route"),
    "cdp":          ("CDP neighbors",       "show cdp neighbors"),
    "vlans":        ("VLANs",               "show vlan brief"),
    "trunks":       ("Trunks",              "show interfaces trunk"),
    "switchports":  ("Switch ports",        "show interfaces status"),
    "stp_root":     ("Spanning-tree root",  "show spanning-tree"),
    "stp_ports":    ("Spanning-tree ports", "show spanning-tree"),
    "etherchannel": ("EtherChannel",        "show etherchannel summary"),
    "hsrp":         ("HSRP",                "show standby brief"),
}


def slug(command):
    return re.sub(r"[^a-z0-9]+", "_", command.lower()).strip("_")


def rows(command, raw):
    """Turn raw command output into a list of dictionaries using ntc-templates."""
    try:
        return parse_output(platform="cisco_ios", command=command, data=raw) or []
    except Exception:
        return []


# --------------------------------------------------------------------------
# Parsers: each one turns raw output into {item: value}. Values deliberately
# leave out anything that changes by itself (timers, ages, counters), so two
# snapshots of an untouched network compare as identical.
# --------------------------------------------------------------------------
def parse_interfaces(raw):
    return {r["interface"]: "%s/%s" % (r["status"], r["proto"]) for r in rows("show ip interface brief", raw)}


def parse_ospf(raw):
    return {
        "%s on %s" % (r["neighbor_id"], r["interface"]): r["state"].split("/")[0].strip()
        for r in rows("show ip ospf neighbor", raw)
    }


def parse_routes(raw):
    routes = {}
    for r in rows("show ip route", raw):
        prefix = "%s/%s" % (r["network"], r["prefix_length"])
        code = (r["protocol"] + " " + r["type"]).strip()
        hop = r["nexthop_ip"] or r["nexthop_if"] or "directly connected"
        routes.setdefault((prefix, code), set()).add(hop)
    return {
        "%s (%s)" % (prefix, code): "via " + ", ".join(sorted(hops))
        for (prefix, code), hops in routes.items()
    }


def parse_cdp(raw):
    return {
        "%s on %s" % (r["neighbor_name"], r["local_interface"]): re.sub(r"^Uni\s+", "", r["neighbor_interface"])
        for r in rows("show cdp neighbors", raw)
    }


def parse_vlans(raw):
    return {
        "VLAN %s" % r["vlan_id"]: "%s, %s" % (r["vlan_name"], r["status"])
        for r in rows("show vlan brief", raw)
        if not 1002 <= int(r["vlan_id"]) <= 1005
    }


def parse_trunks(raw):
    """ntc-templates returns nothing for this output on IOL, so parse it here."""
    trunks, section = {}, None
    for line in raw.splitlines():
        if line.startswith("Port"):
            if "Mode" in line:
                section = "status"
            elif "allowed on trunk" in line:
                section = "allowed"
            else:
                section = "other"
            continue
        parts = line.split()
        if not parts or section is None:
            continue
        trunk = trunks.setdefault(parts[0], {"status": "?", "native": "?", "allowed": "?"})
        if section == "status" and len(parts) >= 5:
            trunk["status"], trunk["native"] = parts[3], parts[4]
        elif section == "allowed":
            trunk["allowed"] = "".join(parts[1:]) or "none"
    return {
        port: "%s, native VLAN %s, allowed %s" % (t["status"], t["native"], t["allowed"])
        for port, t in trunks.items()
    }


def parse_switchports(raw):
    return {r["port"]: "%s, VLAN %s" % (r["status"], r["vlan_id"]) for r in rows("show interfaces status", raw)}


def parse_stp_root(raw):
    """The template lists ports but not the root bridge, so read that here."""
    roots = {}
    for block in re.split(r"^(?=VLAN\d+)", raw, flags=re.M):
        vlan = re.match(r"VLAN0*(\d+)", block)
        root = re.search(r"Root ID\s+Priority\s+(\d+)\s+Address\s+(\S+)", block)
        if vlan and root:
            mine = " (this switch)" if "This bridge is the root" in block else ""
            roots["VLAN %s" % vlan.group(1)] = "%s, priority %s%s" % (root.group(2), root.group(1), mine)
    return roots


def parse_stp_ports(raw):
    return {
        "VLAN %s %s" % (r["vlan_id"], r["interface"]): "%s %s" % (r["role"], r["status"])
        for r in rows("show spanning-tree", raw)
    }


def parse_etherchannel(raw):
    result = {}
    for r in rows("show etherchannel summary", raw):
        members = " ".join("%s(%s)" % pair for pair in zip(r["member_interface"], r["member_interface_status"], strict=False))
        result[r["bundle_name"]] = "%s %s: %s" % (r["bundle_status"], r["bundle_protocol"], members or "no members")
    return result


def parse_hsrp(raw):
    return {
        "%s group %s" % (r["interface"], r["group"]): "%s (active %s, standby %s)" % (r["state"], r["active"], r["standby"])
        for r in rows("show standby brief", raw)
    }


PARSERS = {
    "interfaces": parse_interfaces, "ospf": parse_ospf, "routes": parse_routes, "cdp": parse_cdp,
    "vlans": parse_vlans, "trunks": parse_trunks, "switchports": parse_switchports,
    "stp_root": parse_stp_root, "stp_ports": parse_stp_ports, "etherchannel": parse_etherchannel,
    "hsrp": parse_hsrp,
}


def parse_system(raw):
    found = rows("show version", raw)
    if not found:
        return None
    r = found[0]

    def number(key):
        return int(r.get(key) or 0)

    minutes = (number("uptime_years") * 525600 + number("uptime_weeks") * 10080 + number("uptime_days") * 1440
               + number("uptime_hours") * 60 + number("uptime_minutes"))
    return {"version": r.get("version", "?"), "uptime_minutes": minutes, "uptime": r.get("uptime", "?")}


# --------------------------------------------------------------------------
# Severity rules: how serious is each kind of difference?
# kind is "removed" (was there, now gone), "added" (new) or "changed".
# --------------------------------------------------------------------------
def severity(check, kind, before, after):
    if kind == "added":
        return INFO
    if check == "interfaces":
        if kind == "removed":
            return FAIL
        if before == "up/up" and after != "up/up":
            return FAIL
        return INFO if after == "up/up" else WARN
    if check == "ospf":
        if kind == "removed":
            return FAIL
        return INFO if after == "FULL" else FAIL
    if check == "switchports":
        if kind == "removed":
            return FAIL
        return FAIL if before.startswith("connected") and not after.startswith("connected") else WARN
    if check == "hsrp":
        if kind == "removed":
            return FAIL
        return WARN if after.split(" ")[0] in ("Active", "Standby") else FAIL
    if check == "stp_ports":
        return WARN
    if check in ("etherchannel", "stp_root"):
        return FAIL
    # routes, cdp, vlans, trunks
    return FAIL if kind == "removed" else WARN


# --------------------------------------------------------------------------
# Loading snapshots
# --------------------------------------------------------------------------
def load_snapshot(run_dir):
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        sys.exit("Snapshot folder not found: %s" % run_dir)
    summary = {}
    if (run_dir / "summary.json").exists():
        summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    status = {d["name"]: d for d in summary.get("devices", [])}

    devices = {}
    names = sorted(set(status) | {p.name for p in run_dir.iterdir() if p.is_dir()})
    for name in names:
        device_dir = run_dir / name
        state = {"reachable": device_dir.is_dir() and status.get(name, {}).get("status") != "failed",
                 "error": status.get(name, {}).get("error"), "checks": {}, "system": None}
        if state["reachable"]:
            for check, (_title, command) in CHECKS.items():
                path = device_dir / (slug(command) + ".txt")
                if path.exists():
                    state["checks"][check] = PARSERS[check](path.read_text(encoding="utf-8"))
            version = device_dir / "show_version.txt"
            if version.exists():
                state["system"] = parse_system(version.read_text(encoding="utf-8"))
        devices[name] = state
    order = [d["name"] for d in summary.get("devices", [])]
    ordered = [n for n in order if n in devices] + [n for n in names if n not in order]
    return {"path": run_dir, "name": run_dir.name, "label": summary.get("label", run_dir.name),
            "finished": summary.get("finished", ""), "devices": devices, "order": ordered}


def resolve_run(value):
    """Accept a snapshot folder, or a label such as 'pre' (the newest snapshot with that label)."""
    if Path(value).is_dir():
        return Path(value)
    runs = sorted(p for p in Path("runs").glob("*_" + value) if p.is_dir()) if Path("runs").is_dir() else []
    if not runs:
        available = sorted(p.name for p in Path("runs").glob("*") if p.is_dir()) if Path("runs").is_dir() else []
        sys.exit("No snapshot folder or label called '%s'. Available snapshots:\n  %s" % (value, "\n  ".join(available) or "(none)"))
    return runs[-1]


def latest_two_runs():
    runs = sorted(p for p in Path("runs").glob("*") if p.is_dir()) if Path("runs").is_dir() else []
    if len(runs) < 2:
        sys.exit("Need at least two snapshots in the runs folder. Take them with collect.py first.")
    return runs[-2], runs[-1]


# --------------------------------------------------------------------------
# Comparing
# --------------------------------------------------------------------------
def compare_device(name, pre, post):
    findings, compared = [], 0

    def add(level, check_title, item, before, after, note):
        findings.append({"device": name, "severity": level, "check": check_title, "item": item,
                         "before": before, "after": after, "note": note})

    if pre is None or not pre["reachable"]:
        add(WARN, "Reachability", name, "not collected", "collected" if post and post["reachable"] else "not collected",
            "No usable 'before' data for this device, so it could not be compared.")
        return findings, compared
    if post is None or not post["reachable"]:
        reason = (post or {}).get("error") or "no data collected"
        add(FAIL, "Reachability", name, "reachable", "unreachable", "Could not be collected after the change: %s" % reason)
        return findings, compared

    if pre["system"] and post["system"]:
        compared += 2
        if pre["system"]["version"] != post["system"]["version"]:
            add(WARN, "System", "Software version", pre["system"]["version"], post["system"]["version"],
                "The software version changed.")
        if post["system"]["uptime_minutes"] < pre["system"]["uptime_minutes"]:
            add(WARN, "System", "Uptime", pre["system"]["uptime"], post["system"]["uptime"],
                "The device restarted between the two snapshots.")

    for check, (title, command) in CHECKS.items():
        if check not in pre["checks"]:
            continue
        before_items = pre["checks"][check]
        if check not in post["checks"]:
            add(FAIL, title, command, "collected", "missing", "This command's output is missing from the 'after' snapshot.")
            continue
        after_items = post["checks"][check]
        compared += len(before_items)
        for item in sorted(set(before_items) | set(after_items)):
            before, after = before_items.get(item), after_items.get(item)
            if before == after:
                continue
            if after is None:
                kind, note = "removed", "Present before the change, missing after it."
            elif before is None:
                kind, note = "added", "New after the change."
            else:
                kind, note = "changed", "Value changed."
            add(severity(check, kind, before, after), title, item, before or "-", after or "-", note)
    return findings, compared


def compare(pre, post):
    names = pre["order"] + [n for n in post["order"] if n not in pre["order"]]
    devices, all_findings, total = [], [], 0
    for name in names:
        findings, compared = compare_device(name, pre["devices"].get(name), post["devices"].get(name))
        total += compared
        counts = {level: sum(1 for f in findings if f["severity"] == level) for level in (FAIL, WARN, INFO)}
        verdict = FAIL if counts[FAIL] else WARN if counts[WARN] else PASS
        devices.append({"name": name, "verdict": verdict, "counts": counts, "compared": compared, "findings": findings})
        all_findings.extend(findings)
    overall = max((d["verdict"] for d in devices), key=lambda v: RANK[v], default=PASS)
    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "before": {"snapshot": pre["name"], "label": pre["label"], "finished": pre["finished"]},
        "after": {"snapshot": post["name"], "label": post["label"], "finished": post["finished"]},
        "verdict": overall,
        "items_compared": total,
        "counts": {level: sum(1 for f in all_findings if f["severity"] == level) for level in (FAIL, WARN, INFO)},
        "devices": devices,
    }


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def print_result(result, verbose):
    print("")
    print("Before: %s" % result["before"]["snapshot"])
    print("After:  %s" % result["after"]["snapshot"])
    print("")
    print("  %-7s %-8s %-6s %-6s %-6s %s" % ("Device", "Verdict", "Fail", "Warn", "Info", "Items compared"))
    for d in result["devices"]:
        print("  %-7s %-8s %-6d %-6d %-6d %d" % (
            d["name"], d["verdict"], d["counts"][FAIL], d["counts"][WARN], d["counts"][INFO], d["compared"]))
    shown = [FAIL, WARN, INFO] if verbose else [FAIL, WARN]
    for d in result["devices"]:
        lines = [f for f in d["findings"] if f["severity"] in shown]
        if not lines:
            continue
        print("\n%s" % d["name"])
        for f in sorted(lines, key=lambda f: [FAIL, WARN, INFO].index(f["severity"])):
            print("  [%s] %s: %s" % (f["severity"], f["check"], f["item"]))
            print("         before: %s" % f["before"])
            print("         after:  %s" % f["after"])
            if f["check"] == "Reachability":
                print("         note:   %s" % f["note"])
    c = result["counts"]
    print("\nOverall: %s  (%d fail, %d warn, %d info across %d items compared)" % (
        result["verdict"], c[FAIL], c[WARN], c[INFO], result["items_compared"]))
    if c[INFO] and not verbose:
        print("Add --verbose to list the %d INFO difference(s)." % c[INFO])


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5f6b7a;--line:#dfe3e8;
--fail:#b42318;--failbg:#fde7e4;--warn:#8a5a00;--warnbg:#fdf0cf;--info:#175cd3;--infobg:#e3edfd;--pass:#0b6e3a;--passbg:#dcf5e6}
@media (prefers-color-scheme:dark){:root{--bg:#12151a;--card:#1b2027;--text:#e8ecf1;--muted:#9aa6b5;--line:#2c333d;
--fail:#ff8a7a;--failbg:#44201c;--warn:#f2c661;--warnbg:#3f3212;--info:#8fb8ff;--infobg:#1b2c4a;--pass:#6fdc9f;--passbg:#153524}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:28px 16px 60px}h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:0}
.sub{color:var(--muted);margin:0 0 20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:0 0 20px}
.tile,.card{background:var(--card);border:1px solid var(--line);border-radius:10px}.tile{padding:14px 16px}
.tile b{display:block;font-size:26px;line-height:1.2}.tile span{color:var(--muted);font-size:13px}
.card{margin:0 0 16px;overflow:hidden}.head{display:flex;gap:10px;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line)}
.head .meta{margin-left:auto;color:var(--muted);font-size:13px}.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:9px 16px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}tr:last-child td{border-bottom:0}
td.v{font-family:ui-monospace,Consolas,monospace;font-size:13px;word-break:break-word}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.03em}
.FAIL{color:var(--fail);background:var(--failbg)}.WARN{color:var(--warn);background:var(--warnbg)}
.INFO{color:var(--info);background:var(--infobg)}.PASS{color:var(--pass);background:var(--passbg)}
.banner{padding:16px 18px;border-radius:10px;margin:0 0 20px;font-weight:600;font-size:17px}.ok{padding:14px 16px;color:var(--muted)}
a{color:var(--info)}.note{display:block;color:var(--muted);font-family:system-ui,Segoe UI,Roboto,sans-serif;margin-top:3px}
footer{color:var(--muted);font-size:13px;margin-top:24px}
"""

VERDICT_TEXT = {
    PASS: "PASS: nothing that was working before the change has been lost.",
    WARN: "WARN: nothing was lost, but some things changed and need a look.",
    FAIL: "FAIL: something that was working before the change is missing or down.",
}


def write_html(result, path):
    e = html.escape
    c = result["counts"]
    failed = sum(1 for d in result["devices"] if d["verdict"] == FAIL)
    out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           "<title>NetCheck change report</title><style>%s</style></head><body><main>" % CSS,
           "<h1>NetCheck change report</h1>",
           "<p class='sub'>Before: <b>%s</b> &nbsp;&rarr;&nbsp; After: <b>%s</b></p>" % (
               e(result["before"]["snapshot"]), e(result["after"]["snapshot"])),
           "<div class='banner %s'>%s</div>" % (result["verdict"], e(VERDICT_TEXT[result["verdict"]])),
           "<div class='grid'>"]
    for value, label in ((len(result["devices"]), "devices checked"), (failed, "devices failed"), (c[FAIL], "failures"),
                         (c[WARN], "warnings"), (c[INFO], "info"), (result["items_compared"], "items compared")):
        out.append("<div class='tile'><b>%s</b><span>%s</span></div>" % (value, label))
    out.append("</div>")

    out.append("<div class='card'><div class='head'><h2>Devices</h2></div><div class='scroll'><table>"
               "<tr><th>Device</th><th>Verdict</th><th>Fail</th><th>Warn</th><th>Info</th><th>Items compared</th></tr>")
    for d in result["devices"]:
        out.append("<tr><td><a href='#%s'>%s</a></td><td><span class='pill %s'>%s</span></td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>" % (
            e(d["name"]), e(d["name"]), d["verdict"], d["verdict"], d["counts"][FAIL], d["counts"][WARN], d["counts"][INFO], d["compared"]))
    out.append("</table></div></div>")

    order = {FAIL: 0, WARN: 1, INFO: 2}
    for d in result["devices"]:
        out.append("<div class='card' id='%s'><div class='head'><h2>%s</h2><span class='pill %s'>%s</span>"
                   "<span class='meta'>%d items compared</span></div>" % (e(d["name"]), e(d["name"]), d["verdict"], d["verdict"], d["compared"]))
        if not d["findings"]:
            out.append("<div class='ok'>No differences.</div></div>")
            continue
        out.append("<div class='scroll'><table><tr><th>Severity</th><th>Check</th><th>Item</th><th>Before</th><th>After</th></tr>")
        for f in sorted(d["findings"], key=lambda f: order[f["severity"]]):
            note = "<span class='note'>%s</span>" % e(f["note"]) if f["check"] in ("Reachability", "System") else ""
            out.append("<tr><td><span class='pill %s'>%s</span></td><td>%s</td><td class='v'>%s</td><td class='v'>%s</td><td class='v'>%s%s</td></tr>" % (
                f["severity"], f["severity"], e(f["check"]), e(f["item"]), e(str(f["before"])), e(str(f["after"])), note))
        out.append("</table></div></div>")
    out.append("<footer>Generated %s by NetCheck. Compared from saved read-only snapshots; no device was contacted.</footer>" % e(result["generated"]))
    out.append("</main></body></html>")
    path.write_text("\n".join(out), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Compare a 'before' and an 'after' snapshot and report what changed.")
    parser.add_argument("before", nargs="?", help="snapshot folder or label taken before the change")
    parser.add_argument("after", nargs="?", help="snapshot folder or label taken after the change")
    parser.add_argument("--open", action="store_true", help="open the HTML report in the browser")
    parser.add_argument("--verbose", action="store_true", help="also list INFO differences on screen")
    parser.add_argument("--out", default="reports", help="folder for the HTML and JSON report (default: reports)")
    args = parser.parse_args()

    if args.before and args.after:
        before_dir, after_dir = resolve_run(args.before), resolve_run(args.after)
    elif args.before or args.after:
        sys.exit("Give both snapshot folders, or neither to compare the two most recent.")
    else:
        before_dir, after_dir = latest_two_runs()

    result = compare(load_snapshot(before_dir), load_snapshot(after_dir))
    print_result(result, args.verbose)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = "%s__vs__%s" % (result["before"]["snapshot"], result["after"]["snapshot"])
    write_html(result, out_dir / (base + ".html"))
    (out_dir / (base + ".json")).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("Report: %s" % (out_dir / (base + ".html")))
    if args.open:
        webbrowser.open((out_dir / (base + ".html")).resolve().as_uri())

    if result["verdict"] == FAIL:
        sys.exit(1)


if __name__ == "__main__":
    main()
