"""compare.py tested against real output captured from the lab (tests/fixtures/baseline)."""
import shutil
from pathlib import Path

import compare

BASELINE = Path(__file__).parent / "fixtures" / "baseline"


def make_snapshot(tmp_path, name, edits=None, remove=()):
    """Copy the baseline, then apply text edits: {(device, file): function}."""
    target = tmp_path / name
    shutil.copytree(BASELINE, target)
    for (device, file_name), change in (edits or {}).items():
        path = target / device / file_name
        path.write_text(change(path.read_text()))
    for device in remove:
        shutil.rmtree(target / device)
    return target


def run(tmp_path, **post_options):
    before = compare.load_snapshot(make_snapshot(tmp_path, "pre"))
    after = compare.load_snapshot(make_snapshot(tmp_path, "post", **post_options))
    return compare.compare(before, after)


def findings(result, device):
    return {(f["check"], f["item"]): f["severity"] for d in result["devices"] if d["name"] == device for f in d["findings"]}


def drop_lines(marker):
    return lambda text: "\n".join(line for line in text.splitlines() if marker not in line) + "\n"


def test_identical_snapshots_pass(tmp_path):
    result = run(tmp_path)
    assert result["verdict"] == "PASS"
    assert result["counts"] == {"FAIL": 0, "WARN": 0, "INFO": 0}
    assert result["items_compared"] > 150


def test_timers_and_ages_are_ignored(tmp_path):
    result = run(tmp_path, edits={
        ("CORE1", "show_ip_ospf_neighbor.txt"): lambda t: t.replace("00:00:30", "00:00:39"),
        ("CORE1", "show_ip_route.txt"): lambda t: t.replace("00:33:28", "01:12:05"),
        ("CORE1", "show_cdp_neighbors.txt"): lambda t: t.replace("141", "178"),
        ("CORE1", "show_version.txt"): lambda t: t.replace("33 minutes", "1 hour, 12 minutes"),
    })
    assert result["verdict"] == "PASS"


def test_interface_down_and_lost_ospf_neighbor_fail(tmp_path):
    result = run(tmp_path, edits={
        ("CORE1", "show_ip_interface_brief.txt"): lambda t: t.replace(
            "Ethernet0/0            10.0.0.2        YES TFTP   up                    up",
            "Ethernet0/0            10.0.0.2        YES TFTP   administratively down down"),
        ("CORE1", "show_ip_ospf_neighbor.txt"): drop_lines("10.255.0.1 "),
        ("R1", "show_ip_ospf_neighbor.txt"): drop_lines("10.255.0.11 "),
    })
    assert result["verdict"] == "FAIL"
    core1 = findings(result, "CORE1")
    assert core1[("Interface state", "Ethernet0/0")] == "FAIL"
    assert core1[("OSPF neighbors", "10.255.0.1 on Ethernet0/0")] == "FAIL"
    assert findings(result, "R1")[("OSPF neighbors", "10.255.0.11 on Ethernet0/0")] == "FAIL"
    assert findings(result, "DIST1") == {}


def test_lost_route_fails_and_lost_path_warns(tmp_path):
    result = run(tmp_path, edits={
        ("R1", "show_ip_route.txt"): lambda t: "\n".join(
            line for line in t.splitlines() if "10.255.0.11/32" not in line and "[110/21] via 10.0.0.2, 00:33:14" not in line) + "\n",
    })
    r1 = findings(result, "R1")
    assert r1[("Routing table", "10.255.0.11/32 (O)")] == "FAIL"
    assert r1[("Routing table", "10.10.10.0/24 (O)")] == "WARN"


def test_unreachable_device_fails(tmp_path):
    result = run(tmp_path, remove=["ACC1"])
    assert findings(result, "ACC1") == {("Reachability", "ACC1"): "FAIL"}


def test_restart_is_reported(tmp_path):
    result = run(tmp_path, edits={("ACC1", "show_version.txt"): lambda t: t.replace("33 minutes", "2 minutes")})
    assert findings(result, "ACC1") == {("System", "Uptime"): "WARN"}


def test_layer2_changes(tmp_path):
    result = run(tmp_path, edits={
        ("DIST1", "show_etherchannel_summary.txt"): lambda t: t.replace("Et0/3(P)", "Et0/3(s)"),
        ("DIST1", "show_standby_brief.txt"): lambda t: t.replace(
            "Vl10        10   110 P Active  local           10.10.10.3", "Vl10        10   110 P Standby 10.10.10.3      local     "),
        ("ACC1", "show_vlan_brief.txt"): drop_lines("20   SERVERS"),
        ("ACC1", "show_spanning_tree.txt"): lambda t: t.replace("Address     aabb.cc00.4000\n             Cost", "Address     aabb.cc00.9999\n             Cost"),
    })
    dist1, acc1 = findings(result, "DIST1"), findings(result, "ACC1")
    assert dist1[("EtherChannel", "Po1")] == "FAIL"
    assert dist1[("HSRP", "Vl10 group 10")] == "WARN"
    assert acc1[("VLANs", "VLAN 20")] == "FAIL"
    assert acc1[("Spanning-tree root", "VLAN 10")] == "FAIL"


def test_custom_parsers_on_real_output():
    dist1 = BASELINE / "DIST1"
    trunks = compare.parse_trunks((dist1 / "show_interfaces_trunk.txt").read_text())
    assert set(trunks) == {"Et1/0", "Et1/1", "Et1/2", "Po1"}
    assert trunks["Po1"] == "trunking, native VLAN 99, allowed 10,20"
    roots = compare.parse_stp_root((dist1 / "show_spanning_tree.txt").read_text())
    assert roots["VLAN 10"].endswith("(this switch)")
    assert "this switch" not in roots["VLAN 20"]


def test_template_parsers_on_real_output():
    dist1 = BASELINE / "DIST1"
    assert len(compare.parse_ospf((dist1 / "show_ip_ospf_neighbor.txt").read_text())) == 2
    assert compare.parse_etherchannel((dist1 / "show_etherchannel_summary.txt").read_text()) == {"Po1": "SU LACP: Et0/2(P) Et0/3(P)"}
    assert len(compare.parse_hsrp((dist1 / "show_standby_brief.txt").read_text())) == 2
    assert len(compare.parse_cdp((dist1 / "show_cdp_neighbors.txt").read_text())) == 7
