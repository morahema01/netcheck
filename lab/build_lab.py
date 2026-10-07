#!/usr/bin/env python3
"""
build_lab.py - builds the NetCheck lab for EVE-NG as code.

It generates one .unl lab file (8 Cisco IOL nodes, all links, and a startup
config for every node), plus readable copies of each config and an inventory
file for the automation tool that comes next.

Run it on the EVE-NG server as root:

    python3 build_lab.py               build the lab into /opt/unetlab/labs
    python3 build_lab.py --force       overwrite an existing lab file
    python3 build_lab.py --enable-ssh  after the nodes boot: generate SSH keys, save, verify
    python3 build_lab.py --verify      check ping and SSH on every device

SSH keys cannot be created from a startup config on these IOL images (the
command is ignored at boot), so --enable-ssh does it once through each node's
console port and then saves the configuration.

Lab credentials default to admin / Lab-Admin-123. To choose your own, set
LAB_USER and LAB_PASSWORD in the shell before building. Lab use only.
"""

import argparse
import base64
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from xml.sax.saxutils import escape

# --------------------------------------------------------------------------
# Settings you may want to change
# --------------------------------------------------------------------------
LAB_NAME = "NetCheck-Lab"
LABS_DIR = Path("/opt/unetlab/labs")
IOL_DIR = Path("/opt/unetlab/addons/iol/bin")
ICON_DIR = Path("/opt/unetlab/html/images/icons")
WRAPPER = Path("/opt/unetlab/wrappers/unl_wrapper")

L2_IMAGE = "L2-ADVENTERPRISEK9-M-15.2-IRON-20151103.bin"
L3_IMAGE = "L3-ADVENTERPRISEK9-M-15.4-2T.bin"
L2_RAM = 768            # MB ceiling per switch; keeps all 8 nodes inside a 7.8 GB EVE-NG VM
L3_RAM = 512

MGMT_PREFIX = "192.168.1"          # home LAN that pnet0 (Cloud0) is bridged to
MGMT_MASK = "255.255.255.0"
MGMT_PORT = "e1/3"                 # same management port on every device
MGMT_CLOUD = "pnet0"

USERNAME = os.environ.get("LAB_USER", "admin")
PASSWORD = os.environ.get("LAB_PASSWORD", "Lab-Admin-123")
DOMAIN = "lab.local"

OUTPUT_DIR = Path("lab_output")    # readable configs + inventory land here

# EVE-NG gives each node a telnet console on this port plus the node id
# (first user, tenant 0). R1 has id 1, so its console is 32769.
CONSOLE_HOST = "127.0.0.1"
CONSOLE_BASE_PORT = 32768

# --------------------------------------------------------------------------
# The network design. Change the design here, not in the code below.
# --------------------------------------------------------------------------
DEVICES = [
    # name, EVE node id, role, image kind, mgmt last octet, loopback, canvas x/y
    {"name": "R1",    "id": 1, "role": "edge",   "kind": "l3", "mgmt": 201, "lo": "10.255.0.1",  "pos": (520, 60)},
    {"name": "CORE1", "id": 2, "role": "core",   "kind": "l2", "mgmt": 202, "lo": "10.255.0.11", "pos": (330, 210)},
    {"name": "CORE2", "id": 3, "role": "core",   "kind": "l2", "mgmt": 203, "lo": "10.255.0.12", "pos": (710, 210)},
    {"name": "DIST1", "id": 4, "role": "dist",   "kind": "l2", "mgmt": 204, "lo": "10.255.0.21", "pos": (330, 380)},
    {"name": "DIST2", "id": 5, "role": "dist",   "kind": "l2", "mgmt": 205, "lo": "10.255.0.22", "pos": (710, 380)},
    {"name": "ACC1",  "id": 6, "role": "access", "kind": "l2", "mgmt": 206, "lo": None,          "pos": (200, 560)},
    {"name": "ACC2",  "id": 7, "role": "access", "kind": "l2", "mgmt": 207, "lo": None,          "pos": (520, 560)},
    {"name": "ACC3",  "id": 8, "role": "access", "kind": "l2", "mgmt": 208, "lo": None,          "pos": (840, 560)},
]

# Routed point-to-point links (OSPF area 0). Each gets a /30:
# the first device takes the first usable address, the second takes the next.
ROUTED_LINKS = [
    ("R1",    "e0/0", "CORE1", "e0/0", "10.0.0.0"),
    ("R1",    "e0/1", "CORE2", "e0/0", "10.0.0.4"),
    ("CORE1", "e0/1", "CORE2", "e0/1", "10.0.0.8"),
    ("CORE1", "e0/2", "DIST1", "e0/0", "10.0.0.12"),
    ("CORE1", "e0/3", "DIST2", "e0/1", "10.0.0.16"),
    ("CORE2", "e0/2", "DIST2", "e0/0", "10.0.0.20"),
    ("CORE2", "e0/3", "DIST1", "e0/1", "10.0.0.24"),
]

# Layer 2 trunks. Last value is the port-channel number, or None for a single link.
TRUNK_LINKS = [
    ("DIST1", "e0/2", "DIST2", "e0/2", 1),
    ("DIST1", "e0/3", "DIST2", "e0/3", 1),
    ("DIST1", "e1/0", "ACC1",  "e0/0", None),
    ("DIST1", "e1/1", "ACC2",  "e0/0", None),
    ("DIST1", "e1/2", "ACC3",  "e0/0", None),
    ("DIST2", "e1/0", "ACC1",  "e0/1", None),
    ("DIST2", "e1/1", "ACC2",  "e0/1", None),
    ("DIST2", "e1/2", "ACC3",  "e0/1", None),
]

VLANS = {10: "USERS", 20: "SERVERS", 99: "NATIVE"}
NATIVE_VLAN = 99
TRUNK_ALLOWED = "10,20"
ACCESS_PORTS = {"e0/2": 10, "e0/3": 20}       # on every access switch

# Distribution layer: SVI address and HSRP priority per VLAN.
# DIST1 is the gateway and spanning-tree root for VLAN 10, DIST2 for VLAN 20.
SVIS = {
    "DIST1": {10: ("10.10.10.2", 110), 20: ("10.10.20.2", 100)},
    "DIST2": {10: ("10.10.10.3", 100), 20: ("10.10.20.3", 110)},
}
HSRP_VIP = {10: "10.10.10.1", 20: "10.10.20.1"}
STP_PRIORITY = {
    "DIST1": {10: 4096, 20: 8192},
    "DIST2": {10: 8192, 20: 4096},
}

INTERNET_SIM = "203.0.113.1"       # loopback on R1 that stands in for the internet

ALL_PORTS = ["e%d/%d" % (slot, port) for slot in range(2) for port in range(4)]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def long_name(port):
    """e0/1 -> Ethernet0/1"""
    return "Ethernet" + port[1:]


def iol_interface_id(port):
    """EVE-NG numbers IOL interfaces as slot + port * 16 (e2/1 -> 18)."""
    slot, num = port[1:].split("/")
    return int(slot) + int(num) * 16


def mgmt_ip(device):
    return "%s.%d" % (MGMT_PREFIX, device["mgmt"])


def build_ports():
    """Work out what every port on every device is used for."""
    ports = {d["name"]: {} for d in DEVICES}

    def claim(dev, port, spec):
        if port in ports[dev]:
            sys.exit("Design error: %s %s is used twice" % (dev, port))
        ports[dev][port] = spec

    for a, pa, b, pb, subnet in ROUTED_LINKS:
        net, last = subnet.rsplit(".", 1)
        claim(a, pa, {"kind": "routed", "peer": b, "peer_port": pb, "ip": "%s.%d" % (net, int(last) + 1)})
        claim(b, pb, {"kind": "routed", "peer": a, "peer_port": pa, "ip": "%s.%d" % (net, int(last) + 2)})

    for a, pa, b, pb, po in TRUNK_LINKS:
        claim(a, pa, {"kind": "trunk", "peer": b, "peer_port": pb, "po": po})
        claim(b, pb, {"kind": "trunk", "peer": a, "peer_port": pa, "po": po})

    for d in DEVICES:
        name = d["name"]
        if d["role"] == "access":
            for port, vlan in ACCESS_PORTS.items():
                claim(name, port, {"kind": "access", "vlan": vlan})
        claim(name, MGMT_PORT, {"kind": "mgmt", "ip": mgmt_ip(d)})
        for port in ALL_PORTS:
            ports[name].setdefault(port, {"kind": "unused"})
    return ports


# --------------------------------------------------------------------------
# Startup config for one device
# --------------------------------------------------------------------------
def trunk_lines():
    return [
        " switchport trunk encapsulation dot1q",
        " switchport trunk native vlan %d" % NATIVE_VLAN,
        " switchport trunk allowed vlan %s" % TRUNK_ALLOWED,
        " switchport mode trunk",
    ]


def render_config(device, ports):
    name = device["name"]
    role = device["role"]
    is_switch = device["kind"] == "l2"
    routes = role in ("edge", "core", "dist")
    my_ports = ports[name]
    out = []
    add = out.append

    add("!")
    add("service timestamps debug datetime msec")
    add("service timestamps log datetime msec")
    add("service password-encryption")
    add("!")
    add("hostname %s" % name)
    add("!")
    add("no ip domain-lookup")
    add("ip domain-name %s" % DOMAIN)
    add("!")
    add("username %s privilege 15 secret %s" % (USERNAME, PASSWORD))
    add("enable secret %s" % PASSWORD)
    add("!")

    if is_switch:
        add("vtp mode transparent")
        add("spanning-tree mode rapid-pvst")
        add("spanning-tree extend system-id")
        for vlan, prio in sorted(STP_PRIORITY.get(name, {}).items()):
            add("spanning-tree vlan %d priority %d" % (vlan, prio))
        add("!")
        if role in ("dist", "access"):
            for vlan, vname in sorted(VLANS.items()):
                add("vlan %d" % vlan)
                add(" name %s" % vname)
            add("!")
        if routes:
            add("ip routing")
            add("!")

    # Loopbacks
    if device["lo"]:
        add("interface Loopback0")
        add(" description ROUTER-ID")
        add(" ip address %s 255.255.255.255" % device["lo"])
        add("!")
    if role == "edge":
        add("interface Loopback100")
        add(" description INTERNET-SIM")
        add(" ip address %s 255.255.255.255" % INTERNET_SIM)
        add("!")

    # Port-channels
    port_channels = {}
    for port in ALL_PORTS:
        spec = my_ports[port]
        if spec["kind"] == "trunk" and spec["po"]:
            port_channels[spec["po"]] = spec["peer"]
    for po, peer in sorted(port_channels.items()):
        add("interface Port-channel%d" % po)
        add(" description TRUNK-TO-%s" % peer)
        out.extend(trunk_lines())
        add("!")

    # Physical ports
    for port in ALL_PORTS:
        spec = my_ports[port]
        kind = spec["kind"]
        add("interface %s" % long_name(port))
        if kind == "routed":
            add(" description TO-%s-%s" % (spec["peer"], spec["peer_port"]))
            if is_switch:
                add(" no switchport")
            add(" ip address %s 255.255.255.252" % spec["ip"])
            add(" ip ospf network point-to-point")
            add(" no shutdown")
        elif kind == "trunk":
            add(" description TO-%s-%s" % (spec["peer"], spec["peer_port"]))
            out.extend(trunk_lines())
            if spec["po"]:
                add(" channel-group %d mode active" % spec["po"])
            add(" no shutdown")
        elif kind == "access":
            add(" description %s-ACCESS" % VLANS[spec["vlan"]])
            add(" switchport mode access")
            add(" switchport access vlan %d" % spec["vlan"])
            add(" spanning-tree portfast")
            add(" spanning-tree bpduguard enable")
            add(" no shutdown")
        elif kind == "mgmt":
            add(" description MGMT")
            if is_switch:
                add(" no switchport")
            add(" ip address %s %s" % (spec["ip"], MGMT_MASK))
            add(" no ip proxy-arp")
            add(" no cdp enable")
            add(" no shutdown")
        else:
            add(" description UNUSED")
            if not is_switch:
                add(" no ip address")
            add(" shutdown")
        add("!")

    # SVIs with HSRP
    for vlan, (ip, prio) in sorted(SVIS.get(name, {}).items()):
        add("interface Vlan%d" % vlan)
        add(" description %s-GATEWAY" % VLANS[vlan])
        add(" ip address %s 255.255.255.0" % ip)
        add(" standby version 2")
        add(" standby %d ip %s" % (vlan, HSRP_VIP[vlan]))
        add(" standby %d priority %d" % (vlan, prio))
        add(" standby %d preempt" % vlan)
        add(" no shutdown")
        add("!")

    # OSPF
    if routes:
        add("router ospf 1")
        add(" router-id %s" % device["lo"])
        add(" passive-interface default")
        for port in ALL_PORTS:
            if my_ports[port]["kind"] == "routed":
                add(" no passive-interface %s" % long_name(port))
        add(" network 10.0.0.0 0.0.0.255 area 0")
        add(" network %s 0.0.0.0 area 0" % device["lo"])
        if role == "dist":
            add(" network 10.10.0.0 0.0.255.255 area 0")
        if role == "edge":
            add(" default-information originate always")
        add("!")

    add("no ip http server")
    add("no ip http secure-server")
    add("!")
    add("banner login # Authorized access only. NetCheck lab. #")
    add("!")
    add("line con 0")
    add(" logging synchronous")
    add(" exec-timeout 30 0")
    add("line vty 0 4")
    add(" login local")
    add(" transport input ssh")
    add(" exec-timeout 15 0")
    add("!")
    # The RSA keys SSH needs are generated afterwards by --enable-ssh.
    add("ip ssh version 2")
    add("!")
    add("end")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# The .unl lab file
# --------------------------------------------------------------------------
def pick_icon(wanted, fallback):
    if ICON_DIR.is_dir() and not (ICON_DIR / wanted).exists():
        return fallback
    return wanted


def build_unl(configs):
    interfaces = {d["name"]: [] for d in DEVICES}
    networks = []
    net_id = 0

    for link in ROUTED_LINKS + TRUNK_LINKS:
        a, pa, b, pb = link[0], link[1], link[2], link[3]
        net_id += 1
        networks.append((net_id, "bridge", "Net%d" % net_id, 600 + net_id * 10, 700, 0))
        interfaces[a].append((iol_interface_id(pa), pa, net_id))
        interfaces[b].append((iol_interface_id(pb), pb, net_id))

    net_id += 1
    mgmt_net = net_id
    networks.append((mgmt_net, MGMT_CLOUD, "MGMT-Cloud0", 1040, 320, 1))
    for d in DEVICES:
        interfaces[d["name"]].append((iol_interface_id(MGMT_PORT), MGMT_PORT, mgmt_net))

    icons = {
        "edge": "Router.png",
        "core": "Switch L3.png",
        "dist": "Switch L3.png",
        "access": pick_icon("Switch.png", "Switch L3.png"),
    }

    x = []
    x.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    x.append('<lab name="%s" id="%s" version="1" lock="0">' % (escape(LAB_NAME), uuid.uuid4()))
    x.append("  <topology>")
    x.append("    <nodes>")
    for d in DEVICES:
        image = L2_IMAGE if d["kind"] == "l2" else L3_IMAGE
        ram = L2_RAM if d["kind"] == "l2" else L3_RAM
        x.append(
            '      <node id="%d" name="%s" type="iol" template="iol" image="%s" ethernet="2" '
            'nvram="1024" ram="%d" serial="0" console="" delay="0" icon="%s" config="1" '
            'left="%d" top="%d">'
            % (d["id"], d["name"], image, ram, icons[d["role"]], d["pos"][0], d["pos"][1])
        )
        for if_id, port, network in sorted(interfaces[d["name"]]):
            x.append('        <interface id="%d" name="%s" type="ethernet" network_id="%d"/>' % (if_id, port, network))
        x.append("      </node>")
    x.append("    </nodes>")
    x.append("    <networks>")
    for nid, ntype, nname, left, top, visible in networks:
        x.append(
            '      <network id="%d" type="%s" name="%s" left="%d" top="%d" visibility="%d"/>'
            % (nid, ntype, nname, left, top, visible)
        )
    x.append("    </networks>")
    x.append("  </topology>")
    x.append("  <objects>")
    x.append("    <configs>")
    for d in DEVICES:
        encoded = base64.b64encode(configs[d["name"]].encode("ascii")).decode("ascii")
        x.append('      <config id="%d">%s</config>' % (d["id"], encoded))
    x.append("    </configs>")
    x.append("  </objects>")
    x.append("</lab>")
    return "\n".join(x) + "\n"


def write_side_files(configs):
    cfg_dir = OUTPUT_DIR / "configs"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    for name, text in configs.items():
        (cfg_dir / ("%s.cfg" % name)).write_text(text)

    inv = ["# Generated by build_lab.py - do not edit by hand", "devices:"]
    for d in DEVICES:
        inv.append("  - name: %s" % d["name"])
        inv.append("    role: %s" % d["role"])
        inv.append("    mgmt_ip: %s" % mgmt_ip(d))
        inv.append("    platform: cisco_ios")
    (OUTPUT_DIR / "inventory.yml").write_text("\n".join(inv) + "\n")


def print_plan():
    print("")
    print("  %-6s %-7s %-16s %s" % ("Device", "Role", "Management IP", "Loopback"))
    for d in DEVICES:
        print("  %-6s %-7s %-16s %s" % (d["name"], d["role"], mgmt_ip(d), d["lo"] or "-"))
    print("")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def cmd_build(args):
    lab_path = Path(args.out) if args.out else LABS_DIR / ("%s.unl" % LAB_NAME)

    if not args.out:
        if not LABS_DIR.is_dir():
            sys.exit("This does not look like an EVE-NG server (%s is missing).\n"
                     "Run the script on EVE-NG, or use --out to write the lab file elsewhere." % LABS_DIR)
        for image in (L2_IMAGE, L3_IMAGE):
            if not (IOL_DIR / image).exists():
                sys.exit("IOL image not found: %s" % (IOL_DIR / image))
    if lab_path.exists() and not args.force:
        sys.exit("%s already exists. Stop and wipe its nodes first, then rerun with --force." % lab_path)

    ports = build_ports()
    configs = {d["name"]: render_config(d, ports) for d in DEVICES}
    lab_path.write_text(build_unl(configs))
    write_side_files(configs)

    if not args.out and WRAPPER.exists():
        subprocess.call([str(WRAPPER), "-a", "fixpermissions"])

    print("Lab file written:   %s" % lab_path)
    print("Readable configs:   %s/" % (OUTPUT_DIR / "configs"))
    print("Inventory:          %s" % (OUTPUT_DIR / "inventory.yml"))
    print_plan()
    print("Next: open the EVE-NG web UI, open '%s', start all nodes, wait about" % LAB_NAME)
    print("two minutes, then run:  python3 build_lab.py --enable-ssh")


def cmd_verify(_args):
    print("  %-6s %-16s %-6s %s" % ("Device", "Management IP", "Ping", "SSH (tcp/22)"))
    failures = 0
    for d in DEVICES:
        ip = mgmt_ip(d)
        ping_ok = subprocess.call(
            ["ping", "-c", "2", "-W", "1", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ) == 0
        ssh_ok = False
        try:
            sock = socket.create_connection((ip, 22), timeout=3)
            sock.close()
            ssh_ok = True
        except OSError:
            pass
        if not (ping_ok and ssh_ok):
            failures += 1
        print("  %-6s %-16s %-6s %s" % (d["name"], ip, "ok" if ping_ok else "FAIL", "open" if ssh_ok else "CLOSED"))
    print("")
    if failures:
        print("%d device(s) need attention. If SSH is CLOSED, run:  python3 build_lab.py --enable-ssh" % failures)
        sys.exit(1)
    print("All %d devices are reachable and accepting SSH." % len(DEVICES))


def console_read(sock, wait):
    time.sleep(wait)
    sock.settimeout(0.5)
    data = b""
    try:
        while True:
            chunk = sock.recv(65535)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data.decode("ascii", "ignore")


def console_send(sock, text, wait=1.0):
    sock.sendall(text.encode("ascii") + b"\r")
    return console_read(sock, wait)


def enable_ssh_on(device):
    """Generate RSA keys on one node through its console, then save the config."""
    port = CONSOLE_BASE_PORT + device["id"]
    try:
        sock = socket.create_connection((CONSOLE_HOST, port), timeout=5)
    except OSError as err:
        return False, "cannot open console port %d (%s). Is the node started?" % (port, err)
    try:
        log = console_read(sock, 0.5)
        log += console_send(sock, "")
        log += console_send(sock, "")
        log += console_send(sock, "end")
        log += console_send(sock, "enable")
        log += console_send(sock, PASSWORD)
        log += console_send(sock, "configure terminal")
        out = console_send(sock, "crypto key generate rsa modulus 2048", 2)
        if "yes/no" in out:          # keys already exist: replace them
            out += console_send(sock, "yes", 2)
        waited = 0
        while "[OK]" not in out and waited < 90:
            out += console_read(sock, 3)
            waited += 3
        log += out
        log += console_send(sock, "ip ssh version 2")
        log += console_send(sock, "end")
        log += console_send(sock, "write memory", 5)
    except OSError as err:
        return False, "console connection dropped (%s)" % err
    finally:
        sock.close()
    if "[OK]" in out:
        return True, "keys generated, config saved"
    return False, "no confirmation from device. Last output:\n" + "\n".join(log.splitlines()[-15:])


def cmd_enable_ssh(args):
    print("Generating SSH keys through each node's console. This takes about three minutes.")
    failed = 0
    for d in DEVICES:
        ok, message = enable_ssh_on(d)
        print("  %-6s %s %s" % (d["name"], "OK  " if ok else "FAIL", message))
        sys.stdout.flush()
        failed += 0 if ok else 1
    print("")
    if failed:
        print("%d device(s) failed. Fix those, then run this again." % failed)
        sys.exit(1)
    cmd_verify(args)


def main():
    parser = argparse.ArgumentParser(description="Build the NetCheck EVE-NG lab as code.")
    parser.add_argument("--force", action="store_true", help="overwrite an existing lab file")
    parser.add_argument("--enable-ssh", action="store_true", help="generate SSH keys on every node, save, then verify")
    parser.add_argument("--verify", action="store_true", help="check ping and SSH on every device")
    parser.add_argument("--out", help="write the lab file to this path instead of the EVE-NG labs folder")
    args = parser.parse_args()
    if args.enable_ssh:
        cmd_enable_ssh(args)
    elif args.verify:
        cmd_verify(args)
    else:
        cmd_build(args)


if __name__ == "__main__":
    main()
