import collect

CONFIG = """enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
enable password 7 0822455D0A16
username admin privilege 15 secret 5 $1$abcd$efgh
username bob password 0 hunter2
snmp-server community PUBLIC RO
key chain OSPF-KEYS
 key 1
  key-string 7 094F471A1A0A
 ip ospf message-digest-key 1 md5 7 13061E010803
 password 7 110A1016141D
service password-encryption
tacacs-server key 7 0508571C22431F"""


def test_redact_removes_every_secret():
    out = collect.redact(CONFIG)
    for secret in ("hx5rVt", "0822455", "efgh", "hunter2", "PUBLIC", "094F47", "13061E", "110A10", "0508571"):
        assert secret not in out


def test_redact_keeps_what_the_audit_needs():
    out = collect.redact(CONFIG)
    assert "enable secret 5 <redacted>" in out
    assert "username bob password 0 <redacted>" in out
    assert "key chain OSPF-KEYS" in out and " key 1\n" in out
    assert "service password-encryption" in out


def test_slug_is_a_safe_file_name():
    assert collect.slug("show ip ospf neighbor") == "show_ip_ospf_neighbor"
    assert collect.slug("show spanning-tree") == "show_spanning_tree"


def test_commands_for_adds_role_commands_without_duplicates():
    command_set = {"common": ["show version", "show ip route"], "by_role": {"core": ["show ip route", "show ip ospf neighbor"]}}
    assert collect.commands_for({"role": "core"}, command_set) == ["show version", "show ip route", "show ip ospf neighbor"]
    assert collect.commands_for({"role": "access"}, command_set) == ["show version", "show ip route"]
