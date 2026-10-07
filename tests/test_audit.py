import audit

BASE = """
service password-encryption
hostname ACC1
username admin privilege 15 secret 5 <redacted>
enable secret 5 <redacted>
no ip http server
no ip http secure-server
banner login ^C Authorized access only. ^C
line con 0
 exec-timeout 30 0
 logging synchronous
line vty 0 4
 exec-timeout 15 0
 login local
 transport input ssh
ip ssh version 2
end
"""

HARDENED = BASE.replace(" transport input ssh", " access-class MGMT-ACCESS in\n transport input ssh").replace(
    "ip ssh version 2", "ip ssh version 2\nlogging host 192.168.1.103\nntp server 192.168.1.201")

WEAK = """
hostname BAD
enable password 7 <redacted>
username ops password 7 <redacted>
ip http server
snmp-server community <redacted> RO
line con 0
 exec-timeout 0 0
line vty 0 4
 login local
 transport input telnet ssh
line vty 5 15
 login
end
"""


def failed(text):
    cfg = audit.Config(text)
    return {rule_id for rule_id, _level, _title, check in audit.RULES if not check(cfg)[0]}


def test_lab_default_config_has_three_gaps():
    assert failed(BASE) == {"vty-acl", "syslog", "ntp"}


def test_hardened_config_passes_everything():
    assert failed(HARDENED) == set()


def test_ntp_master_counts_as_a_time_source():
    assert "ntp" not in failed(BASE + "ntp master 4\n")


def test_weak_config_fails_the_high_severity_rules():
    result = failed(WEAK)
    assert {"ssh-only", "enable-secret", "user-secrets"} <= result
    assert {"http-off", "idle-timeout", "snmp", "ssh-v2", "banner", "pw-encryption"} <= result


def test_unconfigured_vty_lines_are_caught():
    cfg = audit.Config(WEAK)
    passed, evidence = audit.rule_ssh_only(cfg)
    assert not passed and "line vty 5 15" in evidence
