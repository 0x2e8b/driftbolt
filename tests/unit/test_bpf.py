from sycope_recorder.alert import ParsedAlert
from sycope_recorder.bpf import FILTER_MODES, build_bpf_filter


def mk(**kw) -> ParsedAlert:
    base = dict(
        client_ip=None, server_ip=None, server_port=None,
        protocol=None, timestamp=0.0, alert_id="id", alert_name="n",
    )
    base.update(kw)
    return ParsedAlert(**base)


def test_full_mode_all_terms():
    p = mk(client_ip="1.1.1.1", server_ip="2.2.2.2", server_port=443, protocol="tcp")
    assert build_bpf_filter(p, "full") == "tcp and host 1.1.1.1 and host 2.2.2.2 and port 443"


def test_hosts_mode_no_port():
    p = mk(client_ip="1.1.1.1", server_ip="2.2.2.2", server_port=443, protocol="tcp")
    assert build_bpf_filter(p, "hosts") == "tcp and host 1.1.1.1 and host 2.2.2.2"


def test_client_and_server_and_port_modes():
    p = mk(client_ip="1.1.1.1", server_ip="2.2.2.2", server_port=443, protocol="udp")
    assert build_bpf_filter(p, "client") == "udp and host 1.1.1.1"
    assert build_bpf_filter(p, "server") == "udp and host 2.2.2.2"
    assert build_bpf_filter(p, "port") == "udp and host 2.2.2.2 and port 443"


def test_icmp_protocol_dropped_when_port_present():
    """ICMP+port suppression rule: an icmp alert with a port present drops both the
    "icmp" term (superseded) and the port term (icmp never gets one), leaving only host terms."""
    p = mk(server_ip="2.2.2.2", server_port=8, protocol="icmp")
    # icmp term dropped because a port is present; port term also excluded (proto is icmp)
    assert build_bpf_filter(p, "full") == "host 2.2.2.2"


def test_icmp_kept_when_no_port():
    p = mk(server_ip="2.2.2.2", protocol="icmp")
    assert build_bpf_filter(p, "full") == "icmp and host 2.2.2.2"


def test_port_term_only_for_tcp_udp_or_unknown():
    # unknown protocol: port term still allowed
    p = mk(server_ip="2.2.2.2", server_port=53)
    assert build_bpf_filter(p, "full") == "host 2.2.2.2 and port 53"


def test_reject_empty_and_bare_protocol_only():
    assert build_bpf_filter(mk(), "full") is None
    assert build_bpf_filter(mk(protocol="tcp"), "full") is None


def test_reject_bare_icmp_protocol_only():
    """Bare-protocol-only rejection applies to icmp too, not just tcp/udp — a lone
    "icmp" term with no host/port is still too broad to be useful."""
    assert build_bpf_filter(mk(protocol="icmp"), "full") is None


def test_unknown_mode_treated_as_full():
    p = mk(client_ip="1.1.1.1", server_ip="2.2.2.2", server_port=443, protocol="tcp")
    assert build_bpf_filter(p, "bogus") == build_bpf_filter(p, "full")


def test_filter_modes_table():
    assert FILTER_MODES["full"] == (True, True, True)
    assert FILTER_MODES["hosts"] == (True, True, False)
    assert FILTER_MODES["client"] == (True, False, False)
    assert FILTER_MODES["server"] == (False, True, False)
    assert FILTER_MODES["port"] == (False, True, True)
