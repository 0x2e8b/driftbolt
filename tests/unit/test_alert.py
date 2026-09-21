from datetime import datetime

from sycope_recorder.alert import parse_alert


def test_ip_string_and_dict_forms_and_alias_priority():
    a = parse_alert({"clientIp": "1.1.1.1", "dstIp": {"addressString": "2.2.2.2"}})
    assert a.client_ip == "1.1.1.1"
    assert a.server_ip == "2.2.2.2"


def test_ip_alias_fallback_order():
    a = parse_alert({"source": "9.9.9.9", "destination": "8.8.8.8"})
    assert a.client_ip == "9.9.9.9"
    assert a.server_ip == "8.8.8.8"


def test_port_zero_and_negative_treated_as_absent():
    assert parse_alert({"serverPort": 0}).server_port is None
    assert parse_alert({"serverPort": -3}).server_port is None
    assert parse_alert({"serverPort": "443"}).server_port == 443
    assert parse_alert({"dstPort": 80}).server_port == 80


def test_protocol_int_and_string_mapping():
    assert parse_alert({"protocol": 6}).protocol == "tcp"
    assert parse_alert({"protocol": 17}).protocol == "udp"
    assert parse_alert({"protocol": 1}).protocol == "icmp"
    assert parse_alert({"protocolName": "TCP"}).protocol == "tcp"
    assert parse_alert({"protocol": "http"}).protocol is None
    assert parse_alert({"protocol": 99}).protocol is None


def test_timestamp_ms_vs_seconds_heuristic():
    """Locks in the >1e12 threshold for the seconds-vs-milliseconds guess: below it is
    treated as already-seconds, above it is assumed milliseconds and divided down."""
    assert parse_alert({"unixTimestamp": 1_700_000_000}).timestamp == 1_700_000_000
    # value > 1e12 is milliseconds
    assert parse_alert({"time": 1_700_000_000_000}).timestamp == 1_700_000_000


def test_timestamp_string_fallback_day_first_two_digit_year():
    a = parse_alert({"timestamp": "01.07.26 14:03:00"})
    assert datetime.fromtimestamp(a.timestamp).strftime("%Y-%m-%d %H:%M:%S") == "2026-07-01 14:03:00"


def test_timestamp_final_fallback_uses_now():
    fixed = datetime(2030, 1, 2, 3, 4, 5)
    a = parse_alert({}, now=fixed)
    assert a.timestamp == fixed.timestamp()


def test_id_presence_not_truthiness_null_id_kept():
    """Presence-vs-truthiness asymmetry: id=None is used as-is (str "None"),
    NOT replaced by the alert_<ts> fallback — see alert.py module note."""
    # 'id' present but null -> kept as-is (becomes "None" downstream), NOT synthesized
    assert parse_alert({"id": None}, now=datetime(2020, 1, 1)).alert_id is None
    # absent -> synthesized alert_<int_ts>
    a = parse_alert({}, now=datetime(2020, 1, 1))
    assert a.alert_id == f"alert_{int(datetime(2020, 1, 1).timestamp())}"
    # alertId used when id absent
    assert parse_alert({"alertId": "X1"}).alert_id == "X1"


def test_name_fallback():
    assert parse_alert({}).alert_name == "Unknown"
    assert parse_alert({"alertName": "Foo"}).alert_name == "Foo"
    assert parse_alert({"name": "Bar", "alertName": "Foo"}).alert_name == "Bar"
