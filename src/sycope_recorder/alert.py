"""Parses loosely-shaped Sycope alert JSON into a ParsedAlert.

Sycope alert payloads vary in field naming by alert type and Sycope
version, so this module tries a priority-ordered list of field name
aliases per logical field (client IP, server IP, port, protocol,
timestamp, id, name) and takes the first usable match. "Usable" differs
by field: the flow fields and timestamp use a truthiness check (so
`serverPort: 0` or an empty-string IP is treated as absent and the next
alias is tried), while alert id/name use plain presence (`dict.get`
chaining), so a present-but-null id is kept as-is rather than falling
through to a synthesized default. See SPEC.md §5.3 for the full alias
tables and the reasoning behind that asymmetry.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

_PROTO_BY_NUM = {1: "icmp", 6: "tcp", 17: "udp"}
_ALLOWED_PROTO = {"tcp", "udp", "icmp"}


@dataclass
class ParsedAlert:
    """Alert fields normalized from Sycope's loosely-shaped JSON payload."""

    client_ip: str | None
    server_ip: str | None
    server_port: int | None
    protocol: str | None
    timestamp: float
    alert_id: Any  # str, int, or None depending on the source payload's "id"/"alertId" field
    alert_name: str


def _find_field(alert: dict, aliases: list[str], extract: Callable[[Any], Any]) -> Any:
    """Try each alias in priority order, returning the first extracted value that is truthy.

    A field name being present isn't enough to accept it: 0, "", None, and
    [] are all treated as "this alias didn't actually give us a value" and
    the next alias is tried instead. This is deliberately different from
    the id/name lookup in parse_alert, which keys off presence alone (see
    module docstring) — a real port of 0 or an empty IP string is useless,
    but a null id is still a meaningful (if unfortunate) value to keep.
    """
    for name in aliases:
        if name in alert:
            value = extract(alert[name])
            if value:
                return value
    return None


def _ip(value: Any) -> str | None:
    """Accept a plain IP string as-is, or pull it from a dict's "addressString" key; anything else is unusable."""
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        return value.get("addressString")
    return None


def _port(value: Any) -> int | None:
    """Coerce to a positive int, rejecting bools, non-numeric strings, and zero/negative values as "no port"."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        try:
            n = int(value)
        except ValueError:
            return None
        return n if n > 0 else None
    return None


def _proto(value: Any) -> str | None:
    """Map a known IP protocol number to its name, or lowercase and validate a string; anything unrecognized is discarded."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return _PROTO_BY_NUM.get(value)
    if isinstance(value, str):
        low = value.lower()
        return low if low in _ALLOWED_PROTO else None
    return None


def _numeric_ts(value: Any) -> float | None:
    """Parse a numeric (or numeric-string) timestamp, converting to seconds.

    Sycope sometimes sends Unix time in milliseconds instead of seconds
    with no explicit unit marker, so any value greater than 1e12 (a
    threshold far above any plausible seconds-based timestamp, but well
    below a milliseconds one) is assumed to be milliseconds and divided
    down.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        n = float(value)
    elif isinstance(value, str):
        try:
            n = float(value)
        except ValueError:
            return None
    else:
        return None
    return n / 1000.0 if n > 1e12 else n


def _resolve_timestamp(alert: dict, now: datetime) -> float:
    """Resolve the alert timestamp via a fallback chain: numeric fields first, then a formatted string, then "now".

    Tries the numeric aliases (unixTimestamp/timestamp_unix/time) via
    _find_field first since they're unambiguous once normalized to
    seconds. If none are usable, falls back to a "timestamp" string
    field in Sycope's day-first, 2-digit-year format
    (`%d.%m.%y %H:%M:%S`). If that's also missing or unparseable, the
    alert is timestamped with `now` rather than failing — a slightly
    wrong time is preferable to rejecting the alert outright.
    """
    numeric = _find_field(alert, ["unixTimestamp", "timestamp_unix", "time"], _numeric_ts)
    if numeric:
        return numeric
    raw = alert.get("timestamp")
    if isinstance(raw, str):
        try:
            return datetime.strptime(raw, "%d.%m.%y %H:%M:%S").timestamp()
        except ValueError:
            pass
    return now.timestamp()


def parse_alert(alert: dict, *, now: datetime | None = None) -> ParsedAlert:
    """Normalize a raw Sycope alert dict into a ParsedAlert.

    The flow fields (client/server IP, port, protocol) and timestamp are
    resolved via _find_field's truthiness gate, so a falsy value (port 0,
    empty-string IP) is skipped in favor of the next alias. alert_id and
    alert_name, by contrast, are resolved with plain `dict.get` chaining,
    which keys off presence only: a present-but-null "id" is used as-is
    (becoming the string "None" downstream) rather than falling through
    to the synthesized `alert_<timestamp>` default. This asymmetry is
    intentional and must be preserved by any reimplementation — see
    SPEC.md §5.3.
    """
    now = now or datetime.now()
    client_ip = _find_field(alert, ["clientIp", "srcIp", "src_ip", "sourceIp", "source"], _ip)
    server_ip = _find_field(alert, ["serverIp", "dstIp", "dst_ip", "destIp", "destination"], _ip)
    server_port = _find_field(alert, ["serverPort", "dstPort", "dst_port", "destPort"], _port)
    protocol = _find_field(alert, ["protocolName", "protocol", "proto", "ipProtocol"], _proto)
    timestamp = _resolve_timestamp(alert, now)

    alert_id = alert.get("id", alert.get("alertId", f"alert_{int(timestamp)}"))
    alert_name = alert.get("name", alert.get("alertName", "Unknown"))

    return ParsedAlert(
        client_ip=client_ip,
        server_ip=server_ip,
        server_port=server_port,
        protocol=protocol,
        timestamp=timestamp,
        alert_id=alert_id,
        alert_name=alert_name,
    )
