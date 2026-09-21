"""Builds the BPF filter expression passed to npcapextract for an alert.

Translates a ParsedAlert plus a filter mode (which fields to include) into
a `tcpdump`-style boolean expression. Carries over legacy operational
rules for when a filter is too broad or nonsensical to be useful — see
SPEC.md §5.5 for the full rationale.
"""

from __future__ import annotations

from sycope_recorder.alert import ParsedAlert

# mode -> (include_client_ip, include_server_ip, include_port)
FILTER_MODES: dict[str, tuple[bool, bool, bool]] = {
    "full": (True, True, True),
    "hosts": (True, True, False),
    "client": (True, False, False),
    "server": (False, True, False),
    "port": (False, True, True),
}

_BARE_PROTO = {"tcp", "udp", "icmp"}


def build_bpf_filter(parsed: ParsedAlert, mode: str) -> str | None:
    """Build a BPF filter string for npcapextract from a parsed alert.

    Returns None (never an empty string) if no filter can be built — e.g.
    mode selects only fields the alert doesn't have, or the only term
    would be a bare protocol name with no host/port (too broad to be a
    useful filter). Callers must treat None as "skip extraction".
    """
    include_client, include_server, include_port = FILTER_MODES.get(
        mode, FILTER_MODES["full"]
    )

    proto = parsed.protocol
    port = parsed.server_port
    terms: list[str] = []

    # 1. protocol term, unless icmp-with-port
    if proto is not None and not (proto == "icmp" and port is not None):
        terms.append(proto)

    # 2/3. host terms
    if include_client and parsed.client_ip:
        terms.append(f"host {parsed.client_ip}")
    if include_server and parsed.server_ip:
        terms.append(f"host {parsed.server_ip}")

    # 4. port term only for tcp/udp/unknown (never icmp)
    if include_port and port is not None and proto in ("tcp", "udp", None):
        terms.append(f"port {port}")

    # 5. rejection rule
    if not terms or (len(terms) == 1 and terms[0] in _BARE_PROTO):
        return None

    return " and ".join(terms)
