#!/usr/bin/env python3
"""
Sycope Traffic Recorder — webhook listener

Receives Sycope alert webhooks and extracts matching packets from
continuously recorded PCAPs using npcapextract.

URL parameters:
  filter: full|hosts|client|server|port
    - full:   client IP + server IP + port (default)
    - hosts:  client IP + server IP
    - client: only client IP
    - server: only server IP
    - port:   server IP + port

  before: seconds before alert (default: 30)
  after:  seconds after alert (default: 60)

Examples:
  http://recorder:8888/extract?filter=full&before=30&after=60
  http://recorder:8888/extract?filter=hosts&before=60&after=120
  http://recorder:8888/extract?filter=server&before=10&after=30
"""

import json
import logging
import os
import subprocess
import threading
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from config_loader import check_basic_auth, load_config

# === CONFIG ===
_config = load_config()
TIMELINE_DIR = _config["timeline_dir"]
OUTPUT_DIR = _config["output_dir"]
PORT = _config["listen_port"]
FILE_SERVER_URL = f"http://{_config['host']}:{_config['fileserver_port']}"
DEFAULT_FILTER = _config["default_filter"]
DEFAULT_BEFORE = _config["default_before"]
DEFAULT_AFTER = _config["default_after"]
AUTH_USER = _config.get("listener_auth_user", "")
AUTH_PASS = _config.get("listener_auth_pass", "")
try:
    MAX_CONCURRENT = int(_config.get("max_concurrent_extractions", 1))
except (TypeError, ValueError):
    MAX_CONCURRENT = 1
MAX_CONCURRENT = max(1, MAX_CONCURRENT)
_EXTRACT_SEM = threading.Semaphore(MAX_CONCURRENT)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("pcap-extractor")

# Declarative filter mode definitions: which components to include in BPF
FILTER_MODES = {
    "full":   {"client": True, "server": True, "port": True},
    "hosts":  {"client": True, "server": True, "port": False},
    "client": {"client": True, "server": False, "port": False},
    "server": {"client": False, "server": True, "port": False},
    "port":   {"client": False, "server": True, "port": True},
}


def extract_ip(field):
    """Extract IP from various Sycope formats"""
    if field is None:
        return None
    if isinstance(field, str):
        return field
    if isinstance(field, dict):
        return field.get("addressString")
    return None


def extract_port(field):
    """Extract port value"""
    if field is None:
        return None
    if isinstance(field, int):
        return field if field > 0 else None
    if isinstance(field, str) and field.isdigit():
        return int(field)
    return None


def extract_protocol(field):
    """Extract protocol for BPF filter"""
    if not field:
        return None
    proto_map = {1: "icmp", 6: "tcp", 17: "udp"}
    if isinstance(field, int):
        return proto_map.get(field)
    val = str(field).lower()
    return val if val in ("tcp", "udp", "icmp") else None


def _find_field(alert, field_names, extractor):
    """Search alert for the first matching field using the given extractor."""
    for field in field_names:
        if field in alert:
            val = extractor(alert[field])
            if val:
                return val
    return None


def build_bpf_filter(parsed, filter_mode):
    """
    Build BPF filter for the selected mode.

    Modes:
      full:   host CLIENT and host SERVER and port PORT
      hosts:  host CLIENT and host SERVER
      client: host CLIENT
      server: host SERVER
      port:   host SERVER and port PORT
    """
    client_ip = parsed["client_ip"]
    server_ip = parsed["server_ip"]
    server_port = parsed["server_port"]
    protocol = parsed["protocol"]

    mode = FILTER_MODES.get(filter_mode, FILTER_MODES["full"])
    parts = []

    # Add protocol (skip ICMP when port is present)
    if protocol and not (protocol == "icmp" and server_port):
        parts.append(protocol)

    if mode["client"] and client_ip:
        parts.append(f"host {client_ip}")
    if mode["server"] and server_ip:
        parts.append(f"host {server_ip}")
    if mode["port"] and server_port and protocol in ("tcp", "udp", None):
        parts.append(f"port {server_port}")

    if not parts or (len(parts) == 1 and parts[0] in ("tcp", "udp", "icmp")):
        return None

    return " and ".join(parts)


def parse_alert(alert):
    """Parse Sycope alert"""

    # Timestamp
    unix_ts = None
    for field in ["unixTimestamp", "timestamp_unix", "time"]:
        if field in alert:
            val = alert[field]
            if isinstance(val, (int, float)):
                unix_ts = val / 1000 if val > 1e12 else val
                break

    if unix_ts is None and "timestamp" in alert:
        try:
            ts_str = alert["timestamp"]
            dt = datetime.strptime(ts_str, "%d.%m.%y %H:%M:%S")
            unix_ts = dt.timestamp()
        except (ValueError, TypeError):
            pass

    if unix_ts is None:
        unix_ts = datetime.now().timestamp()

    client_ip = _find_field(
        alert, ["clientIp", "srcIp", "src_ip", "sourceIp", "source"], extract_ip
    )
    server_ip = _find_field(
        alert, ["serverIp", "dstIp", "dst_ip", "destIp", "destination"], extract_ip
    )
    server_port = _find_field(
        alert, ["serverPort", "dstPort", "dst_port", "destPort"], extract_port
    )
    protocol = _find_field(
        alert, ["protocolName", "protocol", "proto", "ipProtocol"], extract_protocol
    )

    return {
        "id": alert.get("id", alert.get("alertId", f"alert_{int(unix_ts)}")),
        "name": alert.get("name", alert.get("alertName", "Unknown")),
        "timestamp": unix_ts,
        "client_ip": client_ip,
        "server_ip": server_ip,
        "server_port": server_port,
        "protocol": protocol,
    }


def run_extraction(parsed, filter_mode, time_before, time_after):
    """Run npcapextract"""

    alert_time = datetime.fromtimestamp(parsed["timestamp"])
    time_begin = alert_time - timedelta(seconds=time_before)
    time_end = alert_time + timedelta(seconds=time_after)

    fmt = "%Y-%m-%d %H:%M:%S"
    begin_str = time_begin.strftime(fmt)
    end_str = time_end.strftime(fmt)

    bpf_filter = build_bpf_filter(parsed, filter_mode)

    if not bpf_filter:
        log.warning(
            "No BPF filter built (client_ip=%s, server_ip=%s, port=%s, proto=%s, mode=%s)",
            parsed["client_ip"],
            parsed["server_ip"],
            parsed["server_port"],
            parsed["protocol"],
            filter_mode,
        )
        return "NO BPF FILTER"

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    # Build output filename
    safe_id = "".join(c for c in str(parsed["id"]) if c.isalnum() or c in "-_")
    safe_id = safe_id[:64] if safe_id else "alert"
    timestamp_str = alert_time.strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp_str}_{safe_id}.pcap"
    output_file = os.path.join(OUTPUT_DIR, filename)

    cmd = [
        "npcapextract",
        "-t",
        TIMELINE_DIR,
        "-b",
        begin_str,
        "-e",
        end_str,
        "-f",
        bpf_filter,
        "-o",
        output_file,
    ]

    log.info(f"Filter mode: {filter_mode}")
    log.info(f"BPF: {bpf_filter}")
    log.info(
        f"Time: {begin_str} -> {end_str} (before={time_before}s, after={time_after}s)"
    )

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        log.error("npcapextract timeout after 300s")
        return "ERROR: npcapextract timeout"

    if result.returncode == 0 and os.path.exists(output_file):
        size = os.path.getsize(output_file)
        if size > 0:
            url = f"{FILE_SERVER_URL}/{filename}"
            log.info(f"SUCCESS: {output_file} ({size} bytes)")
            log.info(f"URL: {url}")
            return url
        else:
            log.info(f"MISS: {output_file} ({size} bytes)")
            try:
                os.remove(output_file)
            except OSError as e:
                log.error(f"Failed to remove empty file {output_file}: {e}")

    if result.stdout:
        log.info(f"npcapextract stdout: {result.stdout.strip()}")
    if result.stderr:
        log.error(f"npcapextract stderr: {result.stderr.strip()}")

    return "ERROR: npcapextract failed"


def parse_url_params(path):
    """Parse URL query parameters"""
    parsed_url = urlparse(path)
    params = parse_qs(parsed_url.query)

    filter_mode = params.get("filter", [DEFAULT_FILTER])[0]
    if filter_mode == "":
        log.warning("Empty filter mode, using default")
        filter_mode = DEFAULT_FILTER
    if filter_mode not in FILTER_MODES:
        log.warning(f"Unknown filter mode '{filter_mode}', using default '{DEFAULT_FILTER}'")
        filter_mode = DEFAULT_FILTER

    try:
        time_before = int(params.get("before", [DEFAULT_BEFORE])[0])
    except ValueError:
        time_before = DEFAULT_BEFORE

    try:
        time_after = int(params.get("after", [DEFAULT_AFTER])[0])
    except ValueError:
        time_after = DEFAULT_AFTER

    # Clamp to 0..86400 seconds
    raw_before, raw_after = time_before, time_after
    time_before = max(0, min(time_before, 86400))
    time_after = max(0, min(time_after, 86400))
    if (raw_before, raw_after) != (time_before, time_after):
        log.info(
            f"Clamped window: before={raw_before}->{time_before}, after={raw_after}->{time_after}"
        )

    return filter_mode, time_before, time_after


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Parse URL parameters
        filter_mode, time_before, time_after = parse_url_params(self.path)

        if not check_basic_auth(self.headers, AUTH_USER, AUTH_PASS):
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.send_header('WWW-Authenticate', 'Basic realm="pcap-extractor"')
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return

        if "Content-Length" not in self.headers:
            self.send_response(411)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Missing Content-Length")
            return
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 2 * 1024 * 1024:
            self.send_response(413)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Payload too large")
            return
        body = self.rfile.read(content_length)
        if not body:
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Empty request body")
            return

        try:
            alert = json.loads(body)

            log.info("=" * 60)
            log.info(
                f"Alert: id={alert.get('id', alert.get('alertId', 'Unknown'))} name={alert.get('name', 'Unknown')}"
            )
            log.info(f"Alert keys: {list(alert.keys())}")
            log.info(
                f"URL params: filter={filter_mode}, before={time_before}, after={time_after}"
            )

            parsed = parse_alert(alert)

            log.info(f"  ID: {parsed['id']}")
            log.info(
                f"  Time: local={datetime.fromtimestamp(parsed['timestamp'])} utc={datetime.utcfromtimestamp(parsed['timestamp'])}"
            )
            log.info(
                f"  Flow: {parsed['client_ip']} -> {parsed['server_ip']}:{parsed['server_port']} ({parsed['protocol']})"
            )
            if not parsed["client_ip"] or not parsed["server_ip"]:
                log.warning("Alert missing client/server IP fields; BPF may be empty")

            if not _EXTRACT_SEM.acquire(blocking=False):
                self.send_response(429)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Retry-After", "5")
                self.end_headers()
                self.wfile.write(b"Too many concurrent extractions")
                return

            try:
                response = run_extraction(parsed, filter_mode, time_before, time_after)
                log.info(f"Response: {response}")
            finally:
                _EXTRACT_SEM.release()

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Result", response or "EMPTY")
            self.end_headers()
            self.wfile.write(response.encode())

        except json.JSONDecodeError as e:
            log.error(f"Invalid JSON (len={len(body)}): {e}")
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
        except Exception as e:
            log.error(f"Error: {e}")
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(str(e).encode())

    def do_GET(self):
        """Health check / help"""
        if not check_basic_auth(self.headers, AUTH_USER, AUTH_PASS):
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.send_header('WWW-Authenticate', 'Basic realm="pcap-extractor"')
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return

        help_text = {
            "status": "ok",
            "usage": {
                "endpoint": "POST /extract?filter=MODE&before=SEC&after=SEC",
                "filter_modes": {
                    "full": "client IP + server IP + port (default)",
                    "hosts": "client IP + server IP",
                    "client": "only client IP",
                    "server": "only server IP",
                    "port": "server IP + port",
                },
                "defaults": {
                    "filter": DEFAULT_FILTER,
                    "before": DEFAULT_BEFORE,
                    "after": DEFAULT_AFTER,
                },
            },
            "examples": [
                f"http://HOST:{PORT}/extract?filter=full&before=30&after=60",
                f"http://HOST:{PORT}/extract?filter=hosts&before=60&after=120",
                f"http://HOST:{PORT}/extract?filter=server&before=10&after=30",
            ],
        }

        payload = json.dumps(help_text, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not os.path.isdir(TIMELINE_DIR):
        log.error(f"Timeline dir not found: {TIMELINE_DIR}")
    log.info(f"Timeline dir: {TIMELINE_DIR}")
    log.info(f"Output dir: {OUTPUT_DIR}")
    log.info(f"File server: {FILE_SERVER_URL}")
    log.info(
        f"Defaults: filter={DEFAULT_FILTER}, before={DEFAULT_BEFORE}s, after={DEFAULT_AFTER}s"
    )
    log.info(f"Max concurrent extractions: {MAX_CONCURRENT}")
    log.info(f"Listening on port {PORT}...")

    server = ThreadingHTTPServer(("0.0.0.0", PORT), WebhookHandler)
    server.serve_forever()
