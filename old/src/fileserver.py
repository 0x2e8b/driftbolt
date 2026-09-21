#!/usr/bin/env python3
"""Sycope Traffic Recorder — HTTP file server for extracted PCAPs"""

import ipaddress
from functools import partial
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import os

from config_loader import check_basic_auth, load_config

_config = load_config()
PCAP_DIR = _config["output_dir"]
PORT = _config["fileserver_port"]
AUTH_USER = _config.get("fileserver_auth_user", "")
AUTH_PASS = _config.get("fileserver_auth_pass", "")
ALLOWED_IPS = _config.get("allowed_ips", [])


def _build_allowed_networks(values):
    networks = []
    for raw in values:
        try:
            networks.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            print(f"Invalid allowed_ips entry ignored: {raw}")
    return networks


ALLOWED_NETWORKS = _build_allowed_networks(ALLOWED_IPS)


def is_ip_allowed(client_ip):
    if not ALLOWED_NETWORKS:
        return True
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    return any(addr in net for net in ALLOWED_NETWORKS)


class PcapRequestHandler(SimpleHTTPRequestHandler):
    def _reject(self, code, message):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(message.encode())))
        self.end_headers()
        self.wfile.write(message.encode())

    def _check_access(self):
        if not check_basic_auth(self.headers, AUTH_USER, AUTH_PASS):
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.send_header('WWW-Authenticate', 'Basic realm="pcap-files"')
            self.send_header("Content-Length", str(len(b"Unauthorized")))
            self.end_headers()
            self.wfile.write(b"Unauthorized")
            return False

        client_ip = self.client_address[0]
        if not is_ip_allowed(client_ip):
            self._reject(403, "Forbidden")
            return False

        return True

    def do_GET(self):
        if not self._check_access():
            return
        super().do_GET()

    def do_HEAD(self):
        if not self._check_access():
            return
        super().do_HEAD()

    def list_directory(self, path):
        self._reject(403, "Directory listing disabled")
        return None

handler = partial(PcapRequestHandler, directory=PCAP_DIR)

if not os.path.isdir(PCAP_DIR):
    print(f"WARNING: PCAP dir does not exist: {PCAP_DIR}")
print(f"Serving {PCAP_DIR} on http://0.0.0.0:{PORT}")
if AUTH_USER or AUTH_PASS:
    print("Basic auth: enabled")
else:
    print("Basic auth: disabled")
if ALLOWED_NETWORKS:
    print(f"IP allowlist: {', '.join(str(n) for n in ALLOWED_NETWORKS)}")
else:
    print("IP allowlist: disabled")
ThreadingHTTPServer(("0.0.0.0", PORT), handler).serve_forever()
