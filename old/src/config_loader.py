#!/usr/bin/env python3
"""Sycope Traffic Recorder — shared config loader."""

import base64
import hmac
import json
import os
import sys


def _apply_defaults(config):
    # Backward compatibility for old auth keys
    if "basic_auth_user" in config and "listener_auth_user" not in config:
        config["listener_auth_user"] = config.get("basic_auth_user", "")
    if "basic_auth_pass" in config and "listener_auth_pass" not in config:
        config["listener_auth_pass"] = config.get("basic_auth_pass", "")
    if "basic_auth_user" in config and "fileserver_auth_user" not in config:
        config["fileserver_auth_user"] = config.get("basic_auth_user", "")
    if "basic_auth_pass" in config and "fileserver_auth_pass" not in config:
        config["fileserver_auth_pass"] = config.get("basic_auth_pass", "")

    config.setdefault("listener_auth_user", "")
    config.setdefault("listener_auth_pass", "")
    config.setdefault("fileserver_auth_user", "")
    config.setdefault("fileserver_auth_pass", "")
    config.setdefault("allowed_ips", [])
    return config


def _validate_required(config):
    required = [
        "host",
        "listen_port",
        "fileserver_port",
        "timeline_dir",
        "output_dir",
        "default_filter",
        "default_before",
        "default_after",
    ]
    missing = [k for k in required if k not in config]
    if missing:
        print(f"ERROR: Missing required config keys: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)


def check_basic_auth(headers, user, pwd):
    """Return True if auth is valid or disabled, False otherwise."""
    if not user and not pwd:
        return True
    auth = headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False
    try:
        raw = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        got_user, got_pwd = raw.split(":", 1)
    except Exception:
        return False
    return hmac.compare_digest(got_user, user) and hmac.compare_digest(got_pwd, pwd)


def load_config():
    """Load configuration from config/config.json relative to project root."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config_path = os.path.join(base_dir, "config", "config.json")

    if not os.path.exists(config_path):
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    with open(config_path, "r") as f:
        config = json.load(f)

    config = _apply_defaults(config)
    _validate_required(config)
    return config
