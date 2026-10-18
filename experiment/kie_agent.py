"""Laboratory-only NF-co-located KIE signer.

The agent shares the NF network namespace but is NOT a native 3GPP NF or
an Open5GS modification. It signs its OWN challenge receipt counter; it
does not have access to the NF's internal signaling counters.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

NODE = os.environ["KIE_NODE"]
NF_IP = os.environ["KIE_NF_IP"]
MASTER_KEY = bytes.fromhex(os.environ["KIE_TEST_KEY"])
KEY = hmac.new(MASTER_KEY, NODE.encode(), hashlib.sha256).digest()
PORT = 18080
MAX_SKEW = 60.0
MAX_BODY = 4096
MODE_FILE = Path("/tmp/kie-spoof")
LOCK = threading.Lock()
STATE = {"seq": -1, "nonces": set(), "count": 0, "last_honest": 0}


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def mac(obj: dict) -> str:
    return hmac.new(KEY, canonical(obj), hashlib.sha256).hexdigest()


def verify_challenge(challenge: dict, now: float) -> bool:
    if not isinstance(challenge, dict):
        return False
    supplied = challenge.get("mac")
    base = {k: v for k, v in challenge.items() if k != "mac"}
    if set(base) != {"node", "seq", "nonce", "ts"}:
        return False
    if (not isinstance(base["nonce"], str) or len(base["nonce"]) != 32 or
        not isinstance(base["seq"], int) or isinstance(base["seq"], bool) or
        not isinstance(base["ts"], (int, float)) or
        abs(now - base["ts"]) > MAX_SKEW or base["node"] != NODE or
        not isinstance(supplied, str)):
        return False
    if not hmac.compare_digest(mac(base), supplied):
        return False
    with LOCK:
        if base["seq"] <= STATE["seq"] or base["nonce"] in STATE["nonces"]:
            return False
        STATE["seq"] = base["seq"]
        STATE["nonces"].add(base["nonce"])
        STATE["count"] += 1
    return True


def local_nf_port_open() -> int:
    try:
        with socket.create_connection((NF_IP, 7777), timeout=0.3):
            return 1
    except OSError:
        return 0


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        # Never log secrets, challenge content or subscriber information.
        pass

    def do_GET(self) -> None:
        if self.path != "/ready":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self) -> None:
        if self.path != "/kie/v1/challenge":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 2 or length > MAX_BODY:
                self.send_error(413)
                return
            msg = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self.send_error(400)
            return
        if not verify_challenge(msg, time.time()):
            self.send_error(403)
            return
        local_up = local_nf_port_open()
        is_spoof = MODE_FILE.exists()
        with LOCK:
            count = int(STATE["count"])
            if not is_spoof:
                STATE["last_honest"] = count
            claimed = STATE["last_honest"] if is_spoof else count
        # Integrity invariant stays consistent even during dishonest reporting.
        # Independent challenge count and signed claimed count now disagree.
        # Benign delay-only is a negative control: RTT alone is not attack.
        if is_spoof or Path("/tmp/kie-delay-only").exists():
            time.sleep(0.12)
        reply = {
            "node": NODE,
            "seq": msg["seq"],
            "nonce": msg["nonce"],
            "ts": time.time(),
            "local_port_open": local_up,
            "claimed_received": claimed,
            "claimed_components": {"accepted": claimed, "rejected": 0},
        }
        reply["mac"] = mac(reply)
        data = canonical(reply)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
