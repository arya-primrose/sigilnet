"""The "onion" endpoint and credential type: pure formats, no tor process (torlink.py manages tor). Registered with carrier.py on import."""
from __future__ import annotations

import re

from . import carrier

ONION_RE = re.compile(r"[a-z2-7]{56}\.onion")
B32_KEY_RE = re.compile(r"[A-Z2-7]{52}")
DEFAULT_PORT = 47200


def split_addr(addr: str) -> tuple:
    """'<56>.onion:<port>' -> (onion, port); raises ValueError."""
    if not isinstance(addr, str) or not addr.isascii():                # (str.lower() maps some non-ASCII characters, e.g. U+212A KELVIN SIGN, onto ASCII ones: refuse before lowering)
        raise ValueError("an onion endpoint is '<56 base32 characters>.onion:<port>'")
    host, sep, port = addr.lower().partition(":")                      # exact: no stripping (whitespace is refused); case is normalized
    if not sep or not ONION_RE.fullmatch(host) or not re.fullmatch(r"[0-9]{1,5}", port) or not 0 < int(port) < 65536 or port != str(int(port)):
        raise ValueError("an onion endpoint is '<56 base32 characters>.onion:<port>'")
    return host, int(port)


def check_addr(addr: str) -> str:
    host, port = split_addr(addr)
    return f"{host}:{port}"


def check_key(key: str) -> str:
    key = (key or "").strip() if isinstance(key, str) and key.isascii() else ""
    if not B32_KEY_RE.fullmatch(key):
        raise ValueError("an onion client key is 52 characters of base32 (A-Z, 2-7)")
    return key


def endpoint(onion: str, port: int = DEFAULT_PORT) -> dict:
    return carrier.check_endpoint({"type": "onion", "addr": f"{onion}:{port}"})


def parts(ep: dict) -> tuple:
    """endpoint -> (onion, port) for an onion endpoint (anything else: ValueError)."""
    ep = carrier.check_endpoint(ep)
    if ep["type"] != "onion":
        raise ValueError("not an onion endpoint")
    return split_addr(ep["addr"])


carrier.register_type("onion", check_addr=check_addr, check_key=check_key)
