"""Strict, bounded JSON decoder; never deserializes executable objects."""
from __future__ import annotations

import json
import re
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

from .model import Assertion, Flow, Interval, Policy, Rule

MAX_BYTES = 1_048_576
MAX_RULES = 500
MAX_ASSERTIONS = 1000
IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


class PolicyError(ValueError):
    pass


def _fail(where: str, message: str) -> None:
    raise PolicyError(f"{where}: {message}")


def _object(value: Any, where: str, required: set[str], optional: set[str] = set()) -> dict:
    if not isinstance(value, dict):
        _fail(where, "expected an object")
    missing, extra = required - value.keys(), value.keys() - (required | optional)
    if missing:
        _fail(where, f"missing keys: {', '.join(sorted(missing))}")
    if extra:
        _fail(where, f"unknown keys: {', '.join(sorted(extra))}")
    return value


def _str(value: Any, where: str) -> str:
    if not isinstance(value, str):
        _fail(where, "expected a string")
    return value


def _id(value: Any, where: str) -> str:
    result = _str(value, where)
    if not IDENTIFIER.fullmatch(result):
        _fail(where, "must match ^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
    return result


def _action(value: Any, where: str) -> str:
    if value not in ("allow", "deny") or not isinstance(value, str):
        _fail(where, "expected 'allow' or 'deny'")
    return value


def _network(value: Any, where: str):
    item = _str(value, where)
    aliases = {"any4": "0.0.0.0/0", "any6": "::/0"}
    try:
        return ip_network(aliases.get(item, item), strict=True)
    except ValueError as exc:
        _fail(where, f"invalid canonical CIDR: {exc}")


def _flow(obj: Any, where: str) -> Flow:
    data = _object(obj, where, {"src", "dst", "protocol", "port"})
    try:
        src = ip_address(_str(data["src"], where + ".src"))
        dst = ip_address(_str(data["dst"], where + ".dst"))
    except ValueError as exc:
        _fail(where, f"invalid IP address: {exc}")
    if src.version != dst.version:
        _fail(where, "mixed IP families are not supported")
    proto = _str(data["protocol"], where + ".protocol")
    if proto not in ("tcp", "udp", "icmp"):
        _fail(where, "protocol must be tcp, udp or icmp")
    port = data["port"]
    if type(port) is not int or not (0 <= port <= 65535):
        _fail(where, "port must be an integer in [0, 65535]")
    if (proto == "icmp") != (port == 0):
        _fail(where, "ICMP requires port=0; TCP/UDP require port>=1")
    return Flow(src, dst, proto, port)


def _ports(value: Any, where: str, protocol: str) -> tuple[Interval, ...]:
    if protocol in ("any", "icmp"):
        if value is not None:
            _fail(where, "ports are only allowed for tcp/udp")
        return (Interval(1, 65535),)
    if value is None:
        return (Interval(1, 65535),)
    if not isinstance(value, list) or not 1 <= len(value) <= 128:
        _fail(where, "ports must be an array containing 1..128 port numbers/ranges")
    parts = []
    for i, item in enumerate(value):
        if type(item) is int:
            low = high = item
        elif isinstance(item, list) and len(item) == 2 and all(type(v) is int for v in item):
            low, high = item
        else:
            _fail(f"{where}[{i}]", "expected integer or [start, end]")
        if not 1 <= low <= high <= 65535:
            _fail(f"{where}[{i}]", "invalid TCP/UDP port range")
        parts.append(Interval(low, high))
    parts.sort()
    merged: list[Interval] = []
    for part in parts:
        if merged and part.low <= merged[-1].high + 1:
            merged[-1] = Interval(merged[-1].low, max(merged[-1].high, part.high))
        else:
            merged.append(part)
    return tuple(merged)


def parse_policy(data: Any) -> Policy:
    obj = _object(data, "policy", {"version", "name", "default_action", "rules"}, {"assertions"})
    if type(obj["version"]) is not int or obj["version"] != 1:
        _fail("policy.version", "only version 1 is supported")
    name = _id(obj["name"], "policy.name")
    action = _action(obj["default_action"], "policy.default_action")
    raw_rules = obj["rules"]
    if not isinstance(raw_rules, list) or len(raw_rules) > MAX_RULES:
        _fail("policy.rules", f"expected <= {MAX_RULES} rules")
    rules, ids = [], set()
    for i, item in enumerate(raw_rules):
        where = f"policy.rules[{i}]"
        r = _object(item, where, {"id", "action", "src", "dst", "protocol"}, {"ports"})
        rid = _id(r["id"], where + ".id")
        if rid in ids:
            _fail(where, f"duplicate rule id '{rid}'")
        ids.add(rid)
        src, dst = _network(r["src"], where + ".src"), _network(r["dst"], where + ".dst")
        if src.version != dst.version:
            _fail(where, "source/destination IP families must match")
        proto = _str(r["protocol"], where + ".protocol")
        if proto not in ("any", "tcp", "udp", "icmp"):
            _fail(where, "protocol must be any, tcp, udp or icmp")
        ports = _ports(r.get("ports"), where + ".ports", proto)
        rules.append(Rule(rid, _action(r["action"], where + ".action"), src, dst, proto, ports))
    raw_assertions = obj.get("assertions", [])
    if not isinstance(raw_assertions, list) or len(raw_assertions) > MAX_ASSERTIONS:
        _fail("policy.assertions", f"expected <= {MAX_ASSERTIONS} assertions")
    assertions, assertion_ids = [], set()
    for i, item in enumerate(raw_assertions):
        where = f"policy.assertions[{i}]"
        a = _object(item, where, {"id", "flow", "expect"})
        aid = _id(a["id"], where + ".id")
        if aid in assertion_ids:
            _fail(where, f"duplicate assertion id '{aid}'")
        assertion_ids.add(aid)
        assertions.append(Assertion(aid, _flow(a["flow"], where + ".flow"),
                                    _action(a["expect"], where + ".expect")))
    return Policy(name, action, tuple(rules), tuple(assertions))


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON object key: '{key}'")
        result[key] = value
    return result


def load_policy(path: str | Path) -> Policy:
    target = Path(path)
    with target.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise PolicyError(f"policy exceeds {MAX_BYTES} bytes")
    try:
        return parse_policy(json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
                                       parse_constant=lambda n: _fail("json", f"invalid constant: {n}")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"invalid UTF-8 JSON: {exc}") from exc


def parse_flow(data: dict) -> Flow:
    return _flow(data, "flow")
