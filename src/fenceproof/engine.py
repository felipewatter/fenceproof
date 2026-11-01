"""Exact, finite-space reachability analysis for the documented stateless ACL model."""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Iterable

from .model import Box, Flow, Interval, Policy

ADMIN_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 3306: "MySQL",
               5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch"}
PUBLIC_SAMPLES = {4: ("1.1.1.1", "8.8.8.8", "9.9.9.9"),
                  6: ("2606:4700:4700::1111", "2001:4860:4860::8888")}
PROTOS = ("tcp", "udp", "icmp")


class AnalysisLimitError(RuntimeError):
    """A resource bound was hit: an incomplete analysis MUST NOT be called PASS."""


@dataclass
class OperationBudget:
    """Shared global work bound: fragmented inputs cannot consume unlimited CPU."""
    maximum: int = 2_000_000
    used: int = 0

    def tick(self) -> None:
        self.used += 1
        if self.used > self.maximum:
            raise AnalysisLimitError(f"operation budget exceeded ({self.maximum}); analysis inconclusive")


def subtract_many(regions: Iterable[Box], cuts: Iterable[Box], limit: int,
                  budget: OperationBudget | None = None) -> list[Box]:
    current = list(regions)
    if len(current) > limit:
        raise AnalysisLimitError(f"fragment budget exceeded ({limit}); analysis inconclusive")
    for cut in cuts:
        following: list[Box] = []
        for region in current:
            if budget is not None:
                budget.tick()
            following.extend(region.subtract(cut))
            if len(following) > limit:
                raise AnalysisLimitError(f"fragment budget exceeded ({limit}); analysis inconclusive")
        current = following
        if not current:
            break
    return current


def _universe(family: int, proto: str) -> Box:
    max_ip = (1 << (32 if family == 4 else 128)) - 1
    port = Interval(0, 0) if proto == "icmp" else Interval(1, 65535)
    return Box(family, proto, Interval(0, max_ip), Interval(0, max_ip), port)  # type: ignore[arg-type]


def witness(box: Box) -> dict[str, str | int]:
    candidate = next((ip for ip in PUBLIC_SAMPLES[box.family]
                      if box.src.low <= int(ip_address(ip)) <= box.src.high), None)
    source = candidate or str(IPv4Address(box.src.low) if box.family == 4 else IPv6Address(box.src.low))
    destination = str(IPv4Address(box.dst.low) if box.family == 4 else IPv6Address(box.dst.low))
    return {"src": source, "dst": destination, "protocol": box.protocol, "port": box.port.low}


@dataclass(frozen=True)
class EffectiveRule:
    id: str
    action: str
    original_volume: int
    effective: tuple[Box, ...]


@dataclass(frozen=True)
class EffectivePolicy:
    rules: tuple[EffectiveRule, ...]
    allowed: tuple[Box, ...]


def effective_policy(policy: Policy, limit: int = 10000,
                     budget: OperationBudget | None = None) -> EffectivePolicy:
    if not 100 <= limit <= 100000:
        raise ValueError("fragment limit must be in [100, 100000]")
    if budget is None:
        budget = OperationBudget()
    seen: list[Box] = []
    allowed: list[Box] = []
    results: list[EffectiveRule] = []
    for rule in policy.rules:
        originals = rule.boxes()
        remaining = subtract_many(originals, seen, limit, budget)
        if len(seen) + len(remaining) > limit:
            raise AnalysisLimitError(f"fragment budget exceeded ({limit}); analysis inconclusive")
        results.append(EffectiveRule(rule.id, rule.action,
                                     sum(box.volume for box in originals), tuple(remaining)))
        seen.extend(remaining)
        if rule.action == "allow":
            allowed.extend(remaining)
    if policy.default_action == "allow":
        for family in (4, 6):
            for proto in PROTOS:
                remaining = subtract_many([_universe(family, proto)], seen, limit, budget)
                if len(allowed) + len(remaining) > limit:
                    raise AnalysisLimitError(f"fragment budget exceeded ({limit}); analysis inconclusive")
                allowed.extend(remaining)
    return EffectivePolicy(tuple(results), tuple(allowed))


def _finding(code: str, severity: str, message: str, rule: str | None = None,
             evidence: dict | None = None) -> dict:
    return {"id": code, "severity": severity, "message": message,
            "rule_id": rule, "evidence": evidence or {}}


def _public_admin(box: Box) -> dict | None:
    if box.protocol != "tcp":
        return None
    for port, service in ADMIN_PORTS.items():
        if box.port.low <= port <= box.port.high:
            for ip in PUBLIC_SAMPLES[box.family]:
                address = int(ip_address(ip))
                if box.src.low <= address <= box.src.high:
                    flow = witness(box)
                    flow["src"] = ip
                    flow["port"] = port
                    return {"service": service, "flow": flow}
    return None


def check(policy: Policy, limit: int = 10000) -> dict:
    effective = effective_policy(policy, limit)
    findings = []
    if policy.default_action == "allow":
        findings.append(_finding("FP001", "high", "Default action is allow (fail-open behavior)."))
    for rule, summary in zip(policy.rules, effective.rules):
        remaining_volume = sum(box.volume for box in summary.effective)
        if remaining_volume == 0:
            findings.append(_finding("FP002", "medium", "Rule is completely unreachable due to prior rules.", rule.id))
        elif remaining_volume < summary.original_volume:
            findings.append(_finding("FP003", "low", "Rule is partially preempted by prior rules.", rule.id))
        if rule.action == "allow" and rule.src.prefixlen == 0:
            for box in summary.effective:
                ev = _public_admin(box)
                if ev:
                    findings.append(_finding("FP004", "high", "Administrative TCP service reachable from a sampled public IP.", rule.id, ev))
                    break
    assertion_passes = 0
    for assertion in policy.assertions:
        actual, matched = policy.decide(assertion.flow)
        if actual != assertion.expect:
            findings.append(_finding("FP005", "high", "Security assertion failed.", None,
                                     {"assertion_id": assertion.id, "expected": assertion.expect,
                                      "actual": actual, "matched_rule": matched,
                                      "flow": assertion.flow.as_dict()}))
        else:
            assertion_passes += 1
    levels = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        levels[finding["severity"]] += 1
    return {"tool": "FenceProof", "policy": policy.name, "status": "complete",
            "summary": {"rules": len(policy.rules), "assertions_passed": assertion_passes,
                        "assertions_total": len(policy.assertions), "findings": levels},
            "findings": findings}


def diff(before: Policy, after: Policy, limit: int = 10000, samples: int = 20) -> dict:
    """Compares effective allowed traffic sets exactly, not via sample-only simulation."""
    budget = OperationBudget()
    base, candidate = effective_policy(before, limit, budget), effective_policy(after, limit, budget)
    changes: list[dict] = []
    totals = {"newly_allowed": 0, "newly_denied": 0}
    for label, source, destination in (("newly_denied", base.allowed, candidate.allowed),
                                       ("newly_allowed", candidate.allowed, base.allowed)):
        for region in source:
            residual = subtract_many([region], destination, limit, budget)
            totals[label] += len(residual)
            for box in residual:
                if len(changes) < samples:
                    changes.append({"change": label, "witness": witness(box)})
    return {"tool": "FenceProof", "status": "complete", "before": before.name,
            "after": after.name, "changed": any(totals.values()),
            "summary": {"newly_allowed_regions": totals["newly_allowed"],
                        "newly_denied_regions": totals["newly_denied"],
                        "witnesses_returned": len(changes), "witness_limit": samples},
            "changes": changes}
