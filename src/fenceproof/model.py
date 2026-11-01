"""Small, explicit data model for ordered L3/L4 firewall policies."""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from typing import Literal

Action = Literal["allow", "deny"]
Protocol = Literal["tcp", "udp", "icmp"]
Network = IPv4Network | IPv6Network
Address = IPv4Address | IPv6Address


@dataclass(frozen=True, order=True)
class Interval:
    low: int
    high: int

    def __post_init__(self) -> None:
        if self.low < 0 or self.high < self.low:
            raise ValueError("invalid closed interval")

    def intersect(self, other: Interval) -> Interval | None:
        lo, hi = max(self.low, other.low), min(self.high, other.high)
        return Interval(lo, hi) if lo <= hi else None

    @property
    def size(self) -> int:
        return self.high - self.low + 1


@dataclass(frozen=True)
class Box:
    """A Cartesian product of source, destination and destination port."""
    family: int
    protocol: Protocol
    src: Interval
    dst: Interval
    port: Interval

    @property
    def volume(self) -> int:
        return self.src.size * self.dst.size * self.port.size

    def intersection(self, other: Box) -> Box | None:
        if self.family != other.family or self.protocol != other.protocol:
            return None
        src = self.src.intersect(other.src)
        dst = self.dst.intersect(other.dst)
        port = self.port.intersect(other.port)
        return Box(self.family, self.protocol, src, dst, port) if src and dst and port else None

    def subtract(self, other: Box) -> list[Box]:
        """Exact disjoint decomposition of self \\ other, with <= 6 boxes."""
        overlap = self.intersection(other)
        if overlap is None:
            return [self]
        pieces: list[Box] = []
        center = self
        for axis in ("src", "dst", "port"):
            original: Interval = getattr(center, axis)
            cut: Interval = getattr(overlap, axis)
            if original.low < cut.low:
                args = {"family": center.family, "protocol": center.protocol,
                        "src": center.src, "dst": center.dst, "port": center.port}
                args[axis] = Interval(original.low, cut.low - 1)
                pieces.append(Box(**args))
            if cut.high < original.high:
                args = {"family": center.family, "protocol": center.protocol,
                        "src": center.src, "dst": center.dst, "port": center.port}
                args[axis] = Interval(cut.high + 1, original.high)
                pieces.append(Box(**args))
            args = {"family": center.family, "protocol": center.protocol,
                    "src": center.src, "dst": center.dst, "port": center.port}
            args[axis] = cut
            center = Box(**args)
        return pieces


@dataclass(frozen=True)
class Rule:
    id: str
    action: Action
    src: Network
    dst: Network
    protocol: str
    ports: tuple[Interval, ...]

    def boxes(self) -> tuple[Box, ...]:
        family = self.src.version
        src = Interval(int(self.src.network_address), int(self.src.broadcast_address))
        dst = Interval(int(self.dst.network_address), int(self.dst.broadcast_address))
        protocols = ("tcp", "udp", "icmp") if self.protocol == "any" else (self.protocol,)
        result: list[Box] = []
        for proto in protocols:
            intervals = (Interval(0, 0),) if proto == "icmp" else self.ports
            for port in intervals:
                result.append(Box(family, proto, src, dst, port))  # type: ignore[arg-type]
        return tuple(result)


@dataclass(frozen=True)
class Flow:
    src: Address
    dst: Address
    protocol: Protocol
    port: int

    def as_dict(self) -> dict[str, str | int]:
        return {"src": str(self.src), "dst": str(self.dst), "protocol": self.protocol,
                "port": self.port}


@dataclass(frozen=True)
class Assertion:
    id: str
    flow: Flow
    expect: Action


@dataclass(frozen=True)
class Policy:
    name: str
    default_action: Action
    rules: tuple[Rule, ...]
    assertions: tuple[Assertion, ...] = ()

    def decide(self, flow: Flow) -> tuple[Action, str | None]:
        for rule in self.rules:
            if (flow.src.version == rule.src.version == flow.dst.version
                    and flow.src in rule.src and flow.dst in rule.dst
                    and (rule.protocol == "any" or rule.protocol == flow.protocol)
                    and (flow.protocol == "icmp" or any(p.low <= flow.port <= p.high for p in rule.ports))):
                return rule.action, rule.id
        return self.default_action, None
