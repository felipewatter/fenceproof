"""FenceProof CLI; default is conservative (fail on high-severity findings)."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from .engine import AnalysisLimitError, check, diff
from .parser import PolicyError, load_policy, parse_flow
from .report import to_sarif, to_text


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fenceproof", description="Offline ACL verifier (no network access)")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check", help="Inspect policy and verify its security assertions")
    c.add_argument("--policy", required=True)
    c.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    c.add_argument("--output", help="Write output to file instead of stdout")
    c.add_argument("--fail-on", choices=("high", "medium", "low", "none"), default="high")
    c.add_argument("--max-fragments", type=int, default=10000)
    d = sub.add_parser("diff", help="Exact effective allow-set difference between policies")
    d.add_argument("--before", required=True)
    d.add_argument("--after", required=True)
    d.add_argument("--format", choices=("text", "json"), default="text")
    d.add_argument("--output")
    d.add_argument("--max-fragments", type=int, default=10000)
    d.add_argument("--samples", type=int, default=20)
    d.add_argument("--fail-on-change", action="store_true")
    s = sub.add_parser("simulate", help="Simulate an exact packet in the documented stateless model")
    s.add_argument("--policy", required=True)
    s.add_argument("--src", required=True)
    s.add_argument("--dst", required=True)
    s.add_argument("--protocol", required=True, choices=("tcp", "udp", "icmp"))
    s.add_argument("--port", type=int, required=True)
    s.add_argument("--format", choices=("text", "json"), default="text")
    return p


def _emit(result: dict, mode: str, output: str | None) -> None:
    content = (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)
               if mode in ("json", "sarif") else to_text(result)) + "\n"
    if output:
        Path(output).write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "check":
            policy = load_policy(args.policy)
            result = check(policy, args.max_fragments)
            result["input_sha256"] = hashlib.sha256(Path(args.policy).read_bytes()).hexdigest()
            _emit(to_sarif(result, args.policy) if args.format == "sarif" else result,
                  args.format, args.output)
            thresholds = {"high": ("high",), "medium": ("high", "medium"),
                          "low": ("high", "medium", "low"), "none": ()}
            return 2 if any(f["severity"] in thresholds[args.fail_on] for f in result["findings"]) else 0
        if args.command == "diff":
            if not 0 <= args.samples <= 1000:
                raise PolicyError("--samples must be in [0, 1000]")
            result = diff(load_policy(args.before), load_policy(args.after), args.max_fragments, args.samples)
            result["before_sha256"] = hashlib.sha256(Path(args.before).read_bytes()).hexdigest()
            result["after_sha256"] = hashlib.sha256(Path(args.after).read_bytes()).hexdigest()
            _emit(result, args.format, args.output)
            return 2 if result["changed"] and args.fail_on_change else 0
        if args.command == "simulate":
            policy = load_policy(args.policy)
            flow = parse_flow({"src": args.src, "dst": args.dst, "protocol": args.protocol, "port": args.port})
            decision, matched = policy.decide(flow)
            _emit({"policy": policy.name, "flow": flow.as_dict(), "decision": decision,
                   "matched_rule": matched, "default_used": matched is None}, args.format, None)
            return 0
        return 1
    except (OSError, PolicyError, ValueError) as exc:
        print(f"fenceproof: invalid input: {exc}", file=sys.stderr)
        return 1
    except AnalysisLimitError as exc:
        print(f"fenceproof: INCONCLUSIVE: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
