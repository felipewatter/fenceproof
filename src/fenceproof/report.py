"""Deterministic, minimal SARIF 2.1.0 and human-readable reports."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

RULES = {
    "FP001": ("Unsafe default action", "error"),
    "FP002": ("Fully shadowed rule", "warning"),
    "FP003": ("Partially shadowed rule", "note"),
    "FP004": ("Publicly reachable administrative TCP port", "error"),
    "FP005": ("Failed policy assertion", "error"),
}


def to_sarif(report: dict, input_file: str) -> dict:
    target = Path(input_file).resolve()
    try:
        path = target.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        path = target.name
    results = []
    for finding in report["findings"]:
        code = finding["id"]
        evidence = finding.get("evidence", {})
        stable = json.dumps([code, finding.get("rule_id"), evidence], sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(stable.encode()).hexdigest()
        results.append({
            "ruleId": code,
            "level": RULES[code][1],
            "message": {"text": finding["message"] + (f" Rule: {finding['rule_id']}." if finding["rule_id"] else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}}}],
            "partialFingerprints": {"fenceproof/v1": digest[:32]},
            "properties": {"evidence": evidence, "rule_id": finding["rule_id"] or ""},
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "FenceProof", "version": "1.0.0",
                       "informationUri": "https://github.com/felipewatter/fenceproof",
                       "rules": [{"id": code, "name": item[0],
                                  "shortDescription": {"text": item[0]}}
                                 for code, item in RULES.items()]}},
                      "results": results}]}


def to_text(report: dict) -> str:
    if "findings" in report:
        stats = report["summary"]
        lines = [f"FenceProof | {report['policy']} | {report['status']}",
                 f"Rules: {stats['rules']} | Assertions: {stats['assertions_passed']}/{stats['assertions_total']}"]
        for f in report["findings"]:
            lines.append(f"[{f['severity'].upper()}] {f['id']}" +
                         (f" ({f['rule_id']})" if f["rule_id"] else "") + f": {f['message']}")
        if not report["findings"]:
            lines.append("No findings within the modeled checks. This is not a security certification.")
        return "\n".join(lines)
    if "changes" in report:
        lines = [f"FenceProof diff | {report['before']} -> {report['after']}",
                 f"Changed: {report['changed']} | Newly allowed segments: {report['summary']['newly_allowed_regions']} | Newly denied segments: {report['summary']['newly_denied_regions']}"]
        for sample in report["changes"]:
            lines.append(f"  {sample['change']}: {sample['witness']}")
        return "\n".join(lines)
    return json.dumps(report, sort_keys=True, indent=2)
