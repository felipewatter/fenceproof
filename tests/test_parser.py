import json
import tempfile
import unittest
from pathlib import Path

from fenceproof.parser import PolicyError, load_policy, parse_flow, parse_policy


def policy(**kw):
    return {"version": 1, "name": "test", "default_action": "deny", "rules": [], **kw}


def rule(**kw):
    return {"id": "ruleA", "action": "allow", "src": "10.0.0.0/24",
            "dst": "192.0.2.0/24", "protocol": "tcp", "ports": [443], **kw}


class ParserTests(unittest.TestCase):
    def test_minimal(self):
        self.assertEqual(parse_policy(policy()).rules, ())

    def test_canonical_ports_merge(self):
        p = policy()
        p["rules"] = [rule()]
        p["rules"][0]["ports"] = [[10, 12], 9, [12, 15], 443]
        self.assertEqual([(v.low, v.high) for v in parse_policy(p).rules[0].ports], [(9, 15), (443, 443)])

    def test_network_host_bits_rejected(self):
        p = policy(); p["rules"] = [rule()]; p["rules"][0]["src"] = "10.0.0.1/24"
        with self.assertRaises(PolicyError): parse_policy(p)

    def test_mixed_families_rejected(self):
        p = policy(); p["rules"] = [rule()]; p["rules"][0]["src"] = "::/0"
        with self.assertRaises(PolicyError): parse_policy(p)

    def test_duplicate_rule_id_rejected(self):
        p = policy(); p["rules"] = [rule(), rule()]
        with self.assertRaisesRegex(PolicyError, "duplicate rule"): parse_policy(p)

    def test_any_protocol_cannot_restrict_ports(self):
        p = policy(); p["rules"] = [rule()]; p["rules"][0]["protocol"] = "any"
        with self.assertRaises(PolicyError): parse_policy(p)

    def test_icmp_cannot_restrict_ports(self):
        p = policy(); p["rules"] = [rule()]; p["rules"][0]["protocol"] = "icmp"
        with self.assertRaises(PolicyError): parse_policy(p)

    def test_boolean_port_rejected(self):
        p = policy(); p["rules"] = [rule()]; p["rules"][0]["ports"] = [True]
        with self.assertRaises(PolicyError): parse_policy(p)

    def test_unknown_field_rejected(self):
        p = policy(); p["dangerous"] = 1
        with self.assertRaisesRegex(PolicyError, "unknown keys"): parse_policy(p)

    def test_invalid_assertion_rejected(self):
        p = policy(); p["assertions"] = [{"id": "a", "flow": {"src": "1.1.1.1", "dst": "2.2.2.2", "protocol": "icmp", "port": 4}, "expect": "deny"}]
        with self.assertRaises(PolicyError): parse_policy(p)

    def test_duplicate_json_object_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"p.json"
            path.write_text('{"version":1,"version":1,"name":"p","default_action":"deny","rules":[]}', encoding="utf-8")
            with self.assertRaisesRegex(PolicyError, "duplicate JSON"): load_policy(path)

    def test_oversized_input_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"p.json"; path.write_bytes(b" "*1_048_577)
            with self.assertRaisesRegex(PolicyError, "exceeds"): load_policy(path)

    def test_reject_nonstandard_nan(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"p.json"
            path.write_text('{"version":1,"name":"p","default_action":"deny","rules":[], "assertions": NaN}')
            with self.assertRaisesRegex(PolicyError, "invalid constant"): load_policy(path)

    def test_flow_ipv6(self):
        flow = parse_flow({"src": "2001:db8::1", "dst": "2001:db8::2", "protocol": "icmp", "port": 0})
        self.assertEqual(flow.src.version, 6)

    def test_invalid_versions(self):
        for version in (True, 0, 2, "1"):
            p = policy(); p["version"] = version
            with self.subTest(version=version), self.assertRaises(PolicyError): parse_policy(p)

    def test_max_rules(self):
        p = policy(); p["rules"] = [rule()]*501
        with self.assertRaises(PolicyError): parse_policy(p)


if __name__ == '__main__': unittest.main()
