import itertools
import random
import unittest
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from fenceproof.engine import AnalysisLimitError, OperationBudget, check, diff, effective_policy, subtract_many
from fenceproof.model import Box, Flow, Interval
from fenceproof.parser import load_policy, parse_policy

ROOT = Path(__file__).resolve().parents[1]


class BoxTests(unittest.TestCase):
    def test_subtraction_exact_exhaustive_small_boxes(self):
        def points(b):
            return set(itertools.product(range(b.src.low,b.src.high+1),
                                        range(b.dst.low,b.dst.high+1),
                                        range(b.port.low,b.port.high+1)))
        for s in range(3):
            for d in range(3):
                for p in range(3):
                    original = Box(4, "tcp", Interval(0, 2), Interval(0, 2), Interval(1, 3))
                    cut = Box(4, "tcp", Interval(s, s+1), Interval(d, d+1), Interval(p+1, p+2))
                    pieces = original.subtract(cut)
                    actual = [item for part in pieces for item in points(part)]
                    self.assertEqual(len(actual), len(set(actual)), "overlapping fragments")
                    self.assertEqual(set(actual), points(original) - points(cut))

    def test_no_overlap_different_protocol_or_family(self):
        a = Box(4, "tcp", Interval(0,5), Interval(0,5), Interval(1,3))
        for b in (Box(4,"udp",a.src,a.dst,a.port), Box(6,"tcp",a.src,a.dst,a.port)):
            self.assertEqual(a.subtract(b), [a])

    def test_operation_guard(self):
        box = Box(4, "tcp", Interval(0,10),Interval(0,10),Interval(1,10))
        cuts = [Box(4,"tcp",Interval(20+i,20+i),Interval(20,20),Interval(1,10)) for i in range(5)]
        with self.assertRaisesRegex(AnalysisLimitError, "operation budget"):
            subtract_many([box], cuts, 100, OperationBudget(maximum=3))

    def test_resource_guard(self):
        base = Box(4,"tcp",Interval(0,500),Interval(0,500),Interval(1,500))
        cuts = [Box(4,"tcp",Interval(i,i),Interval(0,500),Interval(1,500)) for i in range(0,500,2)]
        with self.assertRaises(AnalysisLimitError): subtract_many([base], cuts, 100)


class EngineTests(unittest.TestCase):
    def test_secure_clean(self):
        result = check(load_policy(ROOT/"examples/secure-policy.json"))
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["summary"]["assertions_passed"], 4)

    def test_risky_findings(self):
        report = check(load_policy(ROOT/"examples/risky-policy.json"))
        self.assertEqual({r["id"] for r in report["findings"]}, {"FP002", "FP004", "FP005"})

    def test_union_shadow_exact(self):
        report = check(load_policy(ROOT/"examples/union-shadow.json"))
        self.assertEqual([(f["id"],f["rule_id"]) for f in report["findings"]], [("FP002", "never-reached")])

    def test_partial_shadow(self):
        p = self._make([("deny", "10.0.0.0/25"), ("allow", "10.0.0.0/24")])
        report = check(p)
        self.assertIn("FP003", [f["id"] for f in report["findings"]])

    def test_default_allow_alert(self):
        data = {"version":1,"name":"default-allow","default_action":"allow","rules":[]}
        report = check(parse_policy(data))
        self.assertEqual(report["findings"][0]["id"], "FP001")

    def test_decision_first_match(self):
        p = self._make([("deny", "10.0.0.0/25"), ("allow", "10.0.0.0/24")])
        self.assertEqual(p.decide(Flow(IPv4Address("10.0.0.3"),IPv4Address("192.0.2.10"),"tcp",443))[0], "deny")
        self.assertEqual(p.decide(Flow(IPv4Address("10.0.0.200"),IPv4Address("192.0.2.10"),"tcp",443))[0], "allow")

    def test_diff_witness(self):
        a,b = (load_policy(ROOT/"examples"/x) for x in ("secure-policy.json", "risky-policy.json"))
        result = diff(a,b)
        self.assertTrue(result["changed"])
        self.assertGreater(result["summary"]["newly_allowed_regions"],0)
        self.assertEqual(result["summary"]["newly_denied_regions"], 0)
        for c in result["changes"]:
            f = c["witness"]
            packet = Flow(IPv4Address(f["src"]) if ":" not in f["src"] else IPv6Address(f["src"]),
                          IPv4Address(f["dst"]) if ":" not in f["dst"] else IPv6Address(f["dst"]),
                          f["protocol"],f["port"])
            self.assertEqual(a.decide(packet)[0], "deny")
            self.assertEqual(b.decide(packet)[0], "allow")

    def test_diff_same_effective_policy_even_if_shadow_rules_added(self):
        before = self._make([("deny", "10.0.0.0/24"), ("allow", "10.0.0.0/24")])
        after = self._make([("deny", "10.0.0.0/24")])
        self.assertFalse(diff(before,after)["changed"])

    def test_ipv6_diff_and_witness(self):
        data = {"version":1,"name":"v6","default_action":"deny","rules":
                [{"id":"v6allow","action":"allow","src":"2001:db8::/126","dst":"2001:db8:1::/126","protocol":"icmp"}]}
        new = parse_policy(data)
        old = parse_policy({"version":1,"name":"before","default_action":"deny","rules":[]})
        r = diff(old,new)
        self.assertTrue(r["changed"])
        self.assertEqual(r["changes"][0]["witness"]["port"],0)
        self.assertIn(":",r["changes"][0]["witness"]["src"])

    def test_default_allow_diff(self):
        a = parse_policy({"version":1,"name":"a","default_action":"deny","rules":[]})
        b = parse_policy({"version":1,"name":"b","default_action":"allow","rules":[]})
        result = diff(a,b)
        self.assertEqual(result["summary"]["newly_allowed_regions"],6)

    def test_budget_validation(self):
        with self.assertRaises(ValueError): effective_policy(self._make([]), 99)

    @staticmethod
    def _make(rules):
        return parse_policy({"version":1,"name":"test","default_action":"deny","rules": [
            {"id":f"r{i}","action":action,"src":src,"dst":"192.0.2.10/32","protocol":"tcp","ports":[443]}
            for i,(action,src) in enumerate(rules)]})

    def test_randomized_shadow_vs_packet_oracle(self):
        """Validate symbolic shadow diagnosis against independent finite-space enumeration."""
        rng = random.Random(91931)
        sources = ("10.0.0.0/30", "10.0.0.0/31", "10.0.0.2/31", "10.0.0.0/32", "10.0.0.1/32",
                   "10.0.0.2/32", "10.0.0.3/32")
        destination = IPv4Address("192.0.2.10")
        for case in range(80):
            entries = [{"id":f"r{i}","action":rng.choice(("allow","deny")), "src":rng.choice(sources),
                        "dst":"192.0.2.10/32", "protocol":"tcp", "ports":[rng.randint(1,3)]}
                       for i in range(rng.randrange(1,7))]
            policy = parse_policy({"version":1,"name":"oracle","default_action":"deny","rules":entries})
            report = check(policy)
            actual = {(f["id"],f["rule_id"]) for f in report["findings"] if f["id"] in ("FP002","FP003")}
            expected = set()
            for i,rule in enumerate(policy.rules):
                applicable = [Flow(IPv4Address(f"10.0.0.{s}"),destination,"tcp",port)
                              for s in range(4) for port in range(1,4)
                              if IPv4Address(f"10.0.0.{s}") in rule.src and
                                 any(v.low<=port<=v.high for v in rule.ports)]
                reachable = [f for f in applicable if not any(
                    f.src in prev.src and f.dst in prev.dst and
                    any(v.low<=f.port<=v.high for v in prev.ports)
                    for prev in policy.rules[:i])]
                if not reachable:
                    expected.add(("FP002",rule.id))
                elif len(reachable)<len(applicable):
                    expected.add(("FP003",rule.id))
            with self.subTest(case=case):
                self.assertEqual(actual,expected)

    def test_randomized_diff_vs_bruteforce(self):
        """Differential oracle: exact symbolic reachability vs finite packet enumeration."""
        randomizer = random.Random(73019)
        cidrs = ("10.0.0.0/30", "10.0.0.0/31", "10.0.0.2/31", "10.0.0.0/32",
                 "10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32")
        def rand_policy(name):
            rules = []
            for i in range(randomizer.randrange(6)):
                rules.append({"id":f"r{i}","action":randomizer.choice(("allow","deny")),
                              "src":randomizer.choice(cidrs),"dst":randomizer.choice(("192.0.2.0/31","192.0.2.2/31","192.0.2.0/30")),
                              "protocol":randomizer.choice(("tcp","udp")),"ports": [randomizer.choice((1,2,3))]})
            return parse_policy({"version":1,"name":name,"default_action":"deny","rules":rules})
        for i in range(80):
            a,b = rand_policy("before"),rand_policy("after")
            expected = any(a.decide(Flow(IPv4Address(f"10.0.0.{src}"),IPv4Address(f"192.0.2.{dst}"),proto,port))[0] !=
                           b.decide(Flow(IPv4Address(f"10.0.0.{src}"),IPv4Address(f"192.0.2.{dst}"),proto,port))[0]
                           for src,dst,proto,port in itertools.product(range(4),range(4),("tcp","udp"),(1,2,3)))
            with self.subTest(case=i):
                self.assertEqual(diff(a,b)["changed"], expected)


if __name__=='__main__': unittest.main()
