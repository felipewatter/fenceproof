import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fenceproof.cli import main
from fenceproof.engine import check
from fenceproof.parser import load_policy
from fenceproof.report import RULES, to_sarif

ROOT = Path(__file__).resolve().parents[1]


class CliReportTests(unittest.TestCase):
    def run_cli(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = main(args)
        return status, out.getvalue(), err.getvalue()

    def test_check_clean(self):
        code, out, err = self.run_cli(["check","--policy",str(ROOT/"examples/secure-policy.json"),"--format","json"])
        self.assertEqual(code,0,err)
        self.assertEqual(json.loads(out)["summary"]["findings"]["high"],0)

    def test_check_risky_exits_2(self):
        code, out, _ = self.run_cli(["check","--policy",str(ROOT/"examples/risky-policy.json")])
        self.assertEqual(code,2)
        self.assertIn("FP004",out)

    def test_check_risky_threshold_none(self):
        code, _, _ = self.run_cli(["check","--policy",str(ROOT/"examples/risky-policy.json"),"--fail-on","none"])
        self.assertEqual(code,0)

    def test_diff_exit_on_change(self):
        code, out, _ = self.run_cli(["diff","--before",str(ROOT/"examples/secure-policy.json"),
                                     "--after",str(ROOT/"examples/risky-policy.json"),"--fail-on-change"])
        self.assertEqual(code,2)
        self.assertIn("Changed: True",out)

    def test_sarif_minimal_required_fields(self):
        result = to_sarif(check(load_policy(ROOT/"examples/risky-policy.json")), "policy.json")
        self.assertEqual(result["version"],"2.1.0")
        self.assertEqual(result["runs"][0]["tool"]["driver"]["name"],"FenceProof")
        self.assertEqual(len(result["runs"][0]["tool"]["driver"]["rules"]),len(RULES))
        for finding in result["runs"][0]["results"]:
            self.assertIn(finding["ruleId"],RULES)
            self.assertIn("fingerprints",str(finding).lower())

    def test_report_deterministic(self):
        args = ["check","--policy",str(ROOT/"examples/risky-policy.json"),"--format","json"]
        self.assertEqual(self.run_cli(args)[1],self.run_cli(args)[1])

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"result.sarif"
            code, out, _ = self.run_cli(["check","--policy",str(ROOT/"examples/risky-policy.json"),
                                         "--format","sarif","--output",str(path)])
            self.assertEqual(code,2)
            self.assertEqual(out, "")
            self.assertEqual(json.loads(path.read_text())["version"], "2.1.0")

    def test_simulate(self):
        code, out, _ = self.run_cli(["simulate","--policy",str(ROOT/"examples/secure-policy.json"),
                                     "--src","1.1.1.1","--dst","10.20.0.10",
                                     "--protocol","tcp","--port","22","--format","json"])
        self.assertEqual(code,0)
        self.assertEqual(json.loads(out)["decision"], "deny")

    def test_invalid_file_exits_1(self):
        code, _, stderr = self.run_cli(["check","--policy","/no/such/file.json"])
        self.assertEqual(code,1)
        self.assertIn("invalid input",stderr)

    def test_invalid_max_fragments_exits_1(self):
        code, _, stderr = self.run_cli(["check","--policy",str(ROOT/"examples/secure-policy.json"),"--max-fragments","3"])
        self.assertEqual(code,1)
        self.assertIn("fragment limit",stderr)


if __name__ == '__main__': unittest.main()
