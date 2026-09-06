"""Negative fixtures for the same evidence parser used by required CI."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("go_evidence", Path(__file__).with_name("verify-go-test-evidence.py"))
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)


class RequiredEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "closure_test.go").write_text("package fixture\nfunc TestClosure(t *testing.T) {}\n", encoding="utf-8")
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.required = self.root / "required.txt"
        self.required.write_text("TestClosure\nTestClosure/B1\n", encoding="utf-8")
        self.events = [
            {"Action": "start", "Package": "fixture"},
            {"Action": "run", "Package": "fixture", "Test": "TestClosure"},
            {"Action": "run", "Package": "fixture", "Test": "TestClosure/B1"},
            {"Action": "pass", "Package": "fixture", "Test": "TestClosure/B1"},
            {"Action": "pass", "Package": "fixture", "Test": "TestClosure"},
            {"Action": "pass", "Package": "fixture"},
        ]

    def verify(self, events=None, exact=True):
        selected = self.events if events is None else events
        (self.logs / "test.json").write_text("".join(json.dumps(event) + "\n" for event in selected), encoding="utf-8")
        return EVIDENCE.verify(self.logs, self.source, [self.required], exact)[0]

    def test_complete_execution(self):
        self.assertEqual([], self.verify())

    def test_run_zero(self):
        self.assertTrue(self.verify([self.events[0], self.events[-1]]))

    def test_missing_required_child(self):
        self.assertTrue(self.verify([event for event in self.events if event.get("Test") != "TestClosure/B1"]))

    def test_required_skip(self):
        self.events[3]["Action"] = "skip"
        self.assertTrue(self.verify())

    def test_failure(self):
        self.events[3]["Action"] = "fail"
        self.assertTrue(self.verify())

    def test_duplicate_run(self):
        self.events.insert(3, dict(self.events[2]))
        self.assertTrue(self.verify())

    def test_duplicate_pass(self):
        self.events.insert(4, dict(self.events[3]))
        self.assertTrue(self.verify())

    def test_duplicate_expected_id(self):
        self.required.write_text("TestClosure\nTestClosure\nTestClosure/B1\n", encoding="utf-8")
        self.assertTrue(self.verify())

    def test_cancelled_process_without_package_pass(self):
        self.assertTrue(self.verify(self.events[:-1]))

    def test_cancelled_process_with_incomplete_child(self):
        self.assertTrue(self.verify([self.events[0], self.events[1], self.events[2], self.events[4], self.events[5]]))

    def test_explicit_cancel(self):
        self.events.insert(3, {"Action": "cancel", "Package": "fixture", "Test": "TestClosure/B1"})
        self.assertTrue(self.verify())

    def test_truncated_json(self):
        self.verify()
        with (self.logs / "test.json").open("a", encoding="utf-8") as stream:
            stream.write('{"Action":')
        self.assertTrue(EVIDENCE.verify(self.logs, self.source, [self.required], True)[0])

    def test_unlisted_subtest(self):
        self.events[4:4] = [{"Action": action, "Package": "fixture", "Test": "TestClosure/unlisted"} for action in ("run", "pass")]
        self.assertTrue(self.verify())
        self.assertEqual([], self.verify(exact=False))

    def test_duplicate_package_execution(self):
        self.assertTrue(self.verify(self.events + self.events))

    def test_disjoint_required_suites_in_separate_process_files(self):
        (self.source / "second_test.go").write_text("package fixture\nfunc TestSecond(t *testing.T) {}\n", encoding="utf-8")
        self.required.write_text("TestClosure\nTestClosure/B1\nTestSecond\n", encoding="utf-8")
        second = [
            {"Action": "start", "Package": "fixture"},
            {"Action": "run", "Package": "fixture", "Test": "TestSecond"},
            {"Action": "pass", "Package": "fixture", "Test": "TestSecond"},
            {"Action": "pass", "Package": "fixture"},
        ]
        (self.logs / "second.json").write_text("".join(json.dumps(event) + "\n" for event in second), encoding="utf-8")
        self.assertEqual([], self.verify())

    def test_duplicate_test_id_across_process_files(self):
        (self.logs / "duplicate.json").write_text("".join(json.dumps(event) + "\n" for event in self.events), encoding="utf-8")
        self.assertTrue(self.verify())

    def test_duplicate_source_parent(self):
        (self.source / "duplicate_test.go").write_text("package fixture\nfunc TestClosure(t *testing.T) {}\n", encoding="utf-8")
        self.assertTrue(self.verify())

    def test_incomplete_unlisted_child(self):
        self.events.insert(4, {"Action": "run", "Package": "fixture", "Test": "TestClosure/unlisted"})
        self.assertTrue(self.verify(exact=False))


if __name__ == "__main__":
    unittest.main()
