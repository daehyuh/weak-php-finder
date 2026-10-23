import csv
import json
import tempfile
import unittest
from pathlib import Path

import scanner


def record(**values):
    return {"host": "portal.example.test", "php_state": "yes", "php_version": "8.4.26", "evidence": "owner package record", "vendor_patch_id": "", **values}


class ClassificationTests(unittest.TestCase):
    def test_each_fixed_floor(self):
        for (major, minor), patch in scanner.FIXED.items():
            for delta, expected in [(-1, "ACTION"), (0, "PATCHED_VERSION"), (1, "PATCHED_VERSION")]:
                version = f"{major}.{minor}.{patch + delta}"
                with self.subTest(version=version):
                    self.assertEqual(scanner.classify(record(php_version=version))[0], expected)

    def test_unknown_and_missing_evidence_never_pass(self):
        for values in [{"php_state": "unknown"}, {"evidence": ""}, {"php_state": "no", "php_version": "", "evidence": ""}]:
            with self.subTest(values=values):
                self.assertEqual(scanner.classify(record(**values))[0], "REVIEW")

    def test_conflicting_no_php_record(self):
        self.assertEqual(scanner.classify(record(php_state="no"))[0], "REVIEW")
        self.assertEqual(scanner.classify(record(php_state="no", php_version="", vendor_patch_id="VENDOR-1"))[0], "REVIEW")

    def test_no_php_with_owner_evidence(self):
        self.assertEqual(scanner.classify(record(php_state="no", php_version=""))[0], "NOT_APPLICABLE")

    def test_vendor_backport_needs_review_even_on_new_version(self):
        for version in ["8.1.29", "8.4.26", "8.4.27"]:
            with self.subTest(version=version):
                self.assertEqual(scanner.classify(record(php_version=version, vendor_patch_id="VENDOR-1"))[0], "VENDOR_REVIEW")

    def test_prereleases_packages_and_new_branches_need_review(self):
        for version in ["8.4.27RC1", "8.4.27-1deb", "8.4", "8.6.0", "9.0.0", ""]:
            with self.subTest(version=version):
                self.assertEqual(scanner.classify(record(php_version=version))[0], "REVIEW")

    def test_eol_has_action_reason_not_a_patched_claim(self):
        status, reason = scanner.classify(record(php_version="7.4.33"))
        self.assertEqual(status, "ACTION")
        self.assertIn("Unsupported", reason)

    def test_normalized_host_and_invalid_inputs(self):
        self.assertEqual(scanner.clean_host(" Portal.Example.test. "), "portal.example.test")
        for host in ["", "https://example.test", "example.test/a", "example.test:443", "127.0.0.1", "a..test", "-bad.test", "bad-.test", "a_b.test", "a" * 64 + ".test", "example.test.."]:
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    scanner.clean_host(host)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.hosts = self.root / "hosts.txt"
        self.inventory = self.root / "inventory.csv"
        self.out = self.root / "result.csv"
        self.hosts.write_text("# example\nPortal.Example.test\nportal.example.test.\nmissing.example.test\n", encoding="utf-8")
        self.write_inventory([record()])

    def write_inventory(self, rows):
        with self.inventory.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=scanner.FIELDS)
            writer.writeheader()
            writer.writerows(rows)

    def test_join_deduplicates_and_records_unmatched_host(self):
        results = scanner.run(self.hosts, self.inventory, self.out)
        self.assertEqual(len(results), 2)
        by_host = {row["host"]: row for row in results}
        self.assertEqual(by_host["missing.example.test"]["status"], "REVIEW")
        self.assertEqual(by_host["portal.example.test"]["status"], "ACTION")
        with self.out.open(encoding="utf-8-sig", newline="") as stream:
            self.assertEqual(len(list(csv.DictReader(stream))), 2)

    def test_duplicate_inventory_is_rejected(self):
        self.write_inventory([record(), record(host="PORTAL.EXAMPLE.TEST")])
        with self.assertRaisesRegex(ValueError, "Duplicate inventory"):
            scanner.run(self.hosts, self.inventory, self.out)
        self.assertFalse(self.out.exists())

    def test_empty_targets_are_rejected(self):
        self.hosts.write_text("# empty\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "No hostnames"):
            scanner.run(self.hosts, self.inventory, self.out)

    def test_duplicate_csv_header_is_rejected(self):
        self.inventory.write_text(",".join(scanner.FIELDS) + ",evidence\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate column"):
            scanner.run(self.hosts, self.inventory, self.out)

    def test_input_overwrite_is_rejected(self):
        for target in [self.hosts, self.inventory]:
            original = target.read_bytes()
            with self.assertRaisesRegex(ValueError, "overwrite"):
                scanner.run(self.hosts, self.inventory, target)
            self.assertEqual(target.read_bytes(), original)

    def test_csv_formula_escape_and_json_original(self):
        self.write_inventory([record(evidence="=SUM(1,2)")])
        results = scanner.run(self.hosts, self.inventory, self.out)
        with self.out.open(encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(rows[1]["evidence"], "'=SUM(1,2)")
        path = self.root / "report.json"
        scanner.write_json(path, results, self.hosts, self.inventory)
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["network_requests"], 0)
        self.assertEqual(len(payload["input_sha256"]["hosts"]), 64)
        self.assertEqual(payload["results"][1]["evidence"], "=SUM(1,2)")
        self.assertEqual(sum(payload["summary"].values()), 2)


if __name__ == "__main__":
    unittest.main()
