
import hashlib
import importlib
import json
import tempfile
import unittest
import zipfile

from pathlib import Path

from modules.evidence_exporter import EvidenceExporter


BASE_DIR = Path(__file__).resolve().parent.parent


class TestZeroTraceModules(unittest.TestCase):

    def test_core_module_imports(self):
        modules = [
            "modules.target_manager",
            "modules.static_analyzer",
            "modules.dataflow_analyzer",
            "modules.vulnerability_classifier",
            "modules.crash_analyzer",
            "modules.crash_deduplicator",
            "modules.crash_prioritizer",
            "modules.regression_tester",
            "modules.corpus_manager",
            "modules.corpus_intelligence",
            "modules.fuzzing_performance",
            "modules.evidence_exporter",
            "modules.crash_intelligence_engine"
        ]

        for module_name in modules:
            with self.subTest(module=module_name):
                imported = importlib.import_module(module_name)
                self.assertIsNotNone(imported)


class TestEvidenceIntegrity(unittest.TestCase):

    def setUp(self):
        self.exporter = EvidenceExporter()

    def test_sha256_calculation(self):
        content = b"ZeroTrace evidence integrity test"

        expected_hash = hashlib.sha256(content).hexdigest()

        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "test_evidence.txt"
            file_path.write_bytes(content)

            actual_hash = self.exporter.calculate_hash(file_path)

        self.assertEqual(actual_hash, expected_hash)

    def test_valid_archive_verification(self):
        content = b"ZeroTrace test evidence"
        file_hash = hashlib.sha256(content).hexdigest()

        manifest = {
            "project": "ZeroTrace",
            "hash_algorithm": "SHA-256",
            "total_files": 1,
            "files": [
                {
                    "category": "report",
                    "path": "reports/sample.txt",
                    "size_bytes": len(content),
                    "sha256": file_hash
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "test_evidence.zip"

            with zipfile.ZipFile(
                archive_path,
                "w",
                compression=zipfile.ZIP_DEFLATED
            ) as archive:

                archive.writestr(
                    "evidence/reports/sample.txt",
                    content
                )

                archive.writestr(
                    "evidence/evidence_manifest.json",
                    json.dumps(manifest)
                )

            result = self.exporter.verify_archive(archive_path)

        self.assertTrue(result["verified"])
        self.assertEqual(result["total_files"], 1)
        self.assertEqual(result["verified_files"], 1)
        self.assertEqual(result["failed_files"], [])

    def test_tampered_archive_detection(self):
        original_content = b"Original evidence"
        changed_content = b"Modified evidence"

        manifest = {
            "project": "ZeroTrace",
            "hash_algorithm": "SHA-256",
            "total_files": 1,
            "files": [
                {
                    "category": "report",
                    "path": "reports/sample.txt",
                    "size_bytes": len(original_content),
                    "sha256": hashlib.sha256(
                        original_content
                    ).hexdigest()
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "tampered.zip"

            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "evidence/reports/sample.txt",
                    changed_content
                )

                archive.writestr(
                    "evidence/evidence_manifest.json",
                    json.dumps(manifest)
                )

            result = self.exporter.verify_archive(archive_path)

        self.assertFalse(result["verified"])
        self.assertEqual(result["verified_files"], 0)
        self.assertEqual(len(result["failed_files"]), 1)
        self.assertEqual(
            result["failed_files"][0]["reason"],
            "SHA-256 mismatch"
        )


class TestZeroTraceReports(unittest.TestCase):

    def load_report(self, relative_path):
        report_path = BASE_DIR / relative_path

        if not report_path.exists():
            self.skipTest(f"Report not found: {relative_path}")

        with open(report_path, "r", encoding="utf-8") as file:
            return json.load(file)

    def test_vulnerability_classification_report(self):
        report = self.load_report(
            "reports/crashes/vulnerability_classification.json"
        )

        self.assertIn("crash_detected", report)
        self.assertIn("classifications", report)
        self.assertIn("severity", report)

        self.assertTrue(report["crash_detected"])
        self.assertTrue(len(report["classifications"]) > 0)

    def test_crash_priority_report(self):
        report = self.load_report(
            "reports/crashes/crash_priority.json"
        )

        self.assertIn("priority_score", report)
        self.assertIn("priority", report)
        self.assertIn("reasons", report)

        self.assertGreaterEqual(report["priority_score"], 0)
        self.assertLessEqual(report["priority_score"], 100)

    def test_regression_report(self):
        report = self.load_report(
            "reports/regression_report.json"
        )

        self.assertIn("checks", report)
        self.assertIn("results", report)

        self.assertEqual(
            report["checks"]["compilation"]["original"]["status"],
            "passed"
        )

        self.assertEqual(
            report["checks"]["compilation"]["patched"]["status"],
            "passed"
        )

        self.assertGreater(len(report["results"]), 0)

        for result in report["results"]:
            self.assertIn("original", result)
            self.assertIn("patched", result)
            self.assertIn("outcome", result["original"])
            self.assertIn("outcome", result["patched"])

    def test_evidence_export_report(self):
        report = self.load_report(
            "exports/evidence_export_report.json"
        )

        self.assertEqual(report["status"], "completed")
        self.assertTrue(report["verification"]["verified"])

        self.assertEqual(
            report["total_files"],
            report["verification"]["verified_files"]
        )

        self.assertEqual(
            report["verification"]["failed_files"],
            []
        )

        archive_path = BASE_DIR / report["archive"]

        self.assertTrue(archive_path.is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
