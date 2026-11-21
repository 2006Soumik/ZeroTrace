
import unittest

from dashboard.app import app


class TestZeroTraceDashboard(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_dashboard_loads(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ZeroTrace", response.data)

    def test_dashboard_api(self):
        response = self.client.get("/api/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.content_type,
            "application/json"
        )

        data = response.get_json()

        self.assertIsInstance(data, dict)
        self.assertEqual(data.get("status"), "success")

        self.assertIn("summary", data)
        self.assertIn("reports", data)

        self.assertIsInstance(data["summary"], dict)
        self.assertIsInstance(data["reports"], dict)

    def test_dashboard_summary_sections(self):
        response = self.client.get("/api/dashboard")
        data = response.get_json()

        summary = data["summary"]

        expected_sections = {
            "project",
            "generated_at",
            "fuzzing",
            "tests",
            "regression",
            "evidence",
            "crash_priority",
            "classification"
        }

        self.assertTrue(
            expected_sections.issubset(summary.keys())
        )

    def test_dashboard_report_sections(self):
        response = self.client.get("/api/dashboard")
        data = response.get_json()

        expected_reports = {
            "corpus",
            "corpus_intelligence",
            "crash_analysis",
            "crash_classification",
            "crash_priority",
            "crash_deduplication",
            "cvss",
            "static_analysis",
            "dataflow",
            "patch_verification",
            "unified"
        }

        self.assertTrue(
            expected_reports.issubset(data["reports"].keys())
        )

    def test_severity_information_available(self):
        response = self.client.get("/api/dashboard")
        data = response.get_json()

        classification = data["summary"]["classification"]

        self.assertIsInstance(classification, dict)

        if classification:
            self.assertTrue(
                any(
                    key in classification
                    for key in ("severity", "classifications", "findings")
                )
            )

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["status"], "online")
        self.assertEqual(data["project"], "ZeroTrace")


if __name__ == "__main__":
    unittest.main()
