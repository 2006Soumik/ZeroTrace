
import json
import unittest
import time

from pathlib import Path
from datetime import datetime, timezone
from html import escape


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"

JSON_REPORT = REPORTS_DIR / "test_results.json"
HTML_REPORT = REPORTS_DIR / "test_results.html"
HISTORY_REPORT = REPORTS_DIR / "test_history.json"


class TestResultCollector(unittest.TextTestResult):

    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)

        self.started_at = None
        self.test_details = []

    def startTest(self, test):
        self.started_at = time.perf_counter()
        super().startTest(test)

    def stopTest(self, test):
        super().stopTest(test)

    def addSuccess(self, test):
        self.test_details.append({
            "test": str(test),
            "status": "passed",
            "details": ""
        })
        super().addSuccess(test)

    def addFailure(self, test, err):
        self.test_details.append({
            "test": str(test),
            "status": "failed",
            "details": self._exc_info_to_string(err, test)
        })
        super().addFailure(test, err)

    def addError(self, test, err):
        self.test_details.append({
            "test": str(test),
            "status": "error",
            "details": self._exc_info_to_string(err, test)
        })
        super().addError(test, err)

    def addSkip(self, test, reason):
        self.test_details.append({
            "test": str(test),
            "status": "skipped",
            "details": reason
        })
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        self.test_details.append({
            "test": str(test),
            "status": "expected_failure",
            "details": self._exc_info_to_string(err, test)
        })
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self.test_details.append({
            "test": str(test),
            "status": "unexpected_success",
            "details": "Test unexpectedly succeeded."
        })
        super().addUnexpectedSuccess(test)


class TestResultRunner:

    def __init__(self):
        self.reports_dir = REPORTS_DIR

    def run_tests(self):
        print("\n[+] Starting ZeroTrace automated test suite...")

        loader = unittest.TestLoader()
        suite = loader.discover(
            start_dir=str(BASE_DIR / "tests"),
            pattern="test_*.py",
            top_level_dir=str(BASE_DIR)
        )

        runner = unittest.TextTestRunner(
            verbosity=2,
            resultclass=TestResultCollector
        )

        start_time = time.perf_counter()
        result = runner.run(suite)
        execution_time = round(time.perf_counter() - start_time, 4)

        return result, execution_time

    def build_report(self, result, execution_time):
        passed = sum(
            1 for item in result.test_details
            if item["status"] == "passed"
        )

        failed = len(result.failures)
        errors = len(result.errors)
        skipped = len(result.skipped)

        status = (
            "passed"
            if result.wasSuccessful()
            else "failed"
        )

        return {
            "project": "ZeroTrace",
            "report_type": "Automated Test Results",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "summary": {
                "total": result.testsRun,
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "skipped": skipped,
                "unexpected_successes": len(result.unexpectedSuccesses),
                "execution_time_seconds": execution_time
            },
            "tests": result.test_details
        }

    def save_json(self, report):
        with open(JSON_REPORT, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print(f"[+] JSON report: {JSON_REPORT}")

    def save_history(self, report):
        history = []

        if HISTORY_REPORT.exists():
            try:
                with open(HISTORY_REPORT, "r", encoding="utf-8") as file:
                    history = json.load(file)

                if not isinstance(history, list):
                    history = []

            except (json.JSONDecodeError, OSError):
                history = []

        history.append({
            "generated_at": report["generated_at"],
            "status": report["status"],
            "summary": report["summary"]
        })

        history = history[-100:]

        with open(HISTORY_REPORT, "w", encoding="utf-8") as file:
            json.dump(history, file, indent=4)

        print(f"[+] Test history: {HISTORY_REPORT}")

    def save_html(self, report):
        summary = report["summary"]

        rows = ""

        for item in report["tests"]:
            test_name = escape(item["test"])
            test_status = escape(item["status"].upper())
            details = escape(item["details"])

            rows += f"""
            <tr>
                <td>{test_name}</td>
                <td class="{test_status.lower()}">
                    {test_status}
                </td>
                <td><pre>{details}</pre></td>
            </tr>
            """

        status = escape(report["status"].upper())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZeroTrace Test Report</title>

<style>
body {{
    font-family: Arial, sans-serif;
    background: #f3f4f6;
    color: #222;
    margin: 0;
    padding: 30px;
}}

.container {{
    max-width: 1100px;
    margin: auto;
    background: white;
    padding: 25px;
    border-radius: 10px;
}}

h1 {{ margin-bottom: 5px; }}

.cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 15px;
    margin: 25px 0;
}}

.card {{
    background: #f3f4f6;
    padding: 18px;
    border-radius: 8px;
}}

.value {{
    font-size: 28px;
    font-weight: bold;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}}

th, td {{
    padding: 12px;
    border-bottom: 1px solid #ddd;
    text-align: left;
    vertical-align: top;
}}

th {{ background: #f3f4f6; }}

.passed {{ color: green; font-weight: bold; }}
.failed, .error {{ color: red; font-weight: bold; }}
.skipped {{ color: #a16207; font-weight: bold; }}

pre {{
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    max-width: 500px;
}}

.footer {{
    margin-top: 25px;
    color: #777;
    font-size: 12px;
}}
</style>
</head>

<body>
<div class="container">

<h1>ZeroTrace</h1>
<p>Automated Security Test Report</p>

<h2>Status: {status}</h2>

<div class="cards">
    <div class="card">
        <div>Total Tests</div>
        <div class="value">{summary["total"]}</div>
    </div>
    <div class="card">
        <div>Passed</div>
        <div class="value">{summary["passed"]}</div>
    </div>
    <div class="card">
        <div>Failed</div>
        <div class="value">{summary["failed"]}</div>
    </div>
    <div class="card">
        <div>Errors</div>
        <div class="value">{summary["errors"]}</div>
    </div>
    <div class="card">
        <div>Skipped</div>
        <div class="value">{summary["skipped"]}</div>
    </div>
    <div class="card">
        <div>Execution Time</div>
        <div class="value">{summary["execution_time_seconds"]}s</div>
    </div>
</div>

<h2>Individual Test Results</h2>

<table>
<thead>
<tr>
    <th>Test</th>
    <th>Status</th>
    <th>Details</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>

<div class="footer">
Generated: {escape(report["generated_at"])}<br>
ZeroTrace Automated Testing Framework
</div>

</div>
</body>
</html>
"""

        with open(HTML_REPORT, "w", encoding="utf-8") as file:
            file.write(html)

        print(f"[+] HTML report: {HTML_REPORT}")

    def run(self):
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        result, execution_time = self.run_tests()
        report = self.build_report(result, execution_time)

        self.save_json(report)
        self.save_html(report)
        self.save_history(report)

        print("\n========== ZEROTRACE TEST SUMMARY ==========")
        print(f"Status: {report['status'].upper()}")
        print(f"Total: {report['summary']['total']}")
        print(f"Passed: {report['summary']['passed']}")
        print(f"Failed: {report['summary']['failed']}")
        print(f"Errors: {report['summary']['errors']}")
        print(f"Skipped: {report['summary']['skipped']}")
        print(f"Time: {execution_time}s")
        print("============================================")

        return report


if __name__ == "__main__":
    report = TestResultRunner().run()

    raise SystemExit(
        0 if report["status"] == "passed" else 1
    )
