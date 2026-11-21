
import json
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent


def read_json(relative_path, default=None):
    if default is None:
        default = {}

    path = BASE_DIR / relative_path

    try:
        if not path.is_file():
            return default

        with path.open("r", encoding="utf-8") as file:
            return json.load(file)

    except (OSError, json.JSONDecodeError, TypeError):
        return default


def read_first(*paths):
    for path in paths:
        data = read_json(path, None)
        if data is not None:
            return data
    return {}


def first_value(*values, default="N/A"):
    for value in values:
        if value is not None and value != "":
            return value
    return default


def display_location(value):
    if isinstance(value, dict):
        return (
            f"{value.get('file', 'Unknown')}:"
            f"{value.get('line', '?')}:"
            f"{value.get('column', '?')}"
        )

    return value if value else "N/A"


def display_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return first_value(value)


def load_reports():
    return {
        "corpus": read_first(
            "reports/corpus_report.json",
            "reports/corpus/corpus_report.json"
        ),
        "corpus_intelligence": read_first(
            "reports/corpus_intelligence.json",
            "reports/corpus_intelligence_report.json"
        ),
        "crash_analysis": read_json(
            "reports/crashes/crash_analysis.json"
        ),
        "crash_classification": read_json(
            "reports/crashes/vulnerability_classification.json"
        ),
        "crash_priority": read_json(
            "reports/crashes/crash_priority.json"
        ),
        "crash_deduplication": read_first(
            "reports/crashes/crash_deduplication.json",
            "reports/crash_deduplication.json"
        ),
        "cvss": read_first(
            "reports/cvss_report.json",
            "reports/cvss_assessment.json",
            "reports/cvss.json"
        ),
        "static_analysis": read_first(
            "reports/static_analysis.json",
            "reports/static_analysis_report.json"
        ),
        "dataflow": read_first(
            "reports/dataflow_report.json",
            "reports/data_flow_analysis.json",
            "reports/dataflow_analysis.json"
        ),
        "patch_verification": read_first(
            "reports/automated_patch_verification.json",
            "reports/patch_verification.json"
        ),
        "unified": read_first(
            "reports/unified_report.json",
            "reports/research_report.json"
        )
    }


def load_dashboard_data():
    reports = load_reports()

    fuzzer = read_json("reports/fuzzer_stats.json")
    performance = read_json("reports/fuzzing_performance.json")
    history = read_json("reports/fuzzing_performance_history.json")

    current = performance.get("current_performance", {})
    if not isinstance(current, dict):
        current = {}

    tests = read_json("reports/test_results.json")
    test_summary = tests.get("summary", {})
    if not isinstance(test_summary, dict):
        test_summary = {}

    regression = read_json("reports/regression_report.json")
    regression_summary = regression.get("summary", {})
    if not isinstance(regression_summary, dict):
        regression_summary = {}

    evidence = read_json("exports/evidence_export_report.json")
    verification = evidence.get("verification", {})
    if not isinstance(verification, dict):
        verification = {}

    crash = reports["crash_analysis"]
    classification = reports["crash_classification"]
    priority = reports["crash_priority"]

    source_location = first_value(
        crash.get("source_location"),
        classification.get("source_location"),
        priority.get("source_location"),
        default=None
    )

    crash_type = first_value(
        crash.get("crash_type"),
        classification.get("classifications"),
        priority.get("crash_type")
    )

    fuzzing = {
        "executions": first_value(
            current.get("total_execs"),
            current.get("executions"),
            fuzzer.get("total_execs"),
            fuzzer.get("executions")
        ),
        "speed": first_value(
            current.get("execs_per_sec"),
            current.get("speed"),
            fuzzer.get("execs_per_sec"),
            fuzzer.get("speed")
        ),
        "runtime": first_value(
            current.get("runtime_seconds"),
            current.get("runtime"),
            fuzzer.get("runtime_seconds"),
            fuzzer.get("runtime")
        ),
        "coverage": first_value(
            current.get("bitmap_coverage_percent"),
            current.get("bitmap_cvg"),
            fuzzer.get("bitmap_cvg")
        ),
        "crashes": first_value(
            current.get("saved_crashes"),
            fuzzer.get("saved_crashes"),
            default=0
        ),
        "stability": first_value(
            current.get("stability"),
            fuzzer.get("stability")
        ),
        "corpus": first_value(
            current.get("corpus_count"),
            current.get("corpus"),
            fuzzer.get("corpus_count"),
            fuzzer.get("corpus")
        )
    }

    tests_data = {
        "status": first_value(tests.get("status")),
        "total": first_value(test_summary.get("total"), default=0),
        "passed": first_value(test_summary.get("passed"), default=0),
        "failed": first_value(test_summary.get("failed"), default=0),
        "errors": first_value(test_summary.get("errors"), default=0)
    }

    regression_data = {
        "status": first_value(regression.get("status")),
        "total": first_value(regression_summary.get("total"), default=0),
        "fixed": first_value(regression_summary.get("fixed"), default=0),
        "still_reproducing": first_value(
            regression_summary.get("still_reproducing"),
            default=0
        ),
        "review_required": first_value(
            regression_summary.get("review_required"),
            default=0
        )
    }

    evidence_data = {
        "status": first_value(evidence.get("status")),
        "total_files": first_value(
            evidence.get("total_files"),
            verification.get("total_files"),
            default=0
        ),
        "verified_files": first_value(
            verification.get("verified_files"),
            default=0
        ),
        "failed_files": verification.get("failed_files", []),
        "verified": verification.get("verified", False)
    }

    classification_data = {
        "severity": first_value(classification.get("severity")),
        "classifications": classification.get("classifications", []),
        "findings": classification.get("findings", [])
    }

    crash_priority = {
        "priority": first_value(priority.get("priority")),
        "priority_score": first_value(
            priority.get("priority_score")
        ),
        "crash_type": display_value(
            priority.get("crash_type")
        )
    }

    summary = {
        "project": "ZeroTrace",
        "generated_at": datetime.now().isoformat(),
        "fuzzing": fuzzing,
        "tests": tests_data,
        "regression": regression_data,
        "evidence": evidence_data,
        "crash_priority": crash_priority,
        "classification": classification_data
    }

    crash_data = {
        "detected": crash.get("crash_detected", False),
        "type": display_value(crash_type),
        "severity": classification_data["severity"],
        "priority": crash_priority["priority"],
        "priority_score": crash_priority["priority_score"],
        "location": display_location(source_location)
    }

    return {
        "status": "success",
        "summary": summary,
        "reports": reports,
        "generated_at": summary["generated_at"],
        "fuzzing": fuzzing,
        "crash": crash_data,
        "tests": tests_data,
        "regression": regression_data,
        "evidence": evidence_data,
        "history": history.get("snapshots", [])
        if isinstance(history, dict) else []
    }

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroTrace Security Dashboard</title>

    <style>
        * { box-sizing: border-box; }

        body {
            margin: 0;
            padding: 25px;
            background: #10141c;
            color: #e8edf5;
            font-family: Arial, sans-serif;
        }

        header { margin-bottom: 25px; }

        h1 { color: #58a6ff; margin-bottom: 6px; }

        .subtitle, .footer { color: #9aa8ba; }

        .section-title {
            margin: 28px 0 14px;
            color: #58a6ff;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 15px;
        }

        .card {
            background: #1b2330;
            border: 1px solid #303b4d;
            border-radius: 10px;
            padding: 18px;
            min-width: 0;
        }

        .card h3 {
            margin-top: 0;
            color: #a9b8cc;
            font-size: 14px;
            font-weight: normal;
        }

        .value {
            font-size: 25px;
            font-weight: bold;
            overflow-wrap: anywhere;
        }

        .details {
            color: #c1ccda;
            line-height: 1.8;
            overflow-wrap: anywhere;
        }

        button {
            padding: 10px 16px;
            background: #2463a5;
            color: white;
            border: 0;
            border-radius: 6px;
            cursor: pointer;
        }

        button:hover { background: #347fc9; }

        .footer {
            margin-top: 35px;
            font-size: 12px;
        }

        @media (max-width: 600px) {
            body { padding: 14px; }
        }
    </style>
</head>

<body>

<header>
    <h1>ZeroTrace</h1>
    <div class="subtitle">
        Software Vulnerability Research and Fuzzing Dashboard
    </div>
    <p id="updated">Loading dashboard...</p>
    <button onclick="loadDashboard()">Refresh Data</button>
</header>

<h2 class="section-title">Fuzzing Performance</h2>
<div class="grid">
    <div class="card">
        <h3>Total Executions</h3>
        <div class="value" id="executions">--</div>
    </div>
    <div class="card">
        <h3>Execution Speed</h3>
        <div class="value" id="speed">--</div>
    </div>
    <div class="card">
        <h3>Bitmap Coverage</h3>
        <div class="value" id="coverage">--</div>
    </div>
    <div class="card">
        <h3>Saved Crashes</h3>
        <div class="value" id="crashes">--</div>
    </div>
    <div class="card">
        <h3>Stability</h3>
        <div class="value" id="stability">--</div>
    </div>
    <div class="card">
        <h3>Runtime</h3>
        <div class="value" id="runtime">--</div>
    </div>
</div>

<h2 class="section-title">Crash Analysis</h2>
<div class="grid">
    <div class="card">
        <h3>Crash Detected</h3>
        <div class="value" id="crashDetected">--</div>
    </div>
    <div class="card">
        <h3>Crash Type</h3>
        <div class="details" id="crashType">--</div>
    </div>
    <div class="card">
        <h3>Severity</h3>
        <div class="value" id="severity">--</div>
    </div>
    <div class="card">
        <h3>Priority</h3>
        <div class="value" id="priority">--</div>
        <div class="details" id="priorityScore"></div>
    </div>
    <div class="card">
        <h3>Source Location</h3>
        <div class="details" id="location">--</div>
    </div>
</div>

<h2 class="section-title">Testing Results</h2>
<div class="grid">
    <div class="card">
        <h3>Test Status</h3>
        <div class="value" id="testStatus">--</div>
    </div>
    <div class="card">
        <h3>Total Tests</h3>
        <div class="value" id="testTotal">--</div>
    </div>
    <div class="card">
        <h3>Passed</h3>
        <div class="value" id="testPassed">--</div>
    </div>
    <div class="card">
        <h3>Failed</h3>
        <div class="value" id="testFailed">--</div>
    </div>
    <div class="card">
        <h3>Errors</h3>
        <div class="value" id="testErrors">--</div>
    </div>
</div>

<h2 class="section-title">Regression Testing</h2>
<div class="grid">
    <div class="card">
        <h3>Regression Status</h3>
        <div class="value" id="regressionStatus">--</div>
    </div>
    <div class="card">
        <h3>Total Cases</h3>
        <div class="value" id="regressionTotal">--</div>
    </div>
    <div class="card">
        <h3>Fixed</h3>
        <div class="value" id="regressionFixed">--</div>
    </div>
    <div class="card">
        <h3>Still Reproducing</h3>
        <div class="value" id="regressionRemaining">--</div>
    </div>
    <div class="card">
        <h3>Review Required</h3>
        <div class="value" id="regressionReview">--</div>
    </div>
</div>

<h2 class="section-title">Evidence Integrity</h2>
<div class="grid">
    <div class="card">
        <h3>Export Status</h3>
        <div class="value" id="evidenceStatus">--</div>
    </div>
    <div class="card">
        <h3>Total Files</h3>
        <div class="value" id="evidenceTotal">--</div>
    </div>
    <div class="card">
        <h3>Verified Files</h3>
        <div class="value" id="evidenceVerified">--</div>
    </div>
    <div class="card">
        <h3>Verification</h3>
        <div class="value" id="evidenceResult">--</div>
    </div>
</div>

<div class="footer">
    ZeroTrace | Local Read-Only Dashboard | Auto-refresh: 10 seconds
</div>

<script>
    function show(id, value) {
        const element = document.getElementById(id);

        if (!element) return;

        if (value === null || value === undefined || value === "") {
            element.textContent = "N/A";
        } else if (typeof value === "object") {
            element.textContent = JSON.stringify(value);
        } else {
            element.textContent = String(value);
        }
    }

    async function loadDashboard() {
        try {
            const response = await fetch("/api/dashboard");

            if (!response.ok) {
                throw new Error("API returned HTTP " + response.status);
            }

            const data = await response.json();

            if (data.status !== "success") {
                throw new Error("Dashboard API reported an error");
            }

            const f = data.fuzzing;
            const c = data.crash;
            const t = data.tests;
            const r = data.regression;
            const e = data.evidence;

            show("executions", f.executions);
            show("speed", f.speed + " exec/sec");

            let coverage = f.coverage;
            if (
                coverage !== "N/A" &&
                coverage !== null &&
                coverage !== undefined &&
                !String(coverage).includes("%")
            ) {
                coverage = coverage + "%";
            }
            show("coverage", coverage);

            show("crashes", f.crashes);
            show("stability", f.stability);
            show("runtime", f.runtime + " sec");

            show("crashDetected", c.detected ? "Yes" : "No");
            show("crashType", c.type);
            show("severity", c.severity);
            show("priority", c.priority);
            show("priorityScore", "Priority score: " + c.priority_score);
            show("location", c.location);

            show("testStatus", t.status);
            show("testTotal", t.total);
            show("testPassed", t.passed);
            show("testFailed", t.failed);
            show("testErrors", t.errors);

            show("regressionStatus", r.status);
            show("regressionTotal", r.total);
            show("regressionFixed", r.fixed);
            show("regressionRemaining", r.still_reproducing);
            show("regressionReview", r.review_required);

            show("evidenceStatus", e.status);
            show("evidenceTotal", e.total_files);
            show("evidenceVerified", e.verified_files);
            show(
                "evidenceResult",
                e.verified ? "Verified" : "Not verified"
            );

            show("updated", "Last updated: " + data.generated_at);

        } catch (error) {
            show("updated", "Dashboard error: " + error.message);
        }
    }

    loadDashboard();
    setInterval(loadDashboard, 10000);
</script>

</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/dashboard")
def dashboard_api():
    return jsonify(load_dashboard_data())


@app.route("/health")
@app.route("/api/health")
def health_api():
    return jsonify({
        "status": "online",
        "project": "ZeroTrace",
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/tests")
def tests_api():
    return jsonify(read_json("reports/test_results.json"))


@app.route("/api/regression")
def regression_api():
    return jsonify(read_json("reports/regression_report.json"))


@app.route("/api/evidence")
def evidence_api():
    return jsonify(read_json("exports/evidence_export_report.json"))


@app.route("/api/performance")
def performance_api():
    return jsonify(read_json("reports/fuzzing_performance.json"))


if __name__ == "__main__":
    print("[+] Starting ZeroTrace dashboard...")
    print("[+] URL: http://127.0.0.1:5000")
    print("[+] Auto-refresh: 10 seconds")
    print("[+] Mode: Read-only")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
