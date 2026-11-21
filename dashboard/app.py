
import json
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template_string


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
CRASH_DIR = REPORTS_DIR / "crashes"
EXPORTS_DIR = BASE_DIR / "exports"

app = Flask(__name__)


# ---------------------------------------------------------
# REPORT READER
# ---------------------------------------------------------

def read_json(path, default=None):
    if default is None:
        default = {}

    try:
        if not path.exists():
            return default

        with path.open("r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError, TypeError):
        return default


def first_existing_report(*paths):
    for path in paths:
        data = read_json(path, None)

        if data is not None:
            return data

    return {}


def get_reports():
    return {
        "fuzzer_stats": read_json(
            REPORTS_DIR / "fuzzer_stats.json"
        ),

        "performance": read_json(
            REPORTS_DIR / "fuzzing_performance.json"
        ),

        "performance_history": read_json(
            REPORTS_DIR / "fuzzing_performance_history.json",
            []
        ),

        "corpus": read_json(
            REPORTS_DIR / "corpus_inventory.json"
        ),

        "corpus_intelligence": read_json(
            REPORTS_DIR / "corpus_intelligence.json"
        ),

        "crash_analysis": read_json(
            CRASH_DIR / "crash_analysis.json"
        ),

        "crash_classification": read_json(
            CRASH_DIR / "vulnerability_classification.json"
        ),

        "crash_priority": read_json(
            CRASH_DIR / "crash_priority.json"
        ),

        "crash_deduplication": read_json(
            CRASH_DIR / "crash_deduplication.json"
        ),

        "crash_intelligence": read_json(
            CRASH_DIR / "crash_intelligence_report.json"
        ),

        "cvss": first_existing_report(
            CRASH_DIR / "cvss_assessment.json",
            REPORTS_DIR / "cvss_assessment.json"
        ),

        "regression": read_json(
            REPORTS_DIR / "regression_report.json"
        ),

        "tests": read_json(
            REPORTS_DIR / "test_results.json"
        ),

        "test_history": read_json(
            REPORTS_DIR / "test_history.json",
            []
        ),

        "evidence": read_json(
            EXPORTS_DIR / "evidence_export_report.json"
        ),

        "unified": first_existing_report(
            REPORTS_DIR / "unified_report.json",
            CRASH_DIR / "unified_report.json"
        ),

        "patch_verification": first_existing_report(
            REPORTS_DIR / "patch_verification.json",
            REPORTS_DIR / "automated_patch_verification.json"
        ),

        "static_analysis": first_existing_report(
            REPORTS_DIR / "static_analysis.json",
            CRASH_DIR / "static_analysis.json"
        ),

        "dataflow": first_existing_report(
            REPORTS_DIR / "dataflow_analysis.json",
            CRASH_DIR / "dataflow_analysis.json"
        )
    }


def number(data, *keys, default=0):
    current = data

    for key in keys:
        if not isinstance(current, dict):
            return default

        current = current.get(key)

    try:
        return float(current)
    except (TypeError, ValueError):
        return default


def get_summary():
    reports = get_reports()

    stats = reports["fuzzer_stats"]
    performance = reports["performance"]
    tests = reports["tests"]
    regression = reports["regression"]
    evidence = reports["evidence"]

    test_summary = tests.get("summary", {})
    regression_summary = regression.get("summary", {})

    return {
        "project": "ZeroTrace",
        "generated_at": datetime.now(timezone.utc).isoformat(),

        "fuzzing": {
            "executions": number(
                stats, "execs_done"
            ),
            "exec_per_second": number(
                stats, "execs_per_sec"
            ),
            "corpus": number(
                stats, "corpus_count"
            ),
            "crashes": number(
                stats, "saved_crashes"
            ),
            "hangs": number(
                stats, "saved_hangs"
            ),
            "coverage": number(
                performance, "bitmap_coverage",
                default=number(stats, "bitmap_cvg")
            ),
            "runtime": stats.get("run_time", "N/A")
        },

        "tests": {
            "status": tests.get("status", "not_available"),
            "total": test_summary.get("total", 0),
            "passed": test_summary.get("passed", 0),
            "failed": test_summary.get("failed", 0),
            "errors": test_summary.get("errors", 0),
            "execution_time": test_summary.get(
                "execution_time_seconds", 0
            )
        },

        "regression": {
            "status": regression.get(
                "status",
                regression.get("regression_status", "not_available")
            ),
            "total": regression_summary.get("total", 0),
            "fixed": regression_summary.get("fixed", 0),
            "still_reproducing": regression_summary.get(
                "still_reproducing", 0
            ),
            "review_required": regression_summary.get(
                "review_required", 0
            )
        },

        "evidence": {
            "status": evidence.get("status", "not_available"),
            "total_files": evidence.get("total_files", 0),
            "verified": evidence.get(
                "verified_files",
                evidence.get("verification", {}).get("verified", 0)
                if isinstance(evidence.get("verification"), dict)
                else 0
            ),
            "verification": evidence.get("verification", {})
        },

        "crash_priority": reports["crash_priority"],
        "classification": reports["crash_classification"]
    }


# ---------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------

@app.route("/api/dashboard")
def dashboard_api():
    reports = get_reports()

    return jsonify({
        "status": "success",
        "summary": get_summary(),
        "reports": {
            "corpus": reports["corpus"],
            "corpus_intelligence": reports["corpus_intelligence"],
            "crash_analysis": reports["crash_analysis"],
            "crash_classification": reports["crash_classification"],
            "crash_priority": reports["crash_priority"],
            "crash_deduplication": reports["crash_deduplication"],
            "cvss": reports["cvss"],
            "static_analysis": reports["static_analysis"],
            "dataflow": reports["dataflow"],
            "patch_verification": reports["patch_verification"],
            "unified": reports["unified"]
        }
    })


@app.route("/api/tests")
def tests_api():
    reports = get_reports()

    return jsonify({
        "status": "success",
        "latest": reports["tests"],
        "history": reports["test_history"]
    })


@app.route("/api/evidence")
def evidence_api():
    return jsonify({
        "status": "success",
        "evidence": get_reports()["evidence"]
    })


@app.route("/api/performance")
def performance_api():
    reports = get_reports()

    return jsonify({
        "status": "success",
        "current": reports["performance"],
        "history": reports["performance_history"],
        "fuzzer_stats": reports["fuzzer_stats"]
    })


@app.route("/api/crash-intelligence")
def crash_intelligence_api():
    reports = get_reports()

    return jsonify({
        "status": "success",
        "intelligence": reports["crash_intelligence"],
        "classification": reports["crash_classification"],
        "priority": reports["crash_priority"],
        "analysis": reports["crash_analysis"],
        "deduplication": reports["crash_deduplication"]
    })


@app.route("/api/regression")
def regression_api():
    return jsonify({
        "status": "success",
        "report": get_reports()["regression"]
    })


# ---------------------------------------------------------
# DASHBOARD INTERFACE
# ---------------------------------------------------------

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>ZeroTrace | Security Research Dashboard</title>

<style>

:root {
    --bg: #090d18;
    --panel: #111827;
    --panel2: #172033;
    --border: #263449;
    --text: #e5edf8;
    --muted: #91a0b7;
    --blue: #55a6ff;
    --green: #35d49a;
    --red: #ff6377;
    --yellow: #f5c451;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: Arial, sans-serif;
}

.sidebar {
    position: fixed;
    left: 0;
    top: 0;
    bottom: 0;
    width: 235px;
    padding: 25px 18px;
    background: #0d1422;
    border-right: 1px solid var(--border);
}

.brand {
    font-size: 23px;
    font-weight: bold;
    letter-spacing: 1px;
    margin-bottom: 7px;
}

.brand span {
    color: var(--blue);
}

.sidebar small {
    color: var(--muted);
}

.nav-title {
    margin-top: 35px;
    margin-bottom: 12px;
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 1.5px;
}

.nav-item {
    display: block;
    padding: 12px;
    margin-bottom: 5px;
    color: #bdc9da;
    text-decoration: none;
    border-radius: 7px;
    font-size: 13px;
}

.nav-item:hover {
    background: var(--panel2);
    color: white;
}

.main {
    margin-left: 235px;
    padding: 28px;
    max-width: 1700px;
}

.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
    flex-wrap: wrap;
    margin-bottom: 28px;
}

h1 {
    font-size: 25px;
    margin: 0 0 7px;
}

.subtitle {
    color: var(--muted);
    font-size: 13px;
}

.refresh {
    background: #17365b;
    border: 1px solid #285b91;
    color: #b9dcff;
    padding: 10px 16px;
    border-radius: 7px;
    cursor: pointer;
}

.section-title {
    font-size: 16px;
    margin: 30px 0 15px;
}

.grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 15px;
}

.card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 19px;
    min-width: 0;
}

.card-label {
    color: var(--muted);
    font-size: 12px;
}

.card-value {
    font-size: 27px;
    font-weight: bold;
    margin-top: 13px;
    overflow-wrap: anywhere;
}

.card-note {
    color: var(--muted);
    font-size: 11px;
    margin-top: 8px;
}

.blue { color: var(--blue); }
.green { color: var(--green); }
.red { color: var(--red); }
.yellow { color: var(--yellow); }

.two-column {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 15px;
}

.status {
    display: inline-block;
    border-radius: 5px;
    padding: 5px 9px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
    background: #263449;
    color: var(--muted);
}

.status.passed,
.status.completed,
.status.success,
.status.fixed {
    background: #123a32;
    color: var(--green);
}

.status.failed,
.status.error {
    background: #481d2a;
    color: var(--red);
}

.status.not_available {
    background: #30384a;
    color: var(--muted);
}

.data-list {
    display: grid;
    gap: 12px;
}

.data-row {
    display: flex;
    justify-content: space-between;
    gap: 15px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    font-size: 13px;
}

.data-row span:first-child {
    color: var(--muted);
}

.data-row strong {
    overflow-wrap: anywhere;
    text-align: right;
}

.table-wrap {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
}

th, td {
    padding: 12px 10px;
    text-align: left;
    border-bottom: 1px solid var(--border);
}

th {
    color: var(--muted);
    font-weight: normal;
}

.history-bars {
    display: flex;
    align-items: end;
    gap: 9px;
    height: 130px;
    padding-top: 15px;
}

.history-bar {
    flex: 1;
    min-width: 5px;
    background: var(--blue);
    border-radius: 4px 4px 0 0;
    position: relative;
}

.history-bar span {
    position: absolute;
    bottom: -22px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 9px;
    color: var(--muted);
}

.empty {
    color: var(--muted);
    font-size: 12px;
    padding: 15px 0;
}

.footer {
    margin-top: 35px;
    padding: 20px 0;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 11px;
}

@media(max-width: 1100px) {
    .grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

@media(max-width: 750px) {
    .sidebar {
        position: relative;
        width: 100%;
        height: auto;
    }

    .sidebar .nav-title,
    .sidebar .nav-item {
        display: none;
    }

    .main {
        margin-left: 0;
        padding: 18px;
    }

    .two-column {
        grid-template-columns: 1fr;
    }
}

@media(max-width: 450px) {
    .grid {
        grid-template-columns: 1fr;
    }
}

</style>
</head>

<body>

<aside class="sidebar">

    <div class="brand">ZERO<span>TRACE</span></div>
    <small>Security Research Framework</small>

    <div class="nav-title">OVERVIEW</div>
    <a class="nav-item" href="#overview">Dashboard Overview</a>
    <a class="nav-item" href="#fuzzing">Fuzzing Analytics</a>

    <div class="nav-title">SECURITY RESEARCH</div>
    <a class="nav-item" href="#crashes">Crash Intelligence</a>
    <a class="nav-item" href="#regression">Regression Testing</a>

    <div class="nav-title">QUALITY & EVIDENCE</div>
    <a class="nav-item" href="#tests">Automated Test Suite</a>
    <a class="nav-item" href="#evidence">Evidence Integrity</a>

</aside>


<main class="main">

<header class="topbar">

    <div>
        <h1>Security Research Dashboard</h1>
        <div class="subtitle">
            ZeroTrace vulnerability research and fuzzing platform
        </div>
    </div>

    <button class="refresh" onclick="loadDashboard()">
        Refresh Data
    </button>

</header>


<section id="overview">

    <div class="section-title">Security Overview</div>

    <div class="grid">

        <div class="card">
            <div class="card-label">Total Executions</div>
            <div class="card-value blue" id="executions">0</div>
            <div class="card-note">AFL++ executions</div>
        </div>

        <div class="card">
            <div class="card-label">Execution Speed</div>
            <div class="card-value" id="speed">0</div>
            <div class="card-note">Executions per second</div>
        </div>

        <div class="card">
            <div class="card-label">Discovered Crashes</div>
            <div class="card-value red" id="crashes">0</div>
            <div class="card-note">AFL++ saved crashes</div>
        </div>

        <div class="card">
            <div class="card-label">Corpus Size</div>
            <div class="card-value green" id="corpus">0</div>
            <div class="card-note">Corpus entries</div>
        </div>

    </div>

</section>


<section id="fuzzing">

    <div class="section-title">Fuzzing Performance Analytics</div>

    <div class="grid">

        <div class="card">
            <div class="card-label">Bitmap Coverage</div>
            <div class="card-value blue" id="coverage">0%</div>
        </div>

        <div class="card">
            <div class="card-label">Saved Hangs</div>
            <div class="card-value yellow" id="hangs">0</div>
        </div>

        <div class="card">
            <div class="card-label">Runtime</div>
            <div class="card-value" id="runtime">N/A</div>
        </div>

        <div class="card">
            <div class="card-label">Performance History</div>
            <div class="card-value" id="history-count">0</div>
            <div class="card-note">Recorded snapshots</div>
        </div>

    </div>

    <div class="card" style="margin-top:15px;">
        <div class="card-label">Execution Performance History</div>
        <div class="history-bars" id="performance-chart"></div>
        <div class="empty" id="performance-empty">
            No performance history available.
        </div>
    </div>

</section>


<section id="crashes">

    <div class="section-title">Crash Intelligence</div>

    <div class="two-column">

        <div class="card">
            <h3>Crash Analysis</h3>
            <div class="data-list" id="crash-details">
                <div class="empty">Loading crash analysis...</div>
            </div>
        </div>

        <div class="card">
            <h3>Vulnerability Classification</h3>
            <div class="data-list" id="classification-details">
                <div class="empty">Loading classification...</div>
            </div>
        </div>

    </div>

    <div class="card" style="margin-top:15px;">
        <h3>Crash Prioritization</h3>
        <div class="data-list" id="priority-details">
            <div class="empty">Loading priority report...</div>
        </div>
    </div>

</section>


<section id="regression">

    <div class="section-title">Automated Regression Testing</div>

    <div class="grid">

        <div class="card">
            <div class="card-label">Regression Status</div>
            <div class="card-value" id="regression-status">N/A</div>
        </div>

        <div class="card">
            <div class="card-label">Test Cases</div>
            <div class="card-value blue" id="regression-total">0</div>
        </div>

        <div class="card">
            <div class="card-label">Fixed</div>
            <div class="card-value green" id="regression-fixed">0</div>
        </div>

        <div class="card">
            <div class="card-label">Still Reproducing</div>
            <div class="card-value red" id="regression-reproducing">0</div>
        </div>

    </div>

    <div class="card" style="margin-top:15px;">
        <div class="card-label">Regression Report Details</div>
        <div class="data-list" id="regression-details"></div>
    </div>

</section>


<section id="tests">

    <div class="section-title">Automated Security Test Suite</div>

    <div class="grid">

        <div class="card">
            <div class="card-label">Test Status</div>
            <div class="card-value" id="test-status">N/A</div>
        </div>

        <div class="card">
            <div class="card-label">Total Tests</div>
            <div class="card-value blue" id="test-total">0</div>
        </div>

        <div class="card">
            <div class="card-label">Passed</div>
            <div class="card-value green" id="test-passed">0</div>
        </div>

        <div class="card">
            <div class="card-label">Failed</div>
            <div class="card-value red" id="test-failed">0</div>
        </div>

    </div>

    <div class="card" style="margin-top:15px;">
        <h3>Individual Test Results</h3>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Test Name</th>
                        <th>Status</th>
                        <th>Details</th>
                    </tr>
                </thead>

                <tbody id="test-table">
                    <tr><td colspan="3">Loading test results...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="card" style="margin-top:15px;">
        <h3>Test Execution History</h3>
        <div class="data-list" id="test-history"></div>
    </div>

</section>


<section id="evidence">

    <div class="section-title">Evidence Integrity</div>

    <div class="grid">

        <div class="card">
            <div class="card-label">Export Status</div>
            <div class="card-value" id="evidence-status">N/A</div>
        </div>

        <div class="card">
            <div class="card-label">Collected Files</div>
            <div class="card-value blue" id="evidence-files">0</div>
        </div>

        <div class="card">
            <div class="card-label">Verified Files</div>
            <div class="card-value green" id="evidence-verified">0</div>
        </div>

        <div class="card">
            <div class="card-label">Archive Verification</div>
            <div class="card-value" id="evidence-verification">N/A</div>
        </div>

    </div>

    <div class="card" style="margin-top:15px;">
        <div class="data-list" id="evidence-details"></div>
    </div>

</section>


<div class="footer">
    ZeroTrace Security Research Framework |
    Read-only monitoring dashboard |
    Auto-refresh: 10 seconds
    <br><br>
    This dashboard presents locally generated research reports.
    Results are not independent proof of exploitability or complete security.
</div>

</main>


<script>

const $ = (id) => document.getElementById(id);

function formatNumber(value) {
    if (value === null || value === undefined || value === "") {
        return "0";
    }

    const parsed = Number(value);

    if (!Number.isFinite(parsed)) {
        return String(value);
    }

    return parsed.toLocaleString();
}

function setText(id, value) {
    $(id).textContent =
        value === null || value === undefined || value === ""
        ? "N/A"
        : String(value);
}

function addRow(container, label, value) {
    const row = document.createElement("div");
    row.className = "data-row";

    const left = document.createElement("span");
    left.textContent = label;

    const right = document.createElement("strong");
    right.textContent =
        value === null || value === undefined || value === ""
        ? "N/A"
        : String(value);

    row.append(left, right);
    container.appendChild(row);
}

function showObject(containerId, data, keys) {
    const container = $(containerId);
    container.replaceChildren();

    if (!data || typeof data !== "object" ||
        Object.keys(data).length === 0) {
        container.textContent = "Report not available yet.";
        container.className = "data-list empty";
        return;
    }

    container.className = "data-list";

    for (const [label, key] of keys) {
        addRow(container, label, data[key]);
    }
}

function showTests(tests) {
    const body = $("test-table");
    body.replaceChildren();

    const items = Array.isArray(tests) ? tests : [];

    if (!items.length) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 3;
        cell.textContent = "No test results available.";

        row.appendChild(cell);
        body.appendChild(row);
        return;
    }

    for (const item of items) {
        const row = document.createElement("tr");

        for (const value of [
            item.test,
            item.status,
            item.details
        ]) {
            const cell = document.createElement("td");
            cell.textContent = value || "";
            row.appendChild(cell);
        }

        body.appendChild(row);
    }
}

function showHistory(history) {
    const container = $("test-history");
    container.replaceChildren();

    if (!Array.isArray(history) || history.length === 0) {
        container.textContent = "No test history available.";
        return;
    }

    for (const item of [...history].reverse().slice(0, 10)) {
        const summary = item.summary || {};

        const row = document.createElement("div");
        row.className = "data-row";

        const left = document.createElement("span");
        left.textContent = item.generated_at || "Unknown date";

        const right = document.createElement("strong");
        right.textContent =
            `${item.status || "unknown"} | ` +
            `${summary.passed || 0}/${summary.total || 0} passed`;

        row.append(left, right);
        container.appendChild(row);
    }
}

function showPerformanceHistory(history) {
    const chart = $("performance-chart");
    const empty = $("performance-empty");

    chart.replaceChildren();

    if (!Array.isArray(history) || history.length === 0) {
        empty.style.display = "block";
        return;
    }

    empty.style.display = "none";

    const items = history.slice(-12);

    const values = items.map(item => {
        return Number(
            item.execs_per_sec ??
            item.executions_per_second ??
            item.execution_speed ??
            0
        ) || 0;
    });

    const maxValue = Math.max(...values, 1);

    items.forEach((item, index) => {
        const bar = document.createElement("div");
        bar.className = "history-bar";

        const height = Math.max(
            4,
            (values[index] / maxValue) * 100
        );

        bar.style.height = `${height}%`;
        bar.title = `${values[index]} executions/sec`;

        const label = document.createElement("span");
        label.textContent = String(index + 1);

        bar.appendChild(label);
        chart.appendChild(bar);
    });
}

async function fetchJSON(url) {
    const response = await fetch(url, {
        cache: "no-store"
    });

    if (!response.ok) {
        throw new Error(`${url}: HTTP ${response.status}`);
    }

    return response.json();
}

async function loadDashboard() {
    try {
        const [
            dashboard,
            tests,
            evidence,
            performance,
            regression
        ] = await Promise.all([
            fetchJSON("/api/dashboard"),
            fetchJSON("/api/tests"),
            fetchJSON("/api/evidence"),
            fetchJSON("/api/performance"),
            fetchJSON("/api/regression")
        ]);

        const summary = dashboard.summary || {};
        const fuzzing = summary.fuzzing || {};
        const testSummary = summary.tests || {};
        const regressionSummary = summary.regression || {};
        const evidenceSummary = summary.evidence || {};
        const reports = dashboard.reports || {};

        // Security overview

        setText("executions", formatNumber(fuzzing.executions));
        setText("speed", formatNumber(fuzzing.exec_per_second));
        setText("crashes", formatNumber(fuzzing.crashes));
        setText("corpus", formatNumber(fuzzing.corpus));

        // Fuzzing analytics

        setText("coverage", `${fuzzing.coverage || 0}%`);
        setText("hangs", formatNumber(fuzzing.hangs));
        setText("runtime", fuzzing.runtime);

        const performanceHistory = performance.history || [];

        setText("history-count", performanceHistory.length);
        showPerformanceHistory(performanceHistory);

        // Crash analysis

        showObject(
            "crash-details",
            reports.crash_analysis,
            [
                ["Status", "status"],
                ["Crash detected", "crash_detected"],
                ["Crash type", "crash_type"],
                ["Source location", "source_location"]
            ]
        );

        showObject(
            "classification-details",
            reports.crash_classification,
            [
                ["Vulnerability", "vulnerability"],
                ["Severity", "severity"],
                ["CWE", "cwe"],
                ["Description", "description"]
            ]
        );

        showObject(
            "priority-details",
            reports.crash_priority,
            [
                ["Priority", "priority"],
                ["Priority score", "priority_score"],
                ["Crash type", "crash_type"],
                ["Source location", "source_location"]
            ]
        );

        // Regression

        setText("regression-status", regressionSummary.status ||
            regression.report.regression_status ||
            regression.report.status ||
            "N/A");

        setText("regression-total", regressionSummary.total);
        setText("regression-fixed", regressionSummary.fixed);
        setText(
            "regression-reproducing",
            regressionSummary.still_reproducing
        );

        showObject(
            "regression-details",
            regression.report,
            [
                ["Overall status", "status"],
                ["Regression status", "regression_status"],
                ["Remote workspace", "remote_workspace"],
                ["Generated at", "generated_at"]
            ]
        );

        // Automated tests

        const testReport = tests.latest || {};
        const testData = testReport.summary || {};

        setText("test-status", testReport.status || "N/A");
        setText("test-total", testData.total || 0);
        setText("test-passed", testData.passed || 0);
        setText("test-failed", testData.failed || 0);

        showTests(testReport.tests || []);
        showHistory(tests.history || []);

        // Evidence

        const evidenceData = evidence.evidence || {};

        setText("evidence-status", evidenceData.status || "N/A");
        setText("evidence-files", evidenceData.total_files || 0);

        const verification = evidenceData.verification || {};

        setText(
            "evidence-verified",
            verification.verified_files ??
            evidenceData.verified_files ??
            0
        );

        setText(
            "evidence-verification",
            verification.status ||
            (verification.success === true ? "Verified" : "See report")
        );

        showObject(
            "evidence-details",
            evidenceData,
            [
                ["Archive", "archive"],
                ["Archive size (bytes)", "archive_size_bytes"],
                ["Verification", "verification"],
                ["Generated at", "generated_at"]
            ]
        );

    } catch (error) {
        console.error("Dashboard refresh failed:", error);
    }
}

loadDashboard();
setInterval(loadDashboard, 10000);

</script>

</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/health")
def health():
    return jsonify({
        "status": "online",
        "project": "ZeroTrace",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


if __name__ == "__main__":
    print("\n==========================================")
    print("       ZEROTRACE SECURITY DASHBOARD")
    print("==========================================")
    print("[+] Starting Flask dashboard...")
    print("[+] URL: http://127.0.0.1:5000")
    print("[+] Auto-refresh: 10 seconds")
    print("[+] Mode: Read-only")
    print("==========================================\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True
    )
