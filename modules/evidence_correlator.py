
import json
from pathlib import Path
from datetime import datetime, timezone


class EvidenceCorrelator:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.report_dir = self.base_dir / "reports" / "crashes"

        self.output_file = self.report_dir / "correlated_evidence.json"

        self.sources = {
            "crash_analysis": self.report_dir / "crash_analysis.json",
            "vulnerability_classification": self.report_dir / "vulnerability_classification.json",
            "crash_priority": self.report_dir / "crash_priority.json",
            "root_cause": self.report_dir / "root_cause_report.json",
            "exploitability": self.report_dir / "exploitability_assessment.json"
        }

    def load_report(self, path):
        if not path.exists():
            return None

        try:
            with open(path, "r", encoding="utf-8") as file:
                return json.load(file)
        except (json.JSONDecodeError, OSError):
            return None

    def run(self):

        evidence = {}
        missing_reports = []

        for name, path in self.sources.items():
            report = self.load_report(path)

            if report is None:
                missing_reports.append(name)
            else:
                evidence[name] = report

        if not evidence:
            return {
                "status": "failed",
                "message": "No analysis reports were found."
            }

        analysis = evidence.get("crash_analysis", {})
        classification = evidence.get("vulnerability_classification", {})
        priority = evidence.get("crash_priority", {})
        root_cause = evidence.get("root_cause", {})
        exploitability = evidence.get("exploitability", {})

        source_location = analysis.get("source_location", {})

        # Correctly read classification list.
        classifications = classification.get("classifications", [])

        if not classifications:
            classifications = ["Unknown"]

        # Correctly read priority score.
        priority_score = priority.get("priority_score")

        correlated_record = {
            "record_id": "ZT-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),

            "crash_type": analysis.get("crash_type", "Unknown"),

            "source_location": {
                "file": source_location.get("file", "Unknown"),
                "line": source_location.get("line"),
                "column": source_location.get("column")
            },

            "vulnerability": {
                "classification": classifications,
                "severity": classification.get("severity", "Unknown")
            },

            "crash_priority": {
                "score": priority_score,
                "priority": priority.get("priority", "Unknown")
            },

            "root_cause": {
                "function": root_cause.get("function", "Unknown"),
                "operation": root_cause.get("operation", "Unknown"),
                "affected_buffer": root_cause.get("affected_buffer", "Unknown"),
                "buffer_size_bytes": root_cause.get("buffer_size_bytes"),
                "reported_write_size_bytes": root_cause.get(
                    "reported_write_size_bytes"
                ),
                "overflow_bytes": root_cause.get("overflow_bytes")
            },

            "exploitability": {
                "score": exploitability.get("assessment_score"),
                "assessment": exploitability.get("assessment", "Unknown"),
                "indicators": exploitability.get("indicators", [])
            }
        }

        report = {
            "tool": "ZeroTrace",
            "module": "Evidence Correlator",
            "correlated_at": datetime.now(timezone.utc).isoformat(),
            "record": correlated_record,
            "evidence_sources": list(evidence.keys()),
            "missing_reports": missing_reports,
            "limitations": [
                "Correlation combines existing reports; it does not independently verify findings.",
                "Scores and severity values retain the meaning assigned by their source modules.",
                "Manual review is required before treating the record as a confirmed vulnerability."
            ]
        }

        self.report_dir.mkdir(parents=True, exist_ok=True)

        with open(self.output_file, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print("[+] Evidence correlation completed.")
        print(f"[+] Evidence sources: {len(evidence)}")
        print(f"[+] Missing reports: {len(missing_reports)}")
        print(f"[+] Record ID: {correlated_record['record_id']}")
        print(f"[+] Report: {self.output_file}")

        return report
