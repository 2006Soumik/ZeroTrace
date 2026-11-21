
import json
from pathlib import Path
from datetime import datetime, timezone

from modules.crash_analyzer import CrashAnalyzer
from modules.vulnerability_classifier import VulnerabilityClassifier
from modules.crash_deduplicator import CrashDeduplicator
from modules.crash_prioritizer import CrashPrioritizer


class CrashIntelligenceEngine:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent

        self.config_path = self.base_dir / "config" / "config.json"
        self.report_dir = self.base_dir / "reports" / "crashes"

        self.output_path = (
            self.report_dir / "crash_intelligence_report.json"
        )

    def load_config(self):
        if not self.config_path.exists():
            raise FileNotFoundError("config/config.json not found.")

        with self.config_path.open("r", encoding="utf-8") as file:
            config = json.load(file)

        kali = config.get("kali", {})
        host = kali.get("host")
        username = kali.get("username")

        if not host or not username:
            raise ValueError("Kali host or username missing in config.")

        return host, username

    def save_report(self, report):
        self.report_dir.mkdir(parents=True, exist_ok=True)

        with self.output_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=4, default=str)

    def run(self):

        report = {
            "tool": "ZeroTrace",
            "module": "Crash Intelligence Engine",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_status": "running",
            "stages": {},
            "limitations": [
                "Crash fingerprints are heuristic and do not prove identical root causes.",
                "Priority scores are research-triage scores, not CVSS scores.",
                "Crash detection does not prove real-world exploitability.",
                "Results depend on the quality of the target and sanitizer evidence."
            ]
        }

        try:
            host, username = self.load_config()

            # Stage 1: Crash Analysis
            print("\n[1/4] Running Crash Analyzer...")

            analysis_result = CrashAnalyzer().run(host, username)

            report["stages"]["crash_analysis"] = analysis_result

            if (
                not isinstance(analysis_result, dict)
                or analysis_result.get("status") != "success"
            ):
                raise RuntimeError("Crash analysis failed.")

            analysis_path = self.report_dir / "crash_analysis.json"

            if not analysis_path.exists():
                raise FileNotFoundError(
                    "Crash analysis report was not generated."
                )

            with analysis_path.open("r", encoding="utf-8") as file:
                analysis_data = json.load(file)

            if not analysis_data.get("crash_detected"):
                raise RuntimeError(
                    "No sanitizer-confirmed crash. "
                    "Classification and prioritization stopped."
                )

            # Stage 2: Vulnerability Classification
            print("\n[2/4] Running Vulnerability Classifier...")

            classification_result = VulnerabilityClassifier().run()

            report["stages"]["vulnerability_classification"] = (
                classification_result
            )

            if (
                not isinstance(classification_result, dict)
                or classification_result.get("status") == "failed"
            ):
                raise RuntimeError("Vulnerability classification failed.")

            # Stage 3: Crash Deduplication
            print("\n[3/4] Running Crash Deduplicator...")

            deduplication_result = CrashDeduplicator().run(
                host,
                username
            )

            report["stages"]["crash_deduplication"] = (
                deduplication_result
            )

            if (
                not isinstance(deduplication_result, dict)
                or deduplication_result.get("status") != "completed"
            ):
                raise RuntimeError("Crash deduplication failed.")

            # Stage 4: Crash Prioritization
            print("\n[4/4] Running Crash Prioritizer...")

            priority_result = CrashPrioritizer().run()

            report["stages"]["crash_prioritization"] = priority_result

            if (
                not isinstance(priority_result, dict)
                or "priority_score" not in priority_result
                or "priority" not in priority_result
            ):
                raise RuntimeError(
                    "Crash prioritization did not return a valid result."
                )

            report["overall_status"] = "completed"

            self.save_report(report)

            print("\n[+] Crash Intelligence completed successfully.")
            print("[+] Priority:", priority_result["priority"])
            print("[+] Score:", priority_result["priority_score"])
            print("[+] Report:", self.output_path)

            return report

        except Exception as error:

            report["overall_status"] = "failed"
            report["error"] = str(error)

            self.save_report(report)

            print("\n[-] Crash Intelligence failed:", error)
            print("[-] Report:", self.output_path)

            return report


if __name__ == "__main__":
    CrashIntelligenceEngine().run()
