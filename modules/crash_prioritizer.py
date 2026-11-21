
import json
from pathlib import Path
from datetime import datetime, timezone


class CrashPrioritizer:

    def __init__(self):
        self.analysis_path = Path("reports/crashes/crash_analysis.json")
        self.classification_path = Path(
            "reports/crashes/vulnerability_classification.json"
        )
        self.output_path = Path(
            "reports/crashes/crash_priority.json"
        )

    def run(self):

        for path in (self.analysis_path, self.classification_path):
            if not path.exists():
                return {
                    "status": "failed",
                    "message": f"Required report missing: {path}"
                }

        with self.analysis_path.open(encoding="utf-8") as file:
            analysis = json.load(file)

        with self.classification_path.open(encoding="utf-8") as file:
            classification = json.load(file)

        score = 0
        reasons = []

        if analysis.get("crash_detected"):
            score += 40
            reasons.append("Sanitizer-confirmed crash")

        crash_types = classification.get("classifications", [])

        high_risk_types = {
            "Stack Buffer Overflow",
            "Heap Buffer Overflow",
            "Heap Use After Free",
            "Double Free"
        }

        if high_risk_types.intersection(crash_types):
            score += 30
            reasons.append("Memory corruption classification")

        if analysis.get("source_location"):
            score += 15
            reasons.append("Source location identified")

        if analysis.get("replay_exit_code") not in (None, 0):
            score += 15
            reasons.append("Target exited with an error during replay")

        if score >= 80:
            priority = "Critical"
        elif score >= 60:
            priority = "High"
        elif score >= 30:
            priority = "Medium"
        else:
            priority = "Low"

        result = {
            "tool": "ZeroTrace",
            "module": "Crash Prioritizer",
            "prioritized_at": datetime.now(timezone.utc).isoformat(),
            "priority_score": score,
            "priority": priority,
            "reasons": reasons,
            "crash_type": crash_types,
            "source_location": analysis.get("source_location"),
            "note": (
                "Research triage score only. "
                "Not a CVSS score or exploitability assessment."
            )
        }

        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        with self.output_path.open("w", encoding="utf-8") as file:
            json.dump(result, file, indent=4)

        print("[+] Crash prioritization completed.")
        print("[+] Score:", score)
        print("[+] Priority:", priority)
        print("[+] Report:", self.output_path)

        return result
