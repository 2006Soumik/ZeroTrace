
import json
from pathlib import Path
from datetime import datetime


class RemediationEngine:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.report_dir = self.base_dir / "reports"

    def load_json(self, path):
        if not path.exists():
            return {}

        try:
            with open(path, "r", encoding="utf-8") as file:
                return json.load(file)
        except (json.JSONDecodeError, OSError):
            return {}

    def run(self):

        report_data = self.load_json(
            self.report_dir / "unified_vulnerability_report.json"
        )

        if not report_data:
            return {
                "status": "error",
                "message": "Unified vulnerability report not found."
            }

        findings = report_data.get("correlated_findings", [])
        remediations = []

        for finding in findings:

            evidence = finding.get("evidence", [])

            cwe_values = [
                item.get("cwe", "")
                for item in evidence
                if item.get("cwe", "") != "Unknown"
            ]

            cwe = cwe_values[0] if cwe_values else "Unknown"

            file_name = finding.get("file", "Unknown")
            line = finding.get("line", "Unknown")

            if cwe in ("CWE-120", "CWE-121"):
                vulnerability = "Buffer Overflow"

                vulnerable_code = (
                    "memcpy(buffer, input, (size_t)length);"
                )

                recommended_code = (
                    "if (length > 0 && "
                    "(size_t)length <= sizeof(buffer)) {\n"
                    "    memcpy(buffer, input, (size_t)length);\n"
                    "} else {\n"
                    '    fprintf(stderr, "Input too large or invalid\\n");\n'
                    "    return 1;\n"
                    "}"
                )

                explanation = (
                    "The copy operation can exceed the destination "
                    "buffer capacity. Validate the length before copying."
                )

            else:
                vulnerability = "Manual Review Required"
                vulnerable_code = "Not automatically identified."
                recommended_code = (
                    "Review the vulnerable operation and apply "
                    "appropriate input validation."
                )
                explanation = (
                    "No automatic remediation rule is available "
                    "for this CWE."
                )

            remediations.append({
                "vulnerability": vulnerability,
                "file": file_name,
                "line": line,
                "cwe": cwe,
                "confidence": finding.get("confidence", "Unknown"),
                "evidence_sources": finding.get("evidence_sources", []),
                "vulnerable_code": vulnerable_code,
                "recommended_code": recommended_code,
                "explanation": explanation,
                "status": "Recommendation generated - manual review required"
            })

        output = {
            "tool": "ZeroTrace",
            "module": "Vulnerability Remediation Engine",
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(remediations),
            "remediations": remediations,
            "note": (
                "Recommendations are generated for review. "
                "Original source files are not modified."
            )
        }

        self.report_dir.mkdir(parents=True, exist_ok=True)

        output_path = self.report_dir / "remediation_report.json"

        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(output, file, indent=4)

        print("[+] Remediation analysis completed.")
        print(f"[+] Findings processed: {len(remediations)}")
        print(f"[+] Report: {output_path}")

        return output
