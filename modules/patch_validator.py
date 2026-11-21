
import json
import re
from pathlib import Path
from datetime import datetime


class PatchValidator:

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

    def validate_buffer_overflow(self, source_code):

        lines = source_code.splitlines()
        memcpy_checks = []

        for index, line in enumerate(lines):

            match = re.search(
                r'\bmemcpy\s*\(\s*(\w+)\s*,',
                line
            )

            if not match:
                continue

            destination = match.group(1)

            previous_lines = "\n".join(
                lines[max(0, index - 10):index]
            )

            size_check = re.search(
                r'sizeof\s*\(\s*' + re.escape(destination) + r'\s*\)',
                previous_lines
            )

            length_check = re.search(
                r'(?:<=|>=|<|>)\s*sizeof\s*\(\s*'
                + re.escape(destination) + r'\s*\)',
                previous_lines
            )

            conditional_check = re.search(
                r'\bif\s*\(',
                previous_lines
            )

            safe_guard = (
                size_check is not None
                and length_check is not None
                and conditional_check is not None
            )

            memcpy_checks.append({
                "line": index + 1,
                "destination": destination,
                "status": "Guard detected" if safe_guard
                          else "Potentially unsafe",
                "message": (
                    "A nearby conditional destination-size check was detected."
                    if safe_guard else
                    "No suitable nearby destination-size check was detected."
                )
            })

        if not memcpy_checks:
            return {
                "status": "Review Required",
                "message": "No memcpy operation found. Manual review required."
            }

        passed = all(
            item["status"] == "Guard detected"
            for item in memcpy_checks
        )

        return {
            "status": "Pass - Heuristic Check" if passed
                      else "Review Required",
            "memcpy_checks": memcpy_checks
        }

    def run(self, patched_path=None):

        if not patched_path:
            return {
                "status": "error",
                "message": "Provide a patched source file path."
            }

        patched_file = Path(patched_path)

        if not patched_file.is_absolute():
            patched_file = self.base_dir / patched_file

        if not patched_file.exists() or not patched_file.is_file():
            return {
                "status": "error",
                "message": f"Patched file not found: {patched_file}"
            }

        remediation = self.load_json(
            self.report_dir / "remediation_report.json"
        )

        if not remediation:
            return {
                "status": "error",
                "message": "Remediation report not found."
            }

        try:
            source_code = patched_file.read_text(encoding="utf-8")
        except OSError as error:
            return {
                "status": "error",
                "message": str(error)
            }

        results = []

        for finding in remediation.get("remediations", []):

            if finding.get("cwe") in ("CWE-120", "CWE-121"):
                validation = self.validate_buffer_overflow(source_code)
            else:
                validation = {
                    "status": "Review Required",
                    "message": "No automated validation rule available."
                }

            results.append({
                "original_file": finding.get("file", "Unknown"),
                "original_line": finding.get("line", "Unknown"),
                "cwe": finding.get("cwe", "Unknown"),
                "validation": validation
            })

        output = {
            "tool": "ZeroTrace",
            "module": "Patch Validation Engine",
            "validated_at": datetime.now().isoformat(),
            "patched_file": str(patched_file.resolve()),
            "total_findings_checked": len(results),
            "results": results,
            "limitations": [
                "Validation uses heuristic source-code checks.",
                "A detected guard does not prove the patch is secure.",
                "Compilation and runtime testing are still required.",
                "Manual security review is recommended."
            ]
        }

        self.report_dir.mkdir(parents=True, exist_ok=True)

        output_path = self.report_dir / "patch_validation_report.json"

        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(output, file, indent=4)

        print("[+] Patch validation completed.")
        print(f"[+] Findings checked: {len(results)}")
        print(f"[+] Report: {output_path}")

        return output
