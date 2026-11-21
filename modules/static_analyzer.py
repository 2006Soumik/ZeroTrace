
import json
import re
from pathlib import Path
from datetime import datetime, timezone


class StaticAnalyzer:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.output_file = self.base_dir / "reports" / "sast_report.json"

        self.extensions = {".c", ".h", ".cpp", ".hpp", ".py"}

        self.excluded_dirs = {
            ".git", "__pycache__", ".venv", "venv",
            "reports", "logs"
        }

        self.rules = [
            {
                "name": "Unsafe gets() function",
                "pattern": r"\bgets\s*\(",
                "severity": "High",
                "cwe": "CWE-242",
                "description": "gets() does not limit input length."
            },
            {
                "name": "Unsafe strcpy() function",
                "pattern": r"\bstrcpy\s*\(",
                "severity": "Medium",
                "cwe": "CWE-120",
                "description": "strcpy() does not check destination capacity."
            },
            {
                "name": "Unsafe strcat() function",
                "pattern": r"\bstrcat\s*\(",
                "severity": "Medium",
                "cwe": "CWE-120",
                "description": "strcat() does not check remaining destination capacity."
            },
            {
                "name": "Unsafe sprintf() function",
                "pattern": r"\bsprintf\s*\(",
                "severity": "Medium",
                "cwe": "CWE-120",
                "description": "sprintf() does not enforce destination buffer size."
            },
            {
                "name": "Unbounded scanf string input",
                "pattern": r"\bscanf\s*\(\s*['\"]%s",
                "severity": "Medium",
                "cwe": "CWE-120",
                "description": "scanf() with %s may read more data than the destination can hold."
            },
            {
                "name": "Review memcpy() bounds",
                "pattern": r"\bmemcpy\s*\(",
                "severity": "Medium",
                "cwe": "CWE-120",
                "description": "Verify that the copy length does not exceed destination capacity."
            },
            {
                "name": "Potential command injection",
                "pattern": r"\bsystem\s*\(",
                "severity": "High",
                "cwe": "CWE-78",
                "description": "Review whether untrusted input can reach a system command."
            },
            {
                "name": "Python dynamic code execution",
                "pattern": r"\b(?:eval|exec)\s*\(",
                "severity": "Medium",
                "cwe": "CWE-95",
                "description": "Dynamic code execution may be unsafe with untrusted input."
            },
            {
                "name": "Subprocess shell execution",
                "pattern": r"\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True",
                "severity": "High",
                "cwe": "CWE-78",
                "description": "Shell execution requires careful validation of command input."
            },
            {
                "name": "Potential hardcoded credential",
                "pattern": r"""(?i)\b(?:password|passwd|api_key|secret|token)\b\s*[:=]\s*["'][^"']{4,}["']""",
                "severity": "High",
                "cwe": "CWE-798",
                "description": "A possible credential or secret is directly assigned in source code."
            }
        ]

    def get_files(self, target):

        if target.is_file():
            if target.suffix.lower() in self.extensions:
                return [target]
            return []

        files = []

        for path in target.rglob("*"):
            if not path.is_file():
                continue

            if any(part in self.excluded_dirs for part in path.parts):
                continue

            if path.suffix.lower() in self.extensions:
                files.append(path)

        return files

    def scan_file(self, file_path):

        findings = []

        try:
            lines = file_path.read_text(
                encoding="utf-8",
                errors="replace"
            ).splitlines()
        except OSError:
            return findings

        for line_number, line in enumerate(lines, start=1):

            stripped = line.strip()

            if not stripped or stripped.startswith(("//", "#", "/*", "*")):
                continue

            for rule in self.rules:

                if re.search(rule["pattern"], line):

                    findings.append({
                        "file": str(file_path.relative_to(self.base_dir)),
                        "line": line_number,
                        "rule": rule["name"],
                        "severity": rule["severity"],
                        "cwe": rule["cwe"],
                        "description": rule["description"],
                        "code": stripped
                    })

        return findings

    def run(self, target_path=None):

        if target_path:
            target = Path(target_path)

            if not target.is_absolute():
                target = self.base_dir / target
        else:
            target = self.base_dir / "target.c"

        if not target.exists():
            return {
                "status": "failed",
                "message": f"Target not found: {target}"
            }

        if not target.is_file() and not target.is_dir():
            return {
                "status": "failed",
                "message": "Target must be a file or directory."
            }

        files = self.get_files(target)

        findings = []

        for file_path in files:
            findings.extend(self.scan_file(file_path))

        severity_counts = {
            "High": 0,
            "Medium": 0,
            "Low": 0
        }

        for finding in findings:
            severity_counts[finding["severity"]] += 1

        report = {
            "tool": "ZeroTrace",
            "module": "Static Vulnerability Analyzer",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": str(target),
            "files_scanned": len(files),
            "total_findings": len(findings),
            "severity_summary": severity_counts,
            "findings": findings,
            "limitations": [
                "Pattern-based static analysis can produce false positives.",
                "Not every unsafe function call is automatically exploitable.",
                "Findings require manual source-code verification.",
                "This scanner does not execute the target program."
            ]
        }

        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.output_file, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print("[+] Static analysis completed.")
        print(f"[+] Files scanned: {len(files)}")
        print(f"[+] Findings: {len(findings)}")
        print(f"[+] High: {severity_counts['High']}")
        print(f"[+] Medium: {severity_counts['Medium']}")
        print(f"[+] Report: {self.output_file}")

        return report
