import json
import re
from pathlib import Path
from datetime import datetime, timezone


class RootCauseAnalyzer:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.analysis_file = self.base_dir / "reports" / "crashes" / "crash_analysis.json"
        self.source_file = self.base_dir / "target.c"
        self.report_file = self.base_dir / "reports" / "crashes" / "root_cause_report.json"

    def run(self):

        if not self.analysis_file.exists() or not self.source_file.exists():
            return {"status": "failed", "message": "Required analysis or source file missing."}

        with open(self.analysis_file, "r", encoding="utf-8") as file:
            analysis = json.load(file)

        source = self.source_file.read_text(encoding="utf-8", errors="replace")
        lines = source.splitlines()

        location = analysis.get("source_location", {})
        line_number = location.get("line", 0)

        if not isinstance(line_number, int) or not 1 <= line_number <= len(lines):
            return {"status": "failed", "message": "Invalid source line number."}

        vulnerable_line = lines[line_number - 1].strip()

        operation = "Unknown"
        affected_buffer = "Unknown"
        buffer_size = None

        memcpy_match = re.search(
            r"\b(memcpy|memmove|strcpy|strncpy)\s*\(\s*(\w+)",
            vulnerable_line
        )

        if memcpy_match:
            operation = memcpy_match.group(1)
            affected_buffer = memcpy_match.group(2)

        if affected_buffer != "Unknown":
            declaration = re.search(
                rf"\b(?:char|unsigned\s+char)\s+{re.escape(affected_buffer)}\s*\[\s*(\d+)\s*\]",
                source
            )

            if declaration:
                buffer_size = int(declaration.group(1))

        write_match = re.search(
            r"WRITE of size (\d+)",
            analysis.get("raw_output", "")
        )

        write_size = int(write_match.group(1)) if write_match else None

        function = "Unknown"
        for index in range(line_number - 1, -1, -1):
            match = re.search(
                r"\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{",
                lines[index]
            )
            if match and match.group(1) not in {"if", "while", "for", "switch"}:
                function = match.group(1)
                break

        overflow_bytes = None
        if buffer_size is not None and write_size is not None:
            overflow_bytes = max(0, write_size - buffer_size)

        root_cause = (
            f"{operation} copies data into {affected_buffer}, "
            "but the destination capacity is not validated."
        )

        if buffer_size is not None:
            root_cause += f" The destination buffer has a capacity of {buffer_size} bytes."

        if overflow_bytes is not None and overflow_bytes > 0:
            root_cause += f" The reported write exceeds that capacity by {overflow_bytes} bytes."

        report = {
            "tool": "ZeroTrace",
            "module": "Root Cause Analyzer",
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "function": function,
            "vulnerable_line": vulnerable_line,
            "operation": operation,
            "affected_buffer": affected_buffer,
            "buffer_size_bytes": buffer_size,
            "reported_write_size_bytes": write_size,
            "overflow_bytes": overflow_bytes,
            "root_cause": root_cause,
            "recommendations": [
                "Validate input length before copying.",
                "Ensure the copy never exceeds destination buffer capacity.",
                "Use safer bounded input and copying logic.",
                "Run AddressSanitizer tests after fixing the code."
            ],
            "limitations": "Automated preliminary analysis. Manual source and runtime review is required."
        }

        self.report_file.parent.mkdir(parents=True, exist_ok=True)

        with open(self.report_file, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print("[+] Root cause analysis completed.")
        print(f"[+] Affected buffer: {affected_buffer}")
        print(f"[+] Buffer capacity: {buffer_size} bytes")
        print(f"[+] Reported write: {write_size} bytes")

        return report