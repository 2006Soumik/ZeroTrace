
import json
from pathlib import Path
from datetime import datetime, timezone


class ResearchReportGenerator:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.report_dir = self.base_dir / "reports" / "crashes"

        self.input_file = self.report_dir / "correlated_evidence.json"
        self.output_file = self.base_dir / "reports" / "zerotrace_research_report.md"

    def run(self):

        if not self.input_file.exists():
            return {
                "status": "failed",
                "message": "Correlated evidence report not found."
            }

        try:
            with open(self.input_file, "r", encoding="utf-8") as file:
                data = json.load(file)
        except (json.JSONDecodeError, OSError) as error:
            return {
                "status": "failed",
                "message": str(error)
            }

        record = data.get("record", {})

        vulnerability = record.get("vulnerability", {})
        source = record.get("source_location", {})
        root_cause = record.get("root_cause", {})
        exploitability = record.get("exploitability", {})
        priority = record.get("crash_priority", {})

        report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        markdown = f"""# ZeroTrace Vulnerability Research Report

## 1. Report Information

- **Tool:** ZeroTrace
- **Record ID:** {record.get('record_id', 'Unknown')}
- **Generated:** {report_date}
- **Report Type:** Automated Vulnerability Research
- **Validation:** Preliminary laboratory finding

## 2. Executive Summary

ZeroTrace identified a crash during controlled fuzz testing.
The available evidence indicates a potential memory corruption
vulnerability requiring further manual validation.

## 3. Vulnerability Details

- **Crash Type:** {record.get('crash_type', 'Unknown')}
- **Classification:** {vulnerability.get('classification', 'Unknown')}
- **Severity:** {vulnerability.get('severity', 'Unknown')}
- **Crash Priority:** {priority.get('priority', 'Unknown')}
- **Priority Score:** {priority.get('score', 'Unknown')}

## 4. Affected Source Location

- **File:** {source.get('file', 'Unknown')}
- **Line:** {source.get('line', 'Unknown')}
- **Column:** {source.get('column', 'Unknown')}
- **Function:** {root_cause.get('function', 'Unknown')}

## 5. Technical Root Cause

- **Operation:** {root_cause.get('operation', 'Unknown')}
- **Affected Buffer:** {root_cause.get('affected_buffer', 'Unknown')}
- **Buffer Capacity:** {root_cause.get('buffer_size_bytes', 'Unknown')} bytes
- **Reported Write:** {root_cause.get('reported_write_size_bytes', 'Unknown')} bytes
- **Calculated Overflow:** {root_cause.get('overflow_bytes', 'Unknown')} bytes

{root_cause.get('root_cause', 'Root cause information unavailable.')}

## 6. Exploitability Indicators

- **Assessment Score:** {exploitability.get('score', 'Unknown')}/100
- **Assessment:** {exploitability.get('assessment', 'Unknown')}

### Observed Indicators

{chr(10).join('- ' + str(item) for item in exploitability.get('indicators', [])) or '- No indicators recorded.'}

## 7. Evidence Sources

{chr(10).join('- ' + str(item) for item in data.get('evidence_sources', [])) or '- No evidence sources recorded.'}

## 8. Recommended Remediation

1. Validate input length before copying data.
2. Ensure destination buffer capacity is respected.
3. Use safe, bounded memory-copy operations.
4. Rebuild the target with appropriate compiler protections.
5. Repeat fuzz testing after remediation.
6. Verify the fix using AddressSanitizer.

## 9. Limitations

- This report is generated automatically from existing ZeroTrace reports.
- Exploitability scores are custom research heuristics, not CVSS scores.
- A crash does not prove practical exploitability.
- The findings relate to a controlled laboratory target.
- Manual source-code review and independent validation are required.

## 10. Conclusion

The laboratory test demonstrated a memory-safety failure.
Further investigation and remediation validation are required
before making claims about real-world impact.
"""

        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        self.output_file.write_text(markdown, encoding="utf-8")

        print("[+] Research report generated.")
        print(f"[+] Record ID: {record.get('record_id', 'Unknown')}")
        print(f"[+] Report: {self.output_file}")

        return {
            "status": "success",
            "module": "Research Report Generator",
            "report_path": str(self.output_file),
            "record_id": record.get("record_id")
        }
