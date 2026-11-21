
import json
import re
from pathlib import Path
from datetime import datetime, timezone


class DataFlowAnalyzer:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.output_file = self.base_dir / "reports" / "dataflow_report.json"

    def extract_call_args(self, line, function):
        """Extract function arguments, including nested parentheses."""

        pattern = re.compile(
            r"\b" + re.escape(function) + r"\s*\("
        )

        results = []

        for match in pattern.finditer(line):
            start = match.end()
            depth = 1
            args = []
            current = ""

            for char in line[start:]:

                if char == "(":
                    depth += 1
                    current += char

                elif char == ")":
                    depth -= 1

                    if depth == 0:
                        args.append(current.strip())
                        break

                    current += char

                elif char == "," and depth == 1:
                    args.append(current.strip())
                    current = ""

                else:
                    current += char

            if depth == 0:
                results.append(args)

        return results

    def run(self, target_path="target.c"):

        target = Path(target_path)

        if not target.is_absolute():
            target = self.base_dir / target

        if not target.is_file():
            return {
                "status": "failed",
                "message": f"Source file not found: {target}"
            }

        lines = target.read_text(
            encoding="utf-8",
            errors="replace"
        ).splitlines()

        source_findings = []
        buffer_sizes = {}
        read_operations = []
        read_length_variables = {}
        flows = []

        # Phase 1: Identify declared character buffers

        for line_number, line in enumerate(lines, start=1):

            match = re.search(
                r"\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]",
                line
            )

            if match:
                buffer_sizes[match.group(1)] = {
                    "capacity_bytes": int(match.group(2)),
                    "declaration_line": line_number
                }

        # Phase 2: Identify read() input and maximum length

        for line_number, line in enumerate(lines, start=1):

            calls = self.extract_call_args(line, "read")

            for args in calls:

                if len(args) < 3:
                    continue

                input_buffer = args[1].strip()
                read_limit = args[2].strip()

                maximum_read = None

                sizeof_match = re.fullmatch(
                    r"sizeof\s*\(\s*(\w+)\s*\)",
                    read_limit
                )

                if sizeof_match:

                    sized_variable = sizeof_match.group(1)

                    if sized_variable in buffer_sizes:
                        maximum_read = buffer_sizes[sized_variable][
                            "capacity_bytes"
                        ]

                elif read_limit.isdigit():
                    maximum_read = int(read_limit)

                source_findings.append({
                    "source": "read",
                    "variable": input_buffer,
                    "line": line_number,
                    "maximum_read_expression": read_limit,
                    "maximum_read_bytes": maximum_read
                })

                read_operations.append({
                    "input_buffer": input_buffer,
                    "maximum_read": maximum_read,
                    "line": line_number
                })

                # Identify variable receiving read() return value

                assignment = re.search(
                    r"\b(\w+)\s*=\s*read\s*\(",
                    line
                )

                if assignment:
                    read_length_variables[assignment.group(1)] = {
                        "source_line": line_number,
                        "input_buffer": input_buffer
                    }

        # Phase 3: Analyze memcpy() operations

        for line_number, line in enumerate(lines, start=1):

            calls = self.extract_call_args(line, "memcpy")

            for args in calls:

                if len(args) < 3:
                    continue

                destination = args[0].strip()
                source = args[1].strip()
                copy_expression = args[2].strip()

                destination_info = buffer_sizes.get(destination)
                source_info = buffer_sizes.get(source)

                destination_capacity = (
                    destination_info["capacity_bytes"]
                    if destination_info else None
                )

                source_capacity = (
                    source_info["capacity_bytes"]
                    if source_info else None
                )

                # Remove simple C type casts

                normalized_length = re.sub(
                    r"^\(\s*(?:unsigned\s+)?(?:size_t|int|long|short|ssize_t)\s*\)\s*",
                    "",
                    copy_expression
                ).strip()

                maximum_copy = None
                length_origin = None

                if normalized_length.isdigit():

                    maximum_copy = int(normalized_length)

                elif normalized_length in read_length_variables:

                    length_origin = "read() return value"

                    origin_buffer = read_length_variables[
                        normalized_length
                    ]["input_buffer"]

                    for operation in read_operations:

                        if operation["input_buffer"] == origin_buffer:
                            maximum_copy = operation["maximum_read"]
                            break

                potential_overflow = (
                    maximum_copy is not None
                    and destination_capacity is not None
                    and maximum_copy > destination_capacity
                )

                excess_bytes = (
                    maximum_copy - destination_capacity
                    if potential_overflow else 0
                )

                flows.append({
                    "source": "read",
                    "source_buffer": source,
                    "destination_buffer": destination,
                    "sink": "memcpy",
                    "sink_line": line_number,
                    "copy_length_expression": copy_expression,
                    "normalized_length": normalized_length,
                    "length_origin": length_origin,
                    "source_capacity_bytes": source_capacity,
                    "destination_capacity_bytes": destination_capacity,
                    "maximum_copy_bytes": maximum_copy,
                    "potential_overflow": potential_overflow,
                    "potential_excess_bytes": excess_bytes,
                    "severity": (
                        "High - Potential Buffer Overflow"
                        if potential_overflow
                        else "Review Required"
                    ),
                    "data_flow": (
                        f"read() -> {source} -> "
                        f"{normalized_length} -> memcpy() -> {destination}"
                    )
                })

        # Phase 4: Generate report

        report = {
            "tool": "ZeroTrace",
            "module": "Buffer Size and Length Analyzer",
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "target": str(target),
            "buffers": buffer_sizes,
            "input_sources": source_findings,
            "read_length_variables": read_length_variables,
            "data_flows": flows,
            "total_flows": len(flows),
            "limitations": [
                "Uses lightweight, line-based parsing.",
                "Only simple character-array declarations are recognized.",
                "Complex expressions, pointers and aliases may be missed.",
                "Maximum copy size is an upper-bound estimate.",
                "Does not prove runtime exploitability."
            ]
        }

        self.output_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(self.output_file, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print("[+] Buffer and length analysis completed.")
        print(f"[+] Buffers identified: {len(buffer_sizes)}")
        print(f"[+] Input sources: {len(source_findings)}")
        print(f"[+] Data flows: {len(flows)}")

        for flow in flows:

            print(
                f"[+] Destination capacity: "
                f"{flow['destination_capacity_bytes']} bytes"
            )

            print(
                f"[+] Maximum copy estimate: "
                f"{flow['maximum_copy_bytes']} bytes"
            )

            print(
                f"[+] Potential excess: "
                f"{flow['potential_excess_bytes']} bytes"
            )

            print(
                f"[+] Potential overflow: "
                f"{flow['potential_overflow']}"
            )

        print(f"[+] Report: {self.output_file}")

        return report
