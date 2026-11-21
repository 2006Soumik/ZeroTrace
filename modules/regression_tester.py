
import json
import shlex
from datetime import datetime, timezone
from pathlib import Path

from integrations.kali_worker import KaliWorker


class RegressionTester:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.crash_dir = self.base_dir / "reports" / "crashes"
        self.report_path = (
            self.base_dir / "reports" / "regression_report.json"
        )

    def save_report(self, report):
        self.report_path.parent.mkdir(parents=True, exist_ok=True)

        report["generated_at"] = datetime.now(
            timezone.utc
        ).isoformat()

        with self.report_path.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print("\n[+] Regression testing completed.")
        print("[+] Status:", report.get("status"))
        print("[+] Report:", self.report_path)

        return report

    def collect_crashes(self):
        if not self.crash_dir.exists():
            return []

        return sorted(
            path for path in self.crash_dir.iterdir()
            if path.is_file()
            and path.name.startswith("id_")
            and path.suffix.lower() != ".json"
        )

    def classify_execution(self, output):
        outcome = "unknown"
        exit_code = None

        for line in output.splitlines():
            if line.startswith("ZT_RESULT:"):
                outcome = line.split(":", 1)[1].strip()

            elif line.startswith("ZT_EXIT:"):
                try:
                    exit_code = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass

        if outcome == "asan_crash":
            final_outcome = "asan_crash"

        elif outcome == "timeout":
            final_outcome = "timeout"

        elif (
            "Input too large" in output
            and exit_code == 1
            and "ERROR: AddressSanitizer" not in output
        ):
            final_outcome = "safely_rejected"

        elif outcome == "passed" and exit_code == 0:
            final_outcome = "passed"

        elif outcome == "nonzero_exit":
            final_outcome = "nonzero_exit"

        else:
            final_outcome = "unknown"

        return {
            "outcome": final_outcome,
            "exit_code": exit_code,
            "details": output[-4000:]
        }

    def run(
        self,
        host,
        username,
        original_path="target.c",
        patched_path="target_patched.c",
        timeout_seconds=5
    ):
        original_file = self.base_dir / original_path
        patched_file = self.base_dir / patched_path

        report = {
            "tool": "ZeroTrace",
            "module": "Automated Regression Tester",
            "started_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "checks": {},
            "results": [],
            "limitations": [
                "Only collected crash inputs are replayed.",
                "Results apply only to the tested binaries and environment.",
                "Safe rejection is based on observed output and exit code.",
                "Passing regression tests do not prove absence of vulnerabilities."
            ]
        }

        if not original_file.is_file():
            report["status"] = "failed"
            report["message"] = "Original target.c not found."
            return self.save_report(report)

        if not patched_file.is_file():
            report["status"] = "failed"
            report["message"] = "Patched target.c not found."
            return self.save_report(report)

        if (
            not isinstance(timeout_seconds, int)
            or not 1 <= timeout_seconds <= 60
        ):
            report["status"] = "failed"
            report["message"] = "Timeout must be between 1 and 60 seconds."
            return self.save_report(report)

        crashes = self.collect_crashes()

        if not crashes:
            report["status"] = "failed"
            report["message"] = "No crash input files found."
            return self.save_report(report)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        remote_dir = (
            f"/home/{username}/zerotrace_worker/lab/"
            f"regression_{timestamp}"
        )

        worker = KaliWorker(host, username)

        try:
            if not worker.connect():
                report["status"] = "failed"
                report["message"] = "Kali connection failed."
                return self.save_report(report)

            setup = worker.execute_command(
                f"mkdir -p {shlex.quote(remote_dir)}"
            )

            if setup["exit_code"] != 0:
                report["status"] = "failed"
                report["message"] = "Remote workspace creation failed."
                return self.save_report(report)

            remote_original = f"{remote_dir}/original.c"
            remote_patched = f"{remote_dir}/patched.c"

            worker.sftp.put(str(original_file), remote_original)
            worker.sftp.put(str(patched_file), remote_patched)

            compile_commands = {
                "original": (
                    f"cd {shlex.quote(remote_dir)} && "
                    "AFL_USE_ASAN=1 afl-clang-fast "
                    "-g -O1 -fno-omit-frame-pointer "
                    "-o original_target original.c"
                ),
                "patched": (
                    f"cd {shlex.quote(remote_dir)} && "
                    "AFL_USE_ASAN=1 afl-clang-fast "
                    "-g -O1 -fno-omit-frame-pointer "
                    "-o patched_target patched.c"
                )
            }

            compile_results = {}

            for name, command in compile_commands.items():
                result = worker.execute_command(command)

                compile_results[name] = {
                    "status": (
                        "passed" if result["exit_code"] == 0
                        else "failed"
                    ),
                    "exit_code": result["exit_code"],
                    "output": result["output"],
                    "error": result["error"]
                }

            report["checks"]["compilation"] = compile_results

            if any(
                item["status"] != "passed"
                for item in compile_results.values()
            ):
                report["status"] = "failed"
                report["message"] = "Target compilation failed."
                return self.save_report(report)

            for index, crash_file in enumerate(crashes, start=1):
                remote_input = f"{remote_dir}/crash_{index}.bin"

                worker.sftp.put(str(crash_file), remote_input)

                test_result = {
                    "testcase": crash_file.name
                }

                for target_name in (
                    "original_target",
                    "patched_target"
                ):
                    output_file = (
                        f"{remote_dir}/{target_name}_{index}.log"
                    )

                    command = (
                        f"cd {shlex.quote(remote_dir)} && "
                        "set +e; "
                        f"timeout {timeout_seconds}s "
                        f"./{shlex.quote(target_name)} "
                        f"< {shlex.quote(remote_input)} "
                        f"> {shlex.quote(output_file)} 2>&1; "
                        "exit_code=$?; "
                        f"if grep -q 'ERROR: AddressSanitizer' "
                        f"{shlex.quote(output_file)}; then "
                        "result=asan_crash; "
                        "elif [ \"$exit_code\" -eq 124 ]; then "
                        "result=timeout; "
                        "elif [ \"$exit_code\" -eq 0 ]; then "
                        "result=passed; "
                        "else result=nonzero_exit; fi; "
                        "echo ZT_RESULT:$result; "
                        "echo ZT_EXIT:$exit_code; "
                        f"cat {shlex.quote(output_file)}"
                    )

                    execution = worker.execute_command(command)

                    test_result[
                        target_name.replace("_target", "")
                    ] = self.classify_execution(
                        execution["output"]
                    )

                original_outcome = test_result["original"]["outcome"]
                patched_outcome = test_result["patched"]["outcome"]

                if original_outcome != "asan_crash":
                    regression_status = "inconclusive"

                elif patched_outcome in (
                    "passed",
                    "safely_rejected"
                ):
                    regression_status = "fixed"

                elif patched_outcome == "asan_crash":
                    regression_status = "still_reproducing"

                else:
                    regression_status = "review_required"

                test_result["regression_status"] = regression_status
                report["results"].append(test_result)

            counts = {
                "total": len(report["results"]),
                "fixed": 0,
                "still_reproducing": 0,
                "review_required": 0,
                "inconclusive": 0
            }

            for item in report["results"]:
                counts[item["regression_status"]] += 1

            report["summary"] = counts
            report["remote_workspace"] = remote_dir

            if counts["still_reproducing"] > 0:
                report["status"] = "regressions_found"

            elif counts["review_required"] > 0:
                report["status"] = "review_required"

            elif counts["fixed"] == counts["total"] and counts["total"] > 0:
                report["status"] = "passed"

            else:
                report["status"] = "inconclusive"

            return self.save_report(report)

        except Exception as error:
            report["status"] = "failed"
            report["message"] = str(error)
            return self.save_report(report)

        finally:
            worker.close()
