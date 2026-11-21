
import json
import shlex
import time
from datetime import datetime
from pathlib import Path

from integrations.kali_worker import KaliWorker
from modules.patch_validator import PatchValidator


class AutomatedPatchVerifier:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.report_dir = self.base_dir / "reports"

    def run(self, patched_path, host, username, fuzz_seconds=60):

        patched_file = Path(patched_path)

        if not patched_file.is_absolute():
            patched_file = self.base_dir / patched_file

        if not patched_file.is_file():
            return {
                "status": "failed",
                "message": f"Patched file not found: {patched_file}"
            }

        if not isinstance(fuzz_seconds, int) or not 10 <= fuzz_seconds <= 3600:
            return {
                "status": "failed",
                "message": "Fuzz duration must be between 10 and 3600 seconds."
            }

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        username_q = shlex.quote(username)

        lab = f"/home/{username}/zerotrace_worker/lab"
        remote_source = f"{lab}/target_patched.c"
        binary = f"target_patched_zerotrace"
        output_dir = f"findings_patchverify_{timestamp}"
        log_file = f"patchverify_{timestamp}.log"
        exit_file = f"patchverify_{timestamp}.exit"

        report = {
            "tool": "ZeroTrace",
            "module": "Automated Patch Verification",
            "started_at": datetime.now().isoformat(),
            "patched_file": str(patched_file.resolve()),
            "fuzz_duration_seconds": fuzz_seconds,
            "checks": {},
            "limitations": [
                "Source validation uses heuristic checks.",
                "Runtime tests cover only the supplied test inputs.",
                "Fuzzing results apply only to the tested duration and corpus.",
                "A successful verification does not prove the absence of vulnerabilities."
            ]
        }

        # 1. Local source validation
        try:
            source_check = PatchValidator().run(str(patched_file))
            report["checks"]["source_validation"] = source_check

        except Exception as error:
            report["checks"]["source_validation"] = {
                "status": "error",
                "message": str(error)
            }

        worker = KaliWorker(host, username)

        try:
            # 2. Connect to Kali
            if not worker.connect():
                report["status"] = "failed"
                report["message"] = "Could not connect to Kali."
                return self.save_report(report)

            # 3. Upload patched source
            uploaded = worker.upload_file(str(patched_file))

            if not uploaded:
                report["status"] = "failed"
                report["message"] = "Source upload failed."
                return self.save_report(report)

            # 4. Copy source into lab and compile
            compile_command = (
                f"cd {shlex.quote(lab)} || exit 1; "
                f"cp {shlex.quote(uploaded)} {shlex.quote(remote_source)} && "
                f"AFL_USE_ASAN=1 afl-clang-fast -g -O1 "
                f"-o {shlex.quote(binary)} "
                f"{shlex.quote(remote_source)}"
            )

            compile_result = worker.execute_command(compile_command)

            report["checks"]["compilation"] = {
                "status": (
                    "passed" if compile_result["exit_code"] == 0
                    else "failed"
                ),
                "exit_code": compile_result["exit_code"],
                "output": compile_result["output"],
                "error": compile_result["error"]
            }

            if compile_result["exit_code"] != 0:
                report["status"] = "failed"
                report["message"] = "Patched target compilation failed."
                return self.save_report(report)

            # 5. Runtime tests
            runtime_command = (
                f"cd {shlex.quote(lab)} || exit 1; "
                "set +e; "
                f"printf 'hello\\n' | ./{shlex.quote(binary)} "
                "> /tmp/zt_normal.out 2>&1; "
                "normal_code=$?; "
                "python3 -c 'print(\"A\" * 100)' | "
                f"./{shlex.quote(binary)} "
                "> /tmp/zt_oversized.out 2>&1; "
                "oversized_code=$?; "
                "echo NORMAL_EXIT:$normal_code; "
                "echo OVERSIZED_EXIT:$oversized_code; "
                "echo NORMAL_OUTPUT; cat /tmp/zt_normal.out; "
                "echo OVERSIZED_OUTPUT; cat /tmp/zt_oversized.out"
            )

            runtime_result = worker.execute_command(runtime_command)
            runtime_output = runtime_result["output"]

            normal_pass = "NORMAL_EXIT:0" in runtime_output
            oversized_rejected = (
                "OVERSIZED_EXIT:1" in runtime_output
                and "Input too large" in runtime_output
            )

            report["checks"]["runtime_tests"] = {
                "status": (
                    "passed" if normal_pass and oversized_rejected
                    else "failed"
                ),
                "normal_input": "passed" if normal_pass else "failed",
                "oversized_input": (
                    "rejected" if oversized_rejected else "not verified"
                ),
                "details": runtime_output,
                "error": runtime_result["error"]
            }

            # 6. AFL++ preflight
            preflight = worker.execute_command(
                f"cd {shlex.quote(lab)} || exit 1; "
                "command -v afl-fuzz >/dev/null 2>&1 && "
                "test -d seeds && "
                "find seeds -type f -print -quit | grep -q ."
            )

            if preflight["exit_code"] != 0:
                report["checks"]["fuzzing"] = {
                    "status": "failed",
                    "message": "AFL++ or seed directory unavailable."
                }
                report["status"] = "partial"
                return self.save_report(report)

            # Preserve existing findings.
            output_exists = worker.execute_command(
                f"cd {shlex.quote(lab)} || exit 1; "
                f"test -e {shlex.quote(output_dir)}"
            )

            if output_exists["exit_code"] == 0:
                report["checks"]["fuzzing"] = {
                    "status": "failed",
                    "message": "Fuzz output directory already exists."
                }
                report["status"] = "partial"
                return self.save_report(report)

            # 7. Start timed AFL++ fuzzing in the background.
            fuzz_command = (
                f"cd {shlex.quote(lab)} || exit 1; "
                f"rm -f {shlex.quote(exit_file)}; "
                f"nohup sh -c "
                f"'timeout -s INT {fuzz_seconds}s "
                f"afl-fuzz -i seeds -o {shlex.quote(output_dir)} "
                f"-m none -- ./{shlex.quote(binary)} "
                f"> {shlex.quote(log_file)} 2>&1; "
                f"echo $? > {shlex.quote(exit_file)}' "
                f"> /dev/null 2>&1 < /dev/null & "
                "echo FUZZING_LAUNCHED"
            )

            fuzz_start = worker.execute_command(fuzz_command)

            if fuzz_start["exit_code"] != 0:
                report["checks"]["fuzzing"] = {
                    "status": "failed",
                    "message": fuzz_start["error"]
                }
                report["status"] = "partial"
                return self.save_report(report)

            # 8. Wait for the timed fuzzing process to finish.
            completed = False
            wait_limit = fuzz_seconds + 45
            waited = 0

            while waited < wait_limit:
                time.sleep(5)
                waited += 5

                status_result = worker.execute_command(
                    f"cd {shlex.quote(lab)} || exit 1; "
                    f"test -f {shlex.quote(exit_file)} && echo FUZZING_FINISHED"
                )

                if "FUZZING_FINISHED" in status_result["output"]:
                    completed = True
                    break

            if not completed:
                report["checks"]["fuzzing"] = {
                    "status": "incomplete",
                    "message": "Fuzzing did not finish within the wait limit."
                }
                report["status"] = "partial"
                return self.save_report(report)

            # 9. Collect fuzzing statistics and crash count.
            stats_command = (
                f"cd {shlex.quote(lab)} || exit 1; "
                f"echo '--- EXIT CODE ---'; cat {shlex.quote(exit_file)}; "
                f"echo '--- CRASH COUNT ---'; "
                f"find {shlex.quote(output_dir + '/default/crashes')} "
                f"-maxdepth 1 -type f -name 'id:*' 2>/dev/null | wc -l; "
                f"echo '--- FUZZER STATS ---'; "
                f"cat {shlex.quote(output_dir + '/default/fuzzer_stats')} "
                f"2>/dev/null; "
                f"echo '--- FUZZ LOG ---'; "
                f"tail -n 15 {shlex.quote(log_file)}"
            )

            stats = worker.execute_command(stats_command)
            stats_output = stats["output"]

            crash_count = 0
            marker = "--- CRASH COUNT ---"

            try:
                crash_count = int(
                    stats_output.split(marker, 1)[1]
                    .splitlines()[1].strip()
                )
            except (IndexError, ValueError):
                pass

            report["checks"]["fuzzing"] = {
                "status": "completed" if stats["exit_code"] == 0 else "incomplete",
                "crashes_found": crash_count,
                "output_directory": output_dir,
                "details": stats_output
            }

            # 10. Overall result
            source_status = (
                report["checks"]["source_validation"].get("results", [])
            )

            source_pass = bool(source_status) and all(
                item.get("validation", {}).get("status")
                == "Pass - Heuristic Check"
                for item in source_status
            )

            compile_pass = (
                report["checks"]["compilation"]["status"] == "passed"
            )

            runtime_pass = (
                report["checks"]["runtime_tests"]["status"] == "passed"
            )

            fuzz_pass = (
                report["checks"]["fuzzing"]["status"] == "completed"
                and crash_count == 0
            )

            report["status"] = (
                "passed" if all([
                    source_pass,
                    compile_pass,
                    runtime_pass,
                    fuzz_pass
                ]) else "review_required"
            )

            report["completed_at"] = datetime.now().isoformat()

            return self.save_report(report)

        except Exception as error:
            report["status"] = "failed"
            report["message"] = str(error)
            return self.save_report(report)

        finally:
            worker.close()

    def save_report(self, report):

        self.report_dir.mkdir(parents=True, exist_ok=True)

        output_path = (
            self.report_dir / "automated_patch_verification.json"
        )

        report["generated_at"] = datetime.now().isoformat()

        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print("\n[+] Automated patch verification finished.")
        print(f"[+] Status: {report.get('status', 'unknown')}")
        print(f"[+] Report: {output_path}")

        return report
