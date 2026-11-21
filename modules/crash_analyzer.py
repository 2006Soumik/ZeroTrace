import json
import re
import shlex
from pathlib import Path
from datetime import datetime, timezone

from integrations.kali_worker import KaliWorker


class CrashAnalyzer:

    def run(self, host, username, crash_path=None):

        project_root = Path(__file__).resolve().parent.parent
        crash_dir = project_root / "reports" / "crashes"
        crash_dir.mkdir(parents=True, exist_ok=True)

        if crash_path is None:
            crash_files = sorted(crash_dir.glob("id_*"))

            if not crash_files:
                return {
                    "status": "failed",
                    "message": "No crash testcase found."
                }

            crash_path = crash_files[0]

        crash_path = Path(crash_path)

        if not crash_path.is_file():
            return {
                "status": "failed",
                "message": "Crash testcase does not exist."
            }

        worker = KaliWorker(host, username)
        remote_lab = f"/home/{username}/zerotrace_worker/lab"
        remote_input = f"{remote_lab}/zerotrace_replay_input"
        uploaded = False

        try:
            if not worker.connect():
                return {
                    "status": "failed",
                    "message": "Could not connect to Kali."
                }

            print("[+] Connected to Kali.")

            # Upload the crash testcase to the controlled lab.
            worker.sftp.put(str(crash_path), remote_input)
            uploaded = True
            print("[+] Crash testcase uploaded.")

            # Replay the testcase against the lab target.
            command = (
                f"cd {shlex.quote(remote_lab)} && "
                f"./target < {shlex.quote(remote_input)}"
            )

            result = worker.execute_command(command)

            output = result["output"] + "\n" + result["error"]

            print("[+] Crash replay completed.")
            print("\n--- Target Output ---")
            print(output.strip() or "No output returned.")

            # Identify common AddressSanitizer errors.
            sanitizer_match = re.search(
                r"AddressSanitizer:\s*([^\n]+)",
                output
            )

            summary_match = re.search(
                r"SUMMARY:\s*([^\n]+)",
                output
            )

            location_match = re.search(
                r"target\.c:(\d+)(?::(\d+))?",
                output
            )

            if sanitizer_match:
                crash_type = sanitizer_match.group(1).strip()
            else:
                crash_type = "Not identified by AddressSanitizer"

            if summary_match:
                summary = summary_match.group(1).strip()
            else:
                summary = "No AddressSanitizer summary found."

            if location_match:
                source_location = {
                    "file": "target.c",
                    "line": int(location_match.group(1)),
                    "column": (
                        int(location_match.group(2))
                        if location_match.group(2)
                        else None
                    )
                }
            else:
                source_location = None

            analysis = {
                "tool": "ZeroTrace",
                "module": "Crash Analyzer",
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
                "testcase": crash_path.name,
                "target": "./target",
                "replay_exit_code": result["exit_code"],
                "crash_detected": bool(sanitizer_match),
                "crash_type": crash_type,
                "summary": summary,
                "source_location": source_location,
                "raw_output": output
            }

            report_path = crash_dir / "crash_analysis.json"

            with report_path.open("w", encoding="utf-8") as report_file:
                json.dump(analysis, report_file, indent=4)

            print(f"\n[+] Analysis report saved: {report_path}")

            return {
                "status": "success",
                "crash_detected": analysis["crash_detected"],
                "crash_type": crash_type,
                "source_location": source_location,
                "report": str(report_path)
            }

        except Exception as error:
            print(f"[-] Analysis failed: {error}")

            return {
                "status": "failed",
                "message": str(error)
            }

        finally:
            if uploaded and worker.sftp:
                try:
                    worker.sftp.remove(remote_input)
                except Exception:
                    print("[!] Could not remove temporary replay file.")

            worker.close()
