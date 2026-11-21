
import json
import re
import shlex
import hashlib

from pathlib import Path
from datetime import datetime, timezone

from integrations.kali_worker import KaliWorker


class CrashDeduplicator:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent

        self.crash_dir = self.base_dir / "reports" / "crashes"

        self.output_file = (
            self.crash_dir / "crash_deduplication.json"
        )

    def extract_crash_type(self, output):
        match = re.search(
            r"AddressSanitizer:\s*([a-zA-Z0-9_-]+)",
            output,
            re.IGNORECASE
        )

        if match:
            return match.group(1).lower()

        return None

    def extract_source_location(self, output):
        matches = re.findall(
            r"target\.c:(\d+)(?::(\d+))?",
            output
        )

        if not matches:
            return None

        line, column = matches[0]

        return {
            "file": "target.c",
            "line": int(line),
            "column": int(column) if column else None
        }

    def extract_stack_frames(self, output):
        frames = []

        for line in output.splitlines():
            match = re.search(
                r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+([^\s(]+)",
                line
            )

            if not match:
                continue

            function = match.group(1)

            if function.startswith("__asan_"):
                continue

            if function in ("_start", "__libc_start_main"):
                continue

            frames.append(function)

        return frames[:5]

    def extract_access_details(self, output):
        match = re.search(
            r"(READ|WRITE) of size (\d+)",
            output,
            re.IGNORECASE
        )

        if not match:
            return {
                "access_type": "unknown",
                "access_size": None
            }

        return {
            "access_type": match.group(1).upper(),
            "access_size": int(match.group(2))
        }

    def generate_fingerprint(
        self,
        crash_type,
        source,
        frames,
        access
    ):
        identity = {
            "crash_type": crash_type,
            "source_file": source["file"] if source else "unknown",
            "source_line": source["line"] if source else 0,
            "stack_frames": frames,
            "access_type": access["access_type"]
        }

        normalized = json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":")
        )

        return hashlib.sha256(
            normalized.encode("utf-8")
        ).hexdigest()

    def replay_crash(self, worker, remote_lab, crash_file, index):
        remote_input = (
            f"{remote_lab}/zerotrace_dedup_input_{index}"
        )

        try:
            worker.sftp.put(
                str(crash_file),
                remote_input
            )

            command = (
                f"cd {shlex.quote(remote_lab)} && "
                f"timeout 10s ./target "
                f"< {shlex.quote(remote_input)} 2>&1"
            )

            result = worker.execute_command(command)

            output = (
                result["output"] + "\n" + result["error"]
            )

            crash_type = self.extract_crash_type(output)

            if not crash_type:
                return {
                    "testcase": crash_file.name,
                    "status": "not_confirmed",
                    "exit_code": result["exit_code"],
                    "message": "No AddressSanitizer crash detected."
                }

            source = self.extract_source_location(output)

            frames = self.extract_stack_frames(output)

            access = self.extract_access_details(output)

            fingerprint = self.generate_fingerprint(
                crash_type,
                source,
                frames,
                access
            )

            return {
                "testcase": crash_file.name,
                "status": "confirmed",
                "fingerprint": fingerprint,
                "crash_type": crash_type,
                "source_location": source,
                "stack_frames": frames,
                "access_details": access,
                "exit_code": result["exit_code"]
            }

        except Exception as error:
            return {
                "testcase": crash_file.name,
                "status": "failed",
                "message": str(error)
            }

        finally:
            try:
                worker.sftp.remove(remote_input)
            except Exception:
                pass

    def run(self, host, username):
        self.crash_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        crash_files = sorted(
            path for path in self.crash_dir.glob("id_*")
            if path.is_file()
        )

        if not crash_files:
            return {
                "status": "failed",
                "message": "No AFL++ crash files found."
            }

        print(f"[+] Found {len(crash_files)} crash files.")

        worker = KaliWorker(host, username)

        groups = {}
        failures = []
        unconfirmed = []

        try:
            if not worker.connect():
                return {
                    "status": "failed",
                    "message": "Could not connect to Kali."
                }

            remote_lab = (
                f"/home/{username}/zerotrace_worker/lab"
            )

            check = worker.execute_command(
                f"test -x {shlex.quote(remote_lab + '/target')}"
            )

            if check["exit_code"] != 0:
                return {
                    "status": "failed",
                    "message": "Kali target binary not found."
                }

            print("[+] Kali target verified.")

            for index, crash_file in enumerate(crash_files, 1):

                print(
                    f"[+] Analyzing {index}/{len(crash_files)}: "
                    f"{crash_file.name}"
                )

                result = self.replay_crash(
                    worker,
                    remote_lab,
                    crash_file,
                    index
                )

                if result["status"] == "failed":
                    failures.append(result)
                    continue

                if result["status"] == "not_confirmed":
                    unconfirmed.append(result)
                    continue

                fingerprint = result["fingerprint"]

                if fingerprint not in groups:
                    groups[fingerprint] = {
                        "fingerprint": fingerprint,
                        "crash_type": result["crash_type"],
                        "source_location": result["source_location"],
                        "stack_frames": result["stack_frames"],
                        "access_details": result["access_details"],
                        "occurrences": 0,
                        "testcases": []
                    }

                groups[fingerprint]["occurrences"] += 1

                groups[fingerprint]["testcases"].append(
                    result["testcase"]
                )

            unique_count = len(groups)

            confirmed_count = sum(
                group["occurrences"]
                for group in groups.values()
            )

            duplicate_count = (
                confirmed_count - unique_count
            )

            report = {
                "tool": "ZeroTrace",
                "module": "Crash Deduplicator",
                "generated_at": datetime.now(
                    timezone.utc
                ).isoformat(),

                "total_crash_files": len(crash_files),
                "confirmed_crashes": confirmed_count,
                "unique_crashes": unique_count,
                "duplicate_crashes": duplicate_count,
                "unconfirmed_crashes": len(unconfirmed),
                "failed_replays": len(failures),

                "crash_groups": list(groups.values()),
                "unconfirmed_testcases": unconfirmed,
                "failed_testcases": failures,

                "status": "completed",

                "limitations": [
                    "Only AddressSanitizer-confirmed crashes are grouped.",
                    "A ten-second timeout is used for each replay.",
                    "Fingerprint matching indicates similar crash signatures, not proven identical root causes.",
                    "Different crashes can share a fingerprint.",
                    "Only the available local id_* crash files are processed."
                ]
            }

            with self.output_file.open(
                "w",
                encoding="utf-8"
            ) as file:
                json.dump(report, file, indent=4)

            print("\n[+] Multi-crash deduplication completed.")
            print(f"[+] Files processed: {len(crash_files)}")
            print(f"[+] Confirmed crashes: {confirmed_count}")
            print(f"[+] Unique crashes: {unique_count}")
            print(f"[+] Duplicate crashes: {duplicate_count}")
            print(f"[+] Unconfirmed: {len(unconfirmed)}")
            print(f"[+] Failed: {len(failures)}")
            print(f"[+] Report: {self.output_file}")

            return report

        except Exception as error:
            print(f"[-] Deduplication failed: {error}")

            return {
                "status": "failed",
                "message": str(error)
            }

        finally:
            worker.close()


if __name__ == "__main__":

    host = input("Enter Kali IP: ").strip()

    username = input("Enter Kali username: ").strip()

    result = CrashDeduplicator().run(
        host=host,
        username=username
    )

    print(json.dumps(result, indent=4))
