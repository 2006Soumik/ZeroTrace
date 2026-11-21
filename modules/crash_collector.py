import os
import json
import stat
from pathlib import Path
from datetime import datetime, timezone

from integrations.kali_worker import KaliWorker


class CrashCollector:

    def run(self, host, username):
        worker = KaliWorker(host, username)

        project_root = Path(__file__).resolve().parent.parent
        local_dir = project_root / "reports" / "crashes"
        local_dir.mkdir(parents=True, exist_ok=True)

        remote_dir = (
            f"/home/{username}/zerotrace_worker/"
            "lab/findings/default/crashes"
        )

        downloaded_files = []

        try:
            if not worker.connect():
                return {
                    "status": "failed",
                    "message": "Could not connect to Kali Linux."
                }

            print("[+] Connected to Kali.")

            try:
                remote_files = worker.sftp.listdir_attr(remote_dir)
            except FileNotFoundError:
                return {
                    "status": "failed",
                    "message": f"Crash directory not found: {remote_dir}"
                }

            for file_info in remote_files:
                filename = file_info.filename

                if not filename.startswith("id:"):
                    continue

                if not stat.S_ISREG(file_info.st_mode):
                    continue

                remote_path = f"{remote_dir}/{filename}"

                # Windows does not allow colons in filenames.
                safe_filename = filename.replace(":", "_")
                local_path = local_dir / safe_filename

                worker.download_file(
                    remote_path,
                    str(local_path)
                )

                downloaded_files.append({
                    "original_filename": filename,
                    "local_filename": safe_filename,
                    "size_bytes": file_info.st_size,
                    "local_path": str(local_path)
                })

            report = {
                "tool": "ZeroTrace",
                "module": "Crash Collector",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "source": remote_dir,
                "total_crashes_collected": len(downloaded_files),
                "files": downloaded_files
            }

            report_path = local_dir / "crash_report.json"

            with report_path.open("w", encoding="utf-8") as report_file:
                json.dump(report, report_file, indent=4)

            print(f"[+] Collected {len(downloaded_files)} crash file(s).")
            print(f"[+] Report saved: {report_path}")

            return {
                "status": "success",
                "total_crashes": len(downloaded_files),
                "files": downloaded_files,
                "report": str(report_path)
            }

        except Exception as error:
            print(f"[-] Crash collection failed: {error}")
            return {
                "status": "failed",
                "message": str(error)
            }

        finally:
            worker.close()
