
import hashlib
import json
import stat

from pathlib import Path
from datetime import datetime, timezone

from integrations.kali_worker import KaliWorker


class CorpusManager:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.reports_dir = self.base_dir / "reports"
        self.output_file = self.reports_dir / "corpus_inventory.json"

    def calculate_remote_hash(self, remote_path, worker):
        digest = hashlib.sha256()

        with worker.sftp.open(remote_path, "rb") as remote_file:
            while True:
                chunk = remote_file.read(1024 * 1024)

                if not chunk:
                    break

                digest.update(chunk)

        return digest.hexdigest()

    def scan_directory(self, worker, remote_dir, category):
        records = []

        try:
            files = worker.sftp.listdir_attr(remote_dir)

        except OSError as error:
            print(f"[!] Cannot access {remote_dir}: {error}")
            return records

        for item in files:

            if not stat.S_ISREG(item.st_mode):
                continue

            filename = item.filename

            # Recognize actual AFL++ crash filenames.
            if category == "crash" and not filename.startswith(("id:", "id_")):
                continue

            remote_path = f"{remote_dir}/{filename}"

            try:
                file_hash = self.calculate_remote_hash(
                    remote_path,
                    worker
                )

                records.append({
                    "filename": filename,
                    "category": category,
                    "remote_path": remote_path,
                    "size_bytes": item.st_size,
                    "sha256": file_hash,
                    "status": "scanned"
                })

            except Exception as error:
                records.append({
                    "filename": filename,
                    "category": category,
                    "remote_path": remote_path,
                    "size_bytes": item.st_size,
                    "status": "failed",
                    "error": str(error)
                })

        return records

    def identify_duplicates(self, records):
        hash_groups = {}

        for record in records:

            if record["status"] != "scanned":
                continue

            file_hash = record["sha256"]

            hash_groups.setdefault(file_hash, []).append(record)

        duplicates = []

        for file_hash, files in hash_groups.items():

            if len(files) > 1:
                duplicates.append({
                    "sha256": file_hash,
                    "duplicate_count": len(files) - 1,
                    "files": [
                        {
                            "filename": item["filename"],
                            "category": item["category"],
                            "remote_path": item["remote_path"]
                        }
                        for item in files
                    ]
                })

        return duplicates

    def run(self, host, username):

        remote_lab = f"/home/{username}/zerotrace_worker/lab"
        remote_seeds = f"{remote_lab}/seeds"
        remote_crashes = f"{remote_lab}/findings/default/crashes"

        worker = KaliWorker(host, username)

        if not worker.connect():
            return {
                "status": "failed",
                "message": "Could not connect to Kali."
            }

        try:
            print("[+] Connected to Kali.")

            seed_records = self.scan_directory(
                worker,
                remote_seeds,
                "seed"
            )

            print(f"[+] Seed files scanned: {len(seed_records)}")

            crash_records = self.scan_directory(
                worker,
                remote_crashes,
                "crash"
            )

            print(f"[+] Crash files scanned: {len(crash_records)}")

            all_records = seed_records + crash_records

            duplicates = self.identify_duplicates(all_records)

            successful = sum(
                1 for item in all_records
                if item["status"] == "scanned"
            )

            failed = len(all_records) - successful

            report = {
                "tool": "ZeroTrace",
                "module": "Corpus Manager",
                "generated_at": datetime.now(timezone.utc).isoformat(),

                "summary": {
                    "total_files": len(all_records),
                    "seed_files": len(seed_records),
                    "crash_files": len(crash_records),
                    "successfully_scanned": successful,
                    "failed_scans": failed,
                    "duplicate_groups": len(duplicates),
                    "duplicate_files": sum(
                        item["duplicate_count"]
                        for item in duplicates
                    )
                },

                "files": all_records,
                "duplicates": duplicates,

                "limitations": [
                    "Inventory is read-only.",
                    "Only the configured AFL++ seed and crash directories are scanned.",
                    "SHA-256 duplicates indicate identical file contents, not identical vulnerability root causes."
                ],

                "status": "completed"
            }

            self.reports_dir.mkdir(
                parents=True,
                exist_ok=True
            )

            with self.output_file.open("w", encoding="utf-8") as file:
                json.dump(report, file, indent=4)

            print("\n[+] Corpus inventory completed.")
            print(f"[+] Total files: {len(all_records)}")
            print(f"[+] Successfully scanned: {successful}")
            print(f"[+] Failed scans: {failed}")
            print(f"[+] Duplicate groups: {len(duplicates)}")
            print(f"[+] Report: {self.output_file}")

            return report

        except Exception as error:
            print(f"[-] Corpus inventory failed: {error}")

            return {
                "status": "failed",
                "message": str(error)
            }

        finally:
            worker.close()


if __name__ == "__main__":

    host = input("Enter Kali IP: ").strip()
    username = input("Enter Kali username: ").strip()

    result = CorpusManager().run(
        host=host,
        username=username
    )

    print(json.dumps(result, indent=4))
