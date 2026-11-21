
import json

from pathlib import Path
from datetime import datetime, timezone


class CorpusIntelligence:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.reports_dir = self.base_dir / "reports"

        self.inventory_file = (
            self.reports_dir / "corpus_inventory.json"
        )

        self.history_file = (
            self.reports_dir / "corpus_history.json"
        )

        self.output_file = (
            self.reports_dir / "corpus_intelligence.json"
        )

    def load_json(self, path):
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)

    def save_json(self, path, data):
        with path.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

    def create_snapshot(self, records):
        snapshot = {}

        for record in records:
            if record.get("status") != "scanned":
                continue

            identity = (
                record["category"] + "|" +
                record["remote_path"]
            )

            snapshot[identity] = {
                "filename": record["filename"],
                "category": record["category"],
                "remote_path": record["remote_path"],
                "size_bytes": record["size_bytes"],
                "sha256": record["sha256"]
            }

        return snapshot

    def compare_snapshots(self, previous, current):

        previous_keys = set(previous)
        current_keys = set(current)

        added_keys = current_keys - previous_keys
        removed_keys = previous_keys - current_keys

        common_keys = previous_keys & current_keys

        modified = []

        for key in common_keys:

            old_file = previous[key]
            new_file = current[key]

            if old_file["sha256"] != new_file["sha256"]:
                modified.append({
                    "file": new_file,
                    "previous_sha256": old_file["sha256"],
                    "current_sha256": new_file["sha256"]
                })

        added = [
            current[key] for key in sorted(added_keys)
        ]

        removed = [
            previous[key] for key in sorted(removed_keys)
        ]

        return added, removed, modified

    def calculate_statistics(self, files):

        seed_files = [
            item for item in files.values()
            if item["category"] == "seed"
        ]

        crash_files = [
            item for item in files.values()
            if item["category"] == "crash"
        ]

        total_size = sum(
            item["size_bytes"] for item in files.values()
        )

        return {
            "total_files": len(files),
            "seed_files": len(seed_files),
            "crash_files": len(crash_files),
            "total_size_bytes": total_size,
            "average_file_size_bytes": (
                round(total_size / len(files), 2)
                if files else 0
            )
        }

    def run(self):

        if not self.inventory_file.is_file():
            return {
                "status": "failed",
                "message": "Corpus inventory not found. Run CorpusManager first."
            }

        try:
            self.reports_dir.mkdir(
                parents=True,
                exist_ok=True
            )

            inventory = self.load_json(
                self.inventory_file
            )

            if inventory.get("status") != "completed":
                return {
                    "status": "failed",
                    "message": "Corpus inventory is not completed."
                }

            current_files = self.create_snapshot(
                inventory.get("files", [])
            )

            if self.history_file.exists():
                history = self.load_json(
                    self.history_file
                )
            else:
                history = {
                    "tool": "ZeroTrace",
                    "module": "Corpus History",
                    "snapshots": []
                }

            snapshots = history.get("snapshots", [])

            previous_files = {}

            if snapshots:
                previous_files = {
                    item["category"] + "|" + item["remote_path"]: item
                    for item in snapshots[-1].get("files", [])
                }

            first_scan = not bool(snapshots)

            added, removed, modified = (
                self.compare_snapshots(
                    previous_files,
                    current_files
                )
            )

            current_stats = self.calculate_statistics(
                current_files
            )

            previous_stats = self.calculate_statistics(
                previous_files
            )

            growth_bytes = (
                current_stats["total_size_bytes"]
                - previous_stats["total_size_bytes"]
            )

            generated_at = datetime.now(
                timezone.utc
            ).isoformat()

            report = {
                "tool": "ZeroTrace",
                "module": "Corpus Intelligence Engine",
                "generated_at": generated_at,

                "comparison": (
                    "baseline" if first_scan
                    else "compared_with_previous_scan"
                ),

                "current_statistics": current_stats,
                "previous_statistics": previous_stats,

                "changes": {
                    "new_files": len(added),
                    "removed_files": len(removed),
                    "modified_files": len(modified),
                    "size_growth_bytes": growth_bytes
                },

                "new_files": added,
                "removed_files": removed,
                "modified_files": modified,

                "status": "completed",

                "limitations": [
                    "Changes are detected by category and remote file path.",
                    "A file renamed or moved is reported as removed and added.",
                    "Only successfully scanned inventory records are compared.",
                    "This module tracks corpus changes; it does not determine vulnerability severity."
                ]
            }

            snapshot = {
                "generated_at": generated_at,
                "statistics": current_stats,
                "files": list(current_files.values())
            }

            snapshots.append(snapshot)

            # Keep the latest 100 snapshots.
            history["snapshots"] = snapshots[-100:]

            self.save_json(
                self.history_file,
                history
            )

            self.save_json(
                self.output_file,
                report
            )

            print("\n[+] Corpus Intelligence completed.")
            print(
                f"[+] Total files: {current_stats['total_files']}"
            )
            print(f"[+] New files: {len(added)}")
            print(f"[+] Removed files: {len(removed)}")
            print(f"[+] Modified files: {len(modified)}")
            print(f"[+] Size growth: {growth_bytes} bytes")

            if first_scan:
                print("[+] Initial baseline created.")

            print(f"[+] Report: {self.output_file}")
            print(f"[+] History: {self.history_file}")

            return report

        except Exception as error:
            print(f"[-] Corpus Intelligence failed: {error}")

            return {
                "status": "failed",
                "message": str(error)
            }


if __name__ == "__main__":

    result = CorpusIntelligence().run()

    print(json.dumps(result, indent=4))
