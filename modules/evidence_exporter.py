
import hashlib
import json
import zipfile
import shutil

from pathlib import Path
from datetime import datetime, timezone


class EvidenceExporter:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.reports_dir = self.base_dir / "reports"
        self.exports_dir = self.base_dir / "exports"

        self.source_files = [
            self.base_dir / "target.c",
            self.base_dir / "target_patched.c"
        ]

    def calculate_hash(self, file_path):
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(65536), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    def collect_evidence(self, staging_dir):
        evidence_dir = staging_dir / "evidence"
        report_output = evidence_dir / "reports"
        source_output = evidence_dir / "source"

        report_output.mkdir(parents=True, exist_ok=True)
        source_output.mkdir(parents=True, exist_ok=True)

        collected_files = []

        # Collect all reports and crash evidence.
        for file_path in self.reports_dir.rglob("*"):

            if not file_path.is_file():
                continue

            relative_path = file_path.relative_to(self.reports_dir)
            destination = report_output / relative_path

            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, destination)

            collected_files.append({
                "category": "report",
                "path": (Path("reports") / relative_path).as_posix(),
                "size_bytes": destination.stat().st_size,
                "sha256": self.calculate_hash(destination)
            })

        # Collect original and patched source files.
        for source_file in self.source_files:

            if not source_file.is_file():
                continue

            destination = source_output / source_file.name
            shutil.copy2(source_file, destination)

            collected_files.append({
                "category": "source",
                "path": (Path("source") / source_file.name).as_posix(),
                "size_bytes": destination.stat().st_size,
                "sha256": self.calculate_hash(destination)
            })

        return evidence_dir, collected_files

    def create_manifest(self, evidence_dir, collected_files):
        manifest = {
            "project": "ZeroTrace",
            "package_type": "Cybersecurity Research Evidence",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "hash_algorithm": "SHA-256",
            "total_files": len(collected_files),
            "files": collected_files
        }

        manifest_path = evidence_dir / "evidence_manifest.json"

        with open(manifest_path, "w", encoding="utf-8") as file:
            json.dump(manifest, file, indent=4)

        return manifest_path

    def create_archive(self, evidence_dir, archive_path):
        with zipfile.ZipFile(
            archive_path,
            "w",
            compression=zipfile.ZIP_DEFLATED
        ) as archive:

            for file_path in evidence_dir.rglob("*"):

                if file_path.is_file():
                    archive_name = (
                        Path("evidence") /
                        file_path.relative_to(evidence_dir)
                    )

                    archive.write(
                        file_path,
                        archive_name.as_posix()
                    )

    def verify_archive(self, archive_path):
        results = {
            "archive": archive_path.name,
            "verified": False,
            "total_files": 0,
            "verified_files": 0,
            "failed_files": []
        }

        try:
            with zipfile.ZipFile(archive_path, "r") as archive:

                archive_names = set(archive.namelist())
                manifest_name = "evidence/evidence_manifest.json"

                if manifest_name not in archive_names:
                    raise ValueError("Evidence manifest is missing.")

                manifest = json.loads(archive.read(manifest_name))

                for item in manifest["files"]:

                    # Normalize Windows and ZIP path separators.
                    relative_path = item["path"].replace("\\", "/")
                    archive_name = "evidence/" + relative_path

                    if archive_name not in archive_names:
                        results["failed_files"].append({
                            "file": relative_path,
                            "reason": "Missing from archive"
                        })
                        continue

                    content = archive.read(archive_name)

                    actual_hash = hashlib.sha256(
                        content
                    ).hexdigest()

                    if actual_hash != item["sha256"]:
                        results["failed_files"].append({
                            "file": relative_path,
                            "reason": "SHA-256 mismatch"
                        })
                    else:
                        results["verified_files"] += 1

                results["total_files"] = len(manifest["files"])

                results["verified"] = (
                    results["verified_files"] == results["total_files"]
                    and not results["failed_files"]
                )

        except Exception as error:
            results["error"] = str(error)

        return results

    def run(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.exports_dir.mkdir(parents=True, exist_ok=True)

        staging_dir = self.exports_dir / f"staging_{timestamp}"
        staging_dir.mkdir(parents=True, exist_ok=True)

        archive_path = (
            self.exports_dir /
            f"zerotrace_evidence_{timestamp}.zip"
        )

        try:
            print("[+] Collecting ZeroTrace evidence...")

            evidence_dir, collected_files = self.collect_evidence(
                staging_dir
            )

            if not collected_files:
                return {
                    "status": "failed",
                    "message": "No evidence files found."
                }

            print(f"[+] Collected {len(collected_files)} files.")

            print("[+] Generating SHA-256 manifest...")

            self.create_manifest(evidence_dir, collected_files)

            print("[+] Creating ZIP archive...")

            self.create_archive(evidence_dir, archive_path)

            print("[+] Verifying ZIP archive...")

            verification = self.verify_archive(archive_path)

            result = {
                "status": (
                    "completed" if verification["verified"] else "failed"
                ),
                "archive": str(archive_path.relative_to(self.base_dir)),
                "manifest": "evidence/evidence_manifest.json",
                "total_files": len(collected_files),
                "archive_size_bytes": archive_path.stat().st_size,
                "verification": verification
            }

            result_path = (
                self.exports_dir / "evidence_export_report.json"
            )

            with open(result_path, "w", encoding="utf-8") as file:
                json.dump(result, file, indent=4)

            print("\n========== EVIDENCE EXPORT ==========")
            print(f"Status: {result['status']}")
            print(f"Files: {result['total_files']}")
            print(f"Archive: {result['archive']}")
            print(
                f"Verified: {verification['verified_files']}/"
                f"{verification['total_files']}"
            )

            if verification["failed_files"]:
                print("Failed files:")
                for failed in verification["failed_files"]:
                    print(f"  - {failed['file']}: {failed['reason']}")

            print("=====================================")

            return result

        finally:
            if staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)


if __name__ == "__main__":
    EvidenceExporter().run()
