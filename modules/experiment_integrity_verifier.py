
import hashlib
import json

from datetime import datetime, timezone
from pathlib import Path


class ExperimentIntegrityVerifier:

    REQUIRED_FILES = [
        "manifest.json",
        "results.json",
        "target_fingerprint.json",
        "environment.json",
        "fuzzer_stats.json",
    ]

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.experiments_dir = self.base_dir / "reports" / "experiments"
        self.report_dir = self.experiments_dir / "integrity_reports"

        self.report_dir.mkdir(parents=True, exist_ok=True)

    def timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    def calculate_sha256(self, file_path):
        digest = hashlib.sha256()

        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(65536), b""):
                digest.update(chunk)

        return digest.hexdigest()

    def read_json(self, file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)

    def add_check(self, checks, name, passed, details):
        checks.append({
            "check": name,
            "status": "passed" if passed else "failed",
            "details": details
        })

    def verify(self, experiment_id):

        if (
            not isinstance(experiment_id, str)
            or not experiment_id.startswith("EXP-")
            or not all(
                character.isalnum() or character == "-"
                for character in experiment_id
            )
        ):
            return {
                "status": "failed",
                "error": "Invalid experiment ID."
            }

        experiment_dir = self.experiments_dir / experiment_id

        if not experiment_dir.is_dir():
            return {
                "status": "failed",
                "error": "Experiment directory does not exist."
            }

        checks = []
        errors = []
        warnings = []

        # --------------------------------------------------
        # 1. CHECK REQUIRED FILES
        # --------------------------------------------------

        file_paths = {}

        for filename in self.REQUIRED_FILES:
            file_path = experiment_dir / filename
            file_paths[filename] = file_path

            exists = file_path.is_file()

            self.add_check(
                checks,
                f"File exists: {filename}",
                exists,
                "File found." if exists else "Required file is missing."
            )

            if not exists:
                errors.append(f"Missing required file: {filename}")

        if errors:
            return self.generate_report(
                experiment_id,
                checks,
                errors,
                warnings,
                "failed",
                {}
            )

        # --------------------------------------------------
        # 2. LOAD JSON FILES
        # --------------------------------------------------

        documents = {}

        for filename, file_path in file_paths.items():
            try:
                documents[filename] = self.read_json(file_path)

                self.add_check(
                    checks,
                    f"JSON validity: {filename}",
                    True,
                    "Valid JSON."
                )

            except (json.JSONDecodeError, OSError) as error:
                errors.append(f"{filename}: {error}")

                self.add_check(
                    checks,
                    f"JSON validity: {filename}",
                    False,
                    str(error)
                )

        if errors:
            return self.generate_report(
                experiment_id,
                checks,
                errors,
                warnings,
                "failed",
                {}
            )

        manifest = documents["manifest.json"]
        results = documents["results.json"]
        target = documents["target_fingerprint.json"]
        environment = documents["environment.json"]
        fuzzer_stats = documents["fuzzer_stats.json"]

        # --------------------------------------------------
        # 3. EXPERIMENT ID AND STATUS
        # --------------------------------------------------

        id_matches = (
            results.get("experiment_id") == experiment_id
            and manifest.get("experiment_id", experiment_id) == experiment_id
        )

        self.add_check(
            checks,
            "Experiment ID consistency",
            id_matches,
            "Experiment IDs match."
            if id_matches else
            "Experiment IDs do not match."
        )

        if not id_matches:
            errors.append("Experiment ID mismatch.")

        finalized = (
            results.get("status") == "finalized"
            and results.get("fuzzing_status") == "stopped"
        )

        self.add_check(
            checks,
            "Experiment finalized",
            finalized,
            "Experiment is finalized and fuzzing is stopped."
            if finalized else
            "Experiment is not finalized or fuzzing is not stopped."
        )

        if not finalized:
            errors.append("Experiment is not in a finalized state.")

        # --------------------------------------------------
        # 4. TARGET FINGERPRINT CONSISTENCY
        # --------------------------------------------------

        manifest_target = manifest.get("target_fingerprint", {})
        results_target = results.get("target_fingerprint", {})

        for field in ("source_sha256", "binary_sha256"):

            recorded_values = [
                target.get(field),
                manifest_target.get(field),
                results_target.get(field)
            ]

            valid = (
                all(isinstance(value, str) and value for value in recorded_values)
                and len(set(recorded_values)) == 1
            )

            self.add_check(
                checks,
                f"Target fingerprint: {field}",
                valid,
                "All recorded hashes match."
                if valid else
                "Missing or inconsistent target hashes."
            )

            if not valid:
                errors.append(f"Target fingerprint mismatch: {field}")

        # --------------------------------------------------
        # 5. ENVIRONMENT CONSISTENCY
        # --------------------------------------------------

        manifest_environment = manifest.get("environment", {})

        for field in ("afl_version", "compiler_version"):

            values = [
                environment.get(field),
                manifest_environment.get(field)
            ]

            valid = (
                all(isinstance(value, str) and value for value in values)
                and len(set(values)) == 1
            )

            self.add_check(
                checks,
                f"Environment consistency: {field}",
                valid,
                "Environment values match."
                if valid else
                "Environment values are missing or inconsistent."
            )

            if not valid:
                errors.append(f"Environment mismatch: {field}")

        # --------------------------------------------------
        # 6. SEED CORPUS FINGERPRINT
        # --------------------------------------------------

        manifest_corpus = manifest.get("corpus", {})
        results_corpus = results.get("corpus", {})

        seeds = manifest_corpus.get("seeds", [])

        try:
            calculated_seed_fingerprint = hashlib.sha256(
                json.dumps(
                    seeds,
                    sort_keys=True
                ).encode("utf-8")
            ).hexdigest()

            recorded_fingerprints = [
                manifest_corpus.get("seed_fingerprint"),
                results_corpus.get("seed_fingerprint")
            ]

            seed_valid = (
                len(seeds) == manifest_corpus.get("seed_count")
                and len(seeds) == results_corpus.get("seed_count")
                and all(
                    isinstance(value, str) and value
                    for value in recorded_fingerprints
                )
                and len(set(recorded_fingerprints)) == 1
                and calculated_seed_fingerprint == recorded_fingerprints[0]
            )

        except (TypeError, ValueError):
            calculated_seed_fingerprint = None
            seed_valid = False

        self.add_check(
            checks,
            "Seed corpus fingerprint",
            seed_valid,
            "Seed inventory fingerprint and counts match."
            if seed_valid else
            "Seed inventory, count, or fingerprint mismatch."
        )

        if not seed_valid:
            errors.append("Seed corpus fingerprint verification failed.")

        # --------------------------------------------------
        # 7. FUZZER STATISTICS CONSISTENCY
        # --------------------------------------------------

        result_statistics = (
            results.get("statistics", {})
            .get("statistics", {})
        )

        local_statistics = fuzzer_stats.get("stats", {})

        statistics_fields = [
            "start_time",
            "run_time",
            "execs_done",
            "execs_per_sec",
            "saved_crashes",
            "saved_hangs",
            "stability",
            "bitmap_cvg",
            "peak_rss_mb",
        ]

        compared_fields = []
        statistics_mismatches = []

        for field in statistics_fields:
            result_value = result_statistics.get(field)
            local_value = local_statistics.get(field)

            if result_value is None or local_value is None:
                continue

            compared_fields.append(field)

            if str(result_value) != str(local_value):
                statistics_mismatches.append(field)

        statistics_valid = (
            len(compared_fields) > 0
            and len(statistics_mismatches) == 0
        )

        self.add_check(
            checks,
            "Fuzzer statistics consistency",
            statistics_valid,
            (
                f"Compared {len(compared_fields)} fields; all match."
                if statistics_valid else
                f"Mismatched fields: {statistics_mismatches}"
            )
        )

        if not statistics_valid:
            errors.append("Fuzzer statistics are inconsistent.")

        # --------------------------------------------------
        # 8. CURRENT SOURCE FILE HASH
        # --------------------------------------------------

        source_file = target.get("source_file", "target.c")
        source_path = self.base_dir / source_file
        recorded_source_hash = target.get("source_sha256")

        if source_path.is_file():
            current_source_hash = self.calculate_sha256(source_path)

            source_matches = (
                current_source_hash == recorded_source_hash
            )

            self.add_check(
                checks,
                "Current source SHA-256",
                source_matches,
                "Current source matches the experiment."
                if source_matches else
                "Current source differs from the recorded experiment source."
            )

            if not source_matches:
                errors.append(
                    "Current target source does not match the experiment fingerprint."
                )

        else:
            current_source_hash = None

            self.add_check(
                checks,
                "Current source SHA-256",
                False,
                f"Source file not found: {source_path}"
            )

            warnings.append(
                "Current source file is unavailable; source hash could not be checked."
            )

        # --------------------------------------------------
        # 9. FILE INTEGRITY BASELINE
        # --------------------------------------------------

        baseline_path = experiment_dir / "integrity_baseline.json"

        current_hashes = {}

        for filename, file_path in file_paths.items():
            current_hashes[filename] = self.calculate_sha256(file_path)

        baseline_status = "existing"

        if not baseline_path.exists():

            if not errors:
                baseline = {
                    "experiment_id": experiment_id,
                    "created_at": self.timestamp(),
                    "algorithm": "SHA-256",
                    "files": current_hashes
                }

                temporary_path = baseline_path.with_suffix(".tmp")

                with open(temporary_path, "w", encoding="utf-8") as file:
                    json.dump(baseline, file, indent=4)

                temporary_path.replace(baseline_path)

                baseline_status = "created"

                warnings.append(
                    "First integrity baseline created. "
                    "Earlier file modifications cannot be ruled out."
                )

                self.add_check(
                    checks,
                    "File integrity baseline",
                    True,
                    "Initial SHA-256 baseline created."
                )

            else:
                baseline_status = "not_created"

                warnings.append(
                    "Baseline was not created because earlier checks failed."
                )

                self.add_check(
                    checks,
                    "File integrity baseline",
                    False,
                    "Resolve verification failures before establishing a baseline."
                )

        else:

            try:
                baseline = self.read_json(baseline_path)
                baseline_files = baseline.get("files", {})

                baseline_valid = (
                    baseline.get("experiment_id") == experiment_id
                    and baseline.get("algorithm") == "SHA-256"
                    and isinstance(baseline_files, dict)
                    and all(
                        filename in baseline_files
                        for filename in self.REQUIRED_FILES
                    )
                )

                if not baseline_valid:
                    errors.append("Integrity baseline is invalid.")

                    self.add_check(
                        checks,
                        "File integrity baseline",
                        False,
                        "Baseline structure or experiment ID is invalid."
                    )

                else:
                    changed_files = []

                    for filename in self.REQUIRED_FILES:
                        if current_hashes[filename] != baseline_files[filename]:
                            changed_files.append(filename)

                    baseline_matches = len(changed_files) == 0

                    self.add_check(
                        checks,
                        "File integrity baseline",
                        baseline_matches,
                        "All experiment files match the original baseline."
                        if baseline_matches else
                        f"Files changed since baseline: {changed_files}"
                    )

                    if not baseline_matches:
                        errors.append(
                            "Experiment files changed since the integrity baseline."
                        )

            except (json.JSONDecodeError, OSError, AttributeError) as error:
                errors.append(f"Cannot read integrity baseline: {error}")

                self.add_check(
                    checks,
                    "File integrity baseline",
                    False,
                    str(error)
                )

        # --------------------------------------------------
        # 10. FINAL STATUS
        # --------------------------------------------------

        if errors:
            status = "failed"
        elif warnings:
            status = "warning"
        else:
            status = "verified"

        metadata = {
            "baseline_status": baseline_status,
            "current_source_sha256": current_source_hash,
            "checked_files": current_hashes,
            "statistics_fields_compared": compared_fields,
        }

        return self.generate_report(
            experiment_id,
            checks,
            errors,
            warnings,
            status,
            metadata
        )

    def generate_report(
        self,
        experiment_id,
        checks,
        errors,
        warnings,
        status,
        metadata
    ):

        passed = sum(
            1 for check in checks
            if check["status"] == "passed"
        )

        failed = sum(
            1 for check in checks
            if check["status"] == "failed"
        )

        report = {
            "project": "ZeroTrace",
            "experiment_id": experiment_id,
            "verified_at": self.timestamp(),
            "status": status,
            "summary": {
                "total_checks": len(checks),
                "passed": passed,
                "failed": failed,
                "errors": len(errors),
                "warnings": len(warnings)
            },
            "checks": checks,
            "errors": errors,
            "warnings": warnings,
            "metadata": metadata
        }

        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )

        report_name = f"integrity_{experiment_id}_{timestamp}"

        json_path = self.report_dir / f"{report_name}.json"
        markdown_path = self.report_dir / f"{report_name}.md"

        with open(json_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        lines = [
            "# ZeroTrace Experiment Integrity Report",
            "",
            f"- Experiment: `{experiment_id}`",
            f"- Verified at: `{report['verified_at']}`",
            f"- Status: **{status.upper()}**",
            "",
            "## Summary",
            "",
            f"- Total checks: {len(checks)}",
            f"- Passed: {passed}",
            f"- Failed: {failed}",
            f"- Errors: {len(errors)}",
            f"- Warnings: {len(warnings)}",
            "",
            "## Verification Checks",
            ""
        ]

        for check in checks:
            lines.extend([
                f"### {check['check']}",
                f"- Status: {check['status'].upper()}",
                f"- Details: {check['details']}",
                ""
            ])

        lines.extend(["## Errors", ""])

        if errors:
            lines.extend(f"- {error}" for error in errors)
        else:
            lines.append("- None")

        lines.extend(["", "## Warnings", ""])

        if warnings:
            lines.extend(f"- {warning}" for warning in warnings)
        else:
            lines.append("- None")

        lines.extend([
            "",
            "## Integrity Scope",
            "",
            "This report checks local experiment records, recorded fingerprints,",
            "and the current source file. It does not independently prove that",
            "the remote binary or remote seed files remain unchanged.",
            "The local SHA-256 baseline is not digitally signed or tamper-proof."
        ])

        with open(markdown_path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))

        report["reports"] = {
            "json": str(json_path),
            "markdown": str(markdown_path)
        }

        print("\n========== EXPERIMENT INTEGRITY ==========")
        print(f"Experiment : {experiment_id}")
        print(f"Status     : {status.upper()}")
        print(f"Passed     : {passed}")
        print(f"Failed     : {failed}")
        print(f"Warnings   : {len(warnings)}")
        print(f"JSON       : {json_path}")
        print(f"Markdown   : {markdown_path}")

        return report

    def run(self, experiment_id=None, **kwargs):

        if experiment_id is None:
            experiment_id = kwargs.get("experiment_id")

        if not experiment_id:
            return {
                "status": "failed",
                "error": "An experiment ID is required."
            }

        return self.verify(experiment_id)
