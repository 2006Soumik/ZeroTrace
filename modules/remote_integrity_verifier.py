
import hashlib
import json
import re
import shlex

from datetime import datetime, timezone
from pathlib import Path

from integrations.kali_worker import KaliWorker


class RemoteIntegrityVerifier:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.experiments_dir = self.base_dir / "reports" / "experiments"
        self.report_dir = self.experiments_dir / "integrity_reports"

        self.report_dir.mkdir(parents=True, exist_ok=True)

    def timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    def read_json(self, path):
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)

    def add_check(self, checks, name, passed, details):
        checks.append({
            "check": name,
            "status": "passed" if passed else "failed",
            "details": details
        })

    def normalize_version(self, value):
        value = re.sub(r"\x1b\[[0-9;]*m", "", str(value))
        return re.sub(r"[^a-z0-9.+-]", "", value.lower())

    def execute(self, worker, command, description):
        result = worker.execute_command(command)

        if result["exit_code"] != 0:
            raise RuntimeError(
                f"{description} failed: "
                f"{result['error'] or result['output']}"
            )

        return result["output"].strip()

    def collect_remote_data(self, worker, configuration):

        remote_lab = configuration.get("remote_lab")

        if not remote_lab:
            raise ValueError("Remote lab path missing from experiment configuration.")

        target = configuration.get("target", "./target")
        seed_directory = configuration.get(
            "seed_directory",
            "./seeds"
        )

        lab = shlex.quote(remote_lab)
        target_path = shlex.quote(target)
        seeds_path = shlex.quote(seed_directory)

        # Binary SHA-256
        binary_command = (
            f"cd {lab} && sha256sum {target_path}"
        )

        binary_output = self.execute(
            worker,
            binary_command,
            "Remote binary hash collection"
        )

        binary_parts = binary_output.split()

        if not binary_parts:
            raise ValueError("Remote binary hash was empty.")

        binary_sha256 = binary_parts[0].lower()

        if not re.fullmatch(r"[a-f0-9]{64}", binary_sha256):
            raise ValueError("Invalid remote binary SHA-256.")

        # Seed inventory and SHA-256 hashes
        seed_command = (
            f"cd {lab} && "
            f"find {seeds_path} -type f -print0 | "
            "sort -z | xargs -0 -r sha256sum"
        )

        seed_output = self.execute(
            worker,
            seed_command,
            "Remote seed inventory collection"
        )

        seed_inventory = []

        for line in seed_output.splitlines():

            parts = line.strip().split(maxsplit=1)

            if len(parts) != 2:
                continue

            digest, seed_path = parts

            if not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
                raise ValueError(
                    f"Invalid seed hash returned by Kali: {line}"
                )

            seed_inventory.append({
                "sha256": digest.lower(),
                "path": seed_path.strip()
            })

        seed_fingerprint = hashlib.sha256(
            json.dumps(
                seed_inventory,
                sort_keys=True
            ).encode("utf-8")
        ).hexdigest()

        # AFL++ version
        afl_command = (
            "afl-fuzz -h 2>&1 | head -n 1"
        )

        afl_version = self.execute(
            worker,
            afl_command,
            "AFL++ version collection"
        )

        # Compiler version
        compiler_command = (
            "clang --version | head -n 1"
        )

        compiler_version = self.execute(
            worker,
            compiler_command,
            "Compiler version collection"
        )

        return {
            "remote_lab": remote_lab,
            "binary_sha256": binary_sha256,
            "seed_count": len(seed_inventory),
            "seed_inventory": seed_inventory,
            "seed_fingerprint": seed_fingerprint,
            "afl_version": afl_version,
            "compiler_version": compiler_version
        }

    def verify(self, experiment_id, host, username):

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

        manifest_path = experiment_dir / "manifest.json"
        results_path = experiment_dir / "results.json"

        if not manifest_path.is_file() or not results_path.is_file():
            return {
                "status": "failed",
                "error": "Manifest or results file is missing."
            }

        try:
            manifest = self.read_json(manifest_path)
            results = self.read_json(results_path)

        except (json.JSONDecodeError, OSError) as error:
            return {
                "status": "failed",
                "error": f"Cannot read experiment records: {error}"
            }

        if results.get("experiment_id") != experiment_id:
            return {
                "status": "failed",
                "error": "Experiment ID mismatch."
            }

        if results.get("status") != "finalized":
            return {
                "status": "failed",
                "error": "Experiment must be finalized first."
            }

        configuration = manifest.get("configuration", {})
        environment = manifest.get("environment", {})
        corpus = manifest.get("corpus", {})
        target = manifest.get("target_fingerprint", {})

        remote_lab = (
            environment.get("remote_lab")
            or configuration.get("remote_lab")
        )

        if not remote_lab:
            return {
                "status": "failed",
                "error": "Remote lab path is missing from the manifest."
            }

        configuration["remote_lab"] = remote_lab

        worker = KaliWorker(host, username)

        checks = []
        errors = []
        warnings = []
        remote_data = {}

        try:

            # ---------------------------------------------
            # 1. SSH CONNECTION
            # ---------------------------------------------

            if not worker.connect():
                raise ConnectionError(
                    "Could not establish a Kali SSH connection."
                )

            self.add_check(
                checks,
                "Kali SSH connection",
                True,
                f"Connected to {host}."
            )

            # ---------------------------------------------
            # 2. COLLECT REMOTE ENVIRONMENT
            # ---------------------------------------------

            remote_data = self.collect_remote_data(
                worker,
                configuration
            )

            # ---------------------------------------------
            # 3. VERIFY REMOTE BINARY
            # ---------------------------------------------

            recorded_binary = target.get("binary_sha256")

            binary_matches = (
                bool(recorded_binary)
                and recorded_binary.lower()
                == remote_data["binary_sha256"]
            )

            self.add_check(
                checks,
                "Remote binary SHA-256",
                binary_matches,
                "Remote binary matches the experiment fingerprint."
                if binary_matches else
                "Remote binary differs from the recorded fingerprint."
            )

            if not binary_matches:
                errors.append("Remote target binary hash mismatch.")

            # ---------------------------------------------
            # 4. VERIFY SEED CORPUS
            # ---------------------------------------------

            recorded_seed_fingerprint = corpus.get(
                "seed_fingerprint"
            )

            recorded_seed_count = corpus.get("seed_count")

            seed_matches = (
                bool(recorded_seed_fingerprint)
                and recorded_seed_fingerprint
                == remote_data["seed_fingerprint"]
                and recorded_seed_count
                == remote_data["seed_count"]
            )

            self.add_check(
                checks,
                "Remote seed corpus fingerprint",
                seed_matches,
                (
                    "Remote seed inventory and fingerprint match."
                    if seed_matches else
                    "Remote seed inventory or fingerprint has changed."
                )
            )

            if not seed_matches:
                errors.append("Remote seed corpus mismatch.")

            # ---------------------------------------------
            # 5. VERIFY AFL++ VERSION
            # ---------------------------------------------

            recorded_afl = environment.get("afl_version", "")

            afl_matches = (
                bool(recorded_afl)
                and self.normalize_version(recorded_afl)
                == self.normalize_version(remote_data["afl_version"])
            )

            self.add_check(
                checks,
                "Remote AFL++ version",
                afl_matches,
                (
                    "AFL++ version matches."
                    if afl_matches else
                    f"Recorded: {recorded_afl}; "
                    f"Current: {remote_data['afl_version']}"
                )
            )

            if not afl_matches:
                errors.append("Remote AFL++ version mismatch.")

            # ---------------------------------------------
            # 6. VERIFY COMPILER VERSION
            # ---------------------------------------------

            recorded_compiler = environment.get(
                "compiler_version",
                ""
            )

            compiler_matches = (
                bool(recorded_compiler)
                and recorded_compiler.strip()
                == remote_data["compiler_version"].strip()
            )

            self.add_check(
                checks,
                "Remote compiler version",
                compiler_matches,
                (
                    "Compiler version matches."
                    if compiler_matches else
                    f"Recorded: {recorded_compiler}; "
                    f"Current: {remote_data['compiler_version']}"
                )
            )

            if not compiler_matches:
                errors.append("Remote compiler version mismatch.")

            # ---------------------------------------------
            # 7. FINAL STATUS
            # ---------------------------------------------

            status = "failed" if errors else (
                "warning" if warnings else "verified"
            )

        except Exception as error:

            errors.append(str(error))

            self.add_check(
                checks,
                "Remote integrity verification",
                False,
                str(error)
            )

            status = "failed"

        finally:
            worker.close()

        return self.generate_report(
            experiment_id,
            host,
            checks,
            errors,
            warnings,
            status,
            remote_data
        )

    def generate_report(
        self,
        experiment_id,
        host,
        checks,
        errors,
        warnings,
        status,
        remote_data
    ):

        passed = sum(
            1 for item in checks
            if item["status"] == "passed"
        )

        failed = sum(
            1 for item in checks
            if item["status"] == "failed"
        )

        report = {
            "project": "ZeroTrace",
            "experiment_id": experiment_id,
            "verified_at": self.timestamp(),
            "remote_host": host,
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
            "remote_environment": remote_data
        }

        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )

        report_name = (
            f"remote_integrity_{experiment_id}_{timestamp}"
        )

        json_path = self.report_dir / f"{report_name}.json"
        markdown_path = self.report_dir / f"{report_name}.md"

        with open(json_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        lines = [
            "# ZeroTrace Remote Integrity Report",
            "",
            f"- Experiment: `{experiment_id}`",
            f"- Kali host: `{host}`",
            f"- Verified at: `{report['verified_at']}`",
            f"- Status: **{status.upper()}**",
            "",
            "## Summary",
            "",
            f"- Total checks: {len(checks)}",
            f"- Passed: {passed}",
            f"- Failed: {failed}",
            "",
            "## Verification Checks",
            ""
        ]

        for item in checks:
            lines.extend([
                f"### {item['check']}",
                f"- Status: {item['status'].upper()}",
                f"- Details: {item['details']}",
                ""
            ])

        lines.extend(["## Errors", ""])

        lines.extend(
            [f"- {error}" for error in errors]
            if errors else ["- None"]
        )

        lines.extend(["", "## Warnings", ""])

        lines.extend(
            [f"- {warning}" for warning in warnings]
            if warnings else ["- None"]
        )

        lines.extend([
            "",
            "## Verification Scope",
            "",
            "This report compares the current remote binary, seed corpus,",
            "AFL++ version and compiler version with the experiment records.",
            "It does not prove that the remote system or toolchain is free",
            "from compromise."
        ])

        with open(markdown_path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))

        report["reports"] = {
            "json": str(json_path),
            "markdown": str(markdown_path)
        }

        print("\n========== REMOTE INTEGRITY ==========")
        print(f"Experiment : {experiment_id}")
        print(f"Kali host  : {host}")
        print(f"Status     : {status.upper()}")
        print(f"Passed     : {passed}")
        print(f"Failed     : {failed}")
        print(f"JSON       : {json_path}")
        print(f"Markdown   : {markdown_path}")

        return report

    def run(self, experiment_id=None, host=None, username=None, **kwargs):

        if experiment_id is None:
            experiment_id = kwargs.get("experiment_id")

        try:
            config_path = self.base_dir / "config" / "config.json"
            config = self.read_json(config_path).get("kali", {})

        except (OSError, json.JSONDecodeError) as error:
            return {
                "status": "failed",
                "error": f"Cannot load Kali configuration: {error}"
            }

        host = host or config.get("host")
        username = username or config.get("username")

        if not host or not username:
            return {
                "status": "failed",
                "error": "Kali host or username is missing."
            }

        if not experiment_id:
            return {
                "status": "failed",
                "error": "Experiment ID is required."
            }

        return self.verify(experiment_id, host, username)
