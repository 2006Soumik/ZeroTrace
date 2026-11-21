
import hashlib
import json
import shlex
import uuid

from pathlib import Path
from datetime import datetime, timezone

from integrations.kali_worker import KaliWorker


class ExperimentManager:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.config_file = self.base_dir / "config" / "config.json"
        self.reports_dir = self.base_dir / "reports"
        self.experiments_dir = self.reports_dir / "experiments"
        self.history_file = self.experiments_dir / "experiment_history.json"

        self.experiments_dir.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------
    # GENERAL HELPERS
    # --------------------------------------------------

    def timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    def write_json(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)

        temporary = path.with_suffix(path.suffix + ".tmp")

        with temporary.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

        temporary.replace(path)

    def read_json(self, path, default=None):
        if default is None:
            default = {}

        try:
            with path.open("r", encoding="utf-8") as file:
                return json.load(file)
        except (OSError, json.JSONDecodeError):
            return default

    def sha256_file(self, path):
        digest = hashlib.sha256()

        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()

    def load_config(self):
        if not self.config_file.exists():
            raise FileNotFoundError("Kali configuration not found.")

        with self.config_file.open("r", encoding="utf-8") as file:
            return json.load(file)

    def get_history(self):
        history = self.read_json(self.history_file, [])

        return history if isinstance(history, list) else []

    def experiment_path(self, experiment_id):
        if not experiment_id or not experiment_id.startswith("EXP-"):
            raise ValueError("Invalid experiment ID.")

        if any(
            char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
            for char in experiment_id
        ):
            raise ValueError("Invalid experiment ID characters.")

        path = (self.experiments_dir / experiment_id).resolve()

        if path.parent != self.experiments_dir.resolve():
            raise ValueError("Invalid experiment path.")

        return path

    def update_history(self, experiment):
        history = self.get_history()

        entry = {
            "experiment_id": experiment["experiment_id"],
            "created_at": experiment["created_at"],
            "status": experiment["status"],
            "target_source_sha256": experiment.get(
                "target_fingerprint", {}
            ).get("source_sha256"),
            "target_binary_sha256": experiment.get(
                "target_fingerprint", {}
            ).get("binary_sha256")
        }

        replaced = False

        for index, item in enumerate(history):
            if item.get("experiment_id") == experiment["experiment_id"]:
                history[index] = entry
                replaced = True
                break

        if not replaced:
            history.append(entry)

        self.write_json(self.history_file, history[-500:])

    # --------------------------------------------------
    # REMOTE ENVIRONMENT COLLECTION
    # --------------------------------------------------

    def collect_remote_environment(self, worker, kali):
        remote_lab = kali.get("workspace", "").rstrip("/") + "/lab"

        if not remote_lab.startswith("/"):
            raise ValueError("Invalid remote lab path.")

        quoted_lab = shlex.quote(remote_lab)

        command = (
            f"cd {quoted_lab} || exit 1; "
            "echo '__ZEROTRACE_AFL_VERSION__'; "
            "afl-fuzz -h 2>&1 | head -n 2; "
            "echo '__ZEROTRACE_COMPILER_VERSION__'; "
            "clang --version 2>/dev/null | head -n 1; "
            "echo '__ZEROTRACE_BINARY_HASH__'; "
            "sha256sum ./target 2>/dev/null || true; "
            "echo '__ZEROTRACE_SEEDS__'; "
            "find ./seeds -type f -print0 2>/dev/null | "
            "sort -z | xargs -0 -r sha256sum"
        )

        result = worker.execute_command(command)

        if result["exit_code"] != 0:
            raise RuntimeError(
                "Could not collect Kali environment: "
                + result.get("error", "")
                + result.get("output", "")
            )

        output = result.get("output", "")

        sections = {}
        current = None

        for line in output.splitlines():
            if line == "__ZEROTRACE_AFL_VERSION__":
                current = "afl_version"
                sections[current] = []
            elif line == "__ZEROTRACE_COMPILER_VERSION__":
                current = "compiler_version"
                sections[current] = []
            elif line == "__ZEROTRACE_BINARY_HASH__":
                current = "binary_hash"
                sections[current] = []
            elif line == "__ZEROTRACE_SEEDS__":
                current = "seeds"
                sections[current] = []
            elif current:
                sections[current].append(line)

        afl_version = " ".join(
            sections.get("afl_version", [])
        ).strip()

        compiler_version = " ".join(
            sections.get("compiler_version", [])
        ).strip()

        binary_hash = None

        for line in sections.get("binary_hash", []):
            parts = line.split()

            if len(parts) >= 2 and len(parts[0]) == 64:
                binary_hash = parts[0]
                break

        seed_inventory = []

        for line in sections.get("seeds", []):
            parts = line.strip().split(None, 1)

            if len(parts) != 2:
                continue

            digest, filename = parts

            if len(digest) == 64:
                seed_inventory.append({
                    "sha256": digest,
                    "path": filename.lstrip("*")
                })

        seed_fingerprint = hashlib.sha256(
            json.dumps(
                seed_inventory,
                sort_keys=True
            ).encode("utf-8")
        ).hexdigest()

        return {
            "remote_lab": remote_lab,
            "afl_version": afl_version or "unavailable",
            "compiler_version": compiler_version or "unavailable",
            "binary_sha256": binary_hash,
            "seed_count": len(seed_inventory),
            "seed_inventory": seed_inventory,
            "seed_fingerprint": seed_fingerprint
        }

    # --------------------------------------------------
    # FUZZER STATISTICS
    # --------------------------------------------------

    def parse_stats_text(self, raw):
        stats = {}

        for line in raw.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                stats[key.strip()] = value.strip()

        return stats

    def collect_fuzzer_stats(self, worker, stats_path):
        if not stats_path:
            return {
                "available": False,
                "message": "Fuzzer statistics path not configured."
            }

        try:
            with worker.sftp.open(stats_path, "r") as remote_file:
                raw = remote_file.read()

            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")

            stats = self.parse_stats_text(raw)

            return {
                "available": bool(stats),
                "statistics": stats,
                "source": "experiment_remote_stats"
            }

        except Exception as error:
            return {
                "available": False,
                "message": str(error),
                "source": "experiment_remote_stats"
            }

    def get_experiment_final_stats(self, experiment_dir, fuzzing, worker=None):
        # First preference: final statistics recorded by FuzzingManager.
        recorded_stats = fuzzing.get("final_statistics")

        if isinstance(recorded_stats, dict) and recorded_stats:
            return {
                "available": True,
                "statistics": recorded_stats,
                "source": "fuzzing_manager_final_statistics"
            }

        # Second preference: the local experiment-specific statistics file.
        local_stats_file = experiment_dir / "fuzzer_stats.json"

        if local_stats_file.is_file():
            local_stats = self.read_json(local_stats_file)

            if isinstance(local_stats, dict) and local_stats:
                # Some versions save the raw AFL++ statistics directly.
                if "statistics" in local_stats:
                    return {
                        "available": bool(local_stats.get("statistics")),
                        "statistics": local_stats.get("statistics", {}),
                        "source": "local_experiment_stats"
                    }

                return {
                    "available": True,
                    "statistics": local_stats,
                    "source": "local_experiment_stats"
                }

        # Last preference: fetch the experiment-specific remote stats file.
        remote_stats_path = (
            fuzzing.get("final_stats_path")
            or fuzzing.get("stats_path")
        )

        if worker and remote_stats_path:
            return self.collect_fuzzer_stats(
                worker,
                remote_stats_path
            )

        return {
            "available": False,
            "message": (
                "No experiment-specific final statistics were found. "
                "Shared AFL++ statistics were deliberately not used."
            ),
            "source": "unavailable"
        }

    # --------------------------------------------------
    # EXPERIMENT CREATION
    # --------------------------------------------------

    def create_experiment(self, host, username):
        kali = self.load_config().get("kali", {})

        if not host or not username:
            return {
                "status": "failed",
                "message": "Kali host and username are required."
            }

        worker = KaliWorker(host, username)

        try:
            print("[+] Connecting to Kali for environment fingerprinting...")

            if not worker.connect():
                return {
                    "status": "failed",
                    "message": "Kali connection failed."
                }

            remote = self.collect_remote_environment(worker, kali)

            source_file = self.base_dir / "target.c"

            source_hash = (
                self.sha256_file(source_file)
                if source_file.is_file()
                else None
            )

            experiment_id = (
                "EXP-"
                + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                + "-"
                + uuid.uuid4().hex[:6].upper()
            )

            experiment_dir = self.experiment_path(experiment_id)
            experiment_dir.mkdir(parents=True, exist_ok=False)

            config_snapshot = {
                "remote_lab": remote["remote_lab"],
                "target": "./target",
                "seed_directory": "./seeds",
                "experiment_output_root": (
                    remote["remote_lab"] + "/experiments"
                ),
                "host": host,
                "username": username
            }

            config_fingerprint = hashlib.sha256(
                json.dumps(
                    config_snapshot,
                    sort_keys=True
                ).encode("utf-8")
            ).hexdigest()

            experiment = {
                "project": "ZeroTrace",
                "experiment_id": experiment_id,
                "status": "created",
                "created_at": self.timestamp(),
                "finalized_at": None,

                "target_fingerprint": {
                    "source_file": "target.c",
                    "source_sha256": source_hash,
                    "binary_sha256": remote["binary_sha256"]
                },

                "environment": {
                    "afl_version": remote["afl_version"],
                    "compiler_version": remote["compiler_version"],
                    "remote_lab": remote["remote_lab"]
                },

                "corpus": {
                    "seed_count": remote["seed_count"],
                    "seed_fingerprint": remote["seed_fingerprint"],
                    "seeds": remote["seed_inventory"]
                },

                "configuration": config_snapshot,
                "configuration_sha256": config_fingerprint,

                "initial_statistics": {
                    "available": False,
                    "message": (
                        "Experiment-specific statistics are collected "
                        "after isolated fuzzing starts. Shared AFL++ "
                        "statistics are not used as an experiment baseline."
                    )
                },

                "final_statistics": None,

                "notes": (
                    "Environment snapshot created. "
                    "This operation does not start or stop AFL++."
                )
            }

            self.write_json(
                experiment_dir / "manifest.json",
                experiment
            )

            self.write_json(
                experiment_dir / "target_fingerprint.json",
                experiment["target_fingerprint"]
            )

            self.write_json(
                experiment_dir / "environment.json",
                experiment["environment"]
            )

            self.update_history(experiment)

            return {
                "status": "completed",
                "experiment_id": experiment_id,
                "experiment_directory": str(experiment_dir),
                "source_sha256": source_hash,
                "binary_sha256": remote["binary_sha256"],
                "afl_version": remote["afl_version"],
                "compiler_version": remote["compiler_version"],
                "seed_count": remote["seed_count"],
                "message": "Experiment environment captured successfully."
            }

        except Exception as error:
            return {
                "status": "failed",
                "message": str(error)
            }

        finally:
            worker.close()

    # --------------------------------------------------
    # EXPERIMENT FINALIZATION
    # --------------------------------------------------

    def finalize_experiment(self, experiment_id, host, username):
        worker = None

        try:
            experiment_dir = self.experiment_path(experiment_id)
            manifest_file = experiment_dir / "manifest.json"

            if not manifest_file.is_file():
                return {
                    "status": "failed",
                    "message": "Experiment manifest not found."
                }

            experiment = self.read_json(manifest_file)

            if experiment.get("status") == "finalized":
                return {
                    "status": "already_finalized",
                    "message": "This experiment is already finalized."
                }

            # Require an explicitly stopped isolated fuzzing process.
            fuzzing = experiment.get("fuzzing", {})

            if not isinstance(fuzzing, dict):
                fuzzing = {}

            fuzzing_status = fuzzing.get("status")

            if fuzzing_status != "stopped":
                return {
                    "status": "failed",
                    "message": (
                        "Experiment cannot be finalized yet. "
                        "Its isolated fuzzing status must be 'stopped'. "
                        "Use option 29 to stop experiment fuzzing first."
                    ),
                    "fuzzing_status": fuzzing_status
                }

            if not host or not username:
                return {
                    "status": "failed",
                    "message": "Kali host and username are required."
                }

            kali = self.load_config().get("kali", {})
            worker = KaliWorker(host, username)

            try:
                if not worker.connect():
                    return {
                        "status": "failed",
                        "message": "Kali connection failed."
                    }

                # Read only this experiment's statistics.
                stats = self.get_experiment_final_stats(
                    experiment_dir,
                    fuzzing,
                    worker
                )

                current_remote = self.collect_remote_environment(
                    worker,
                    kali
                )

            finally:
                worker.close()
                worker = None

            original = experiment.get("environment", {})
            original_target = experiment.get("target_fingerprint", {})
            original_corpus = experiment.get("corpus", {})

            checks = {
                "afl_version_unchanged": (
                    original.get("afl_version")
                    == current_remote.get("afl_version")
                ),
                "compiler_version_unchanged": (
                    original.get("compiler_version")
                    == current_remote.get("compiler_version")
                ),
                "binary_unchanged": (
                    original_target.get("binary_sha256")
                    == current_remote.get("binary_sha256")
                ),
                "seed_corpus_unchanged": (
                    original_corpus.get("seed_fingerprint")
                    == current_remote.get("seed_fingerprint")
                )
            }

            environment_unchanged = all(checks.values())

            experiment["finalized_at"] = self.timestamp()
            experiment["status"] = "finalized"
            experiment["final_statistics"] = stats

            experiment["final_environment_check"] = checks
            experiment["environment_unchanged"] = environment_unchanged

            experiment["final_corpus"] = {
                "seed_count": current_remote["seed_count"],
                "seed_fingerprint": current_remote["seed_fingerprint"]
            }

            experiment["fuzzing"]["finalization_confirmed"] = True
            experiment["fuzzing"]["finalized_at"] = experiment["finalized_at"]

            self.write_json(manifest_file, experiment)

            results = {
                "project": "ZeroTrace",
                "experiment_id": experiment_id,
                "status": "finalized",
                "created_at": experiment.get("created_at"),
                "finalized_at": experiment["finalized_at"],
                "fuzzing_status": fuzzing_status,
                "statistics": stats,
                "environment_checks": checks,
                "environment_unchanged": environment_unchanged,
                "target_fingerprint": experiment.get(
                    "target_fingerprint", {}
                ),
                "corpus": experiment.get("corpus", {}),
                "final_corpus": experiment.get("final_corpus", {})
            }

            self.write_json(
                experiment_dir / "results.json",
                results
            )

            self.update_history(experiment)

            return {
                "status": "completed",
                "experiment_id": experiment_id,
                "fuzzing_status": fuzzing_status,
                "statistics_available": stats.get("available", False),
                "statistics_source": stats.get("source"),
                "environment_unchanged": environment_unchanged,
                "checks": checks,
                "statistics": stats,
                "results_file": str(experiment_dir / "results.json"),
                "message": (
                    "Experiment finalized using experiment-specific "
                    "fuzzing statistics."
                )
            }

        except Exception as error:
            return {
                "status": "failed",
                "message": str(error)
            }

        finally:
            if worker is not None:
                worker.close()

    # --------------------------------------------------
    # EXPERIMENT LIST
    # --------------------------------------------------

    def list_experiments(self):
        history = self.get_history()

        return {
            "status": "completed",
            "total_experiments": len(history),
            "experiments": history
        }

    # --------------------------------------------------
    # EXPERIMENT COMPARISON
    # --------------------------------------------------

    def compare_experiments(self, first_id, second_id):
        try:
            first_path = self.experiment_path(first_id)
            second_path = self.experiment_path(second_id)

            first_file = first_path / "manifest.json"
            second_file = second_path / "manifest.json"

            if not first_file.is_file() or not second_file.is_file():
                return {
                    "status": "failed",
                    "message": (
                        "One or both experiment manifests are missing."
                    )
                }

            first = self.read_json(first_file)
            second = self.read_json(second_file)

            comparisons = {
                "source_sha256": (
                    first.get("target_fingerprint", {}).get("source_sha256")
                    == second.get("target_fingerprint", {}).get("source_sha256")
                ),
                "binary_sha256": (
                    first.get("target_fingerprint", {}).get("binary_sha256")
                    == second.get("target_fingerprint", {}).get("binary_sha256")
                ),
                "afl_version": (
                    first.get("environment", {}).get("afl_version")
                    == second.get("environment", {}).get("afl_version")
                ),
                "compiler_version": (
                    first.get("environment", {}).get("compiler_version")
                    == second.get("environment", {}).get("compiler_version")
                ),
                "seed_fingerprint": (
                    first.get("corpus", {}).get("seed_fingerprint")
                    == second.get("corpus", {}).get("seed_fingerprint")
                ),
                "configuration_sha256": (
                    first.get("configuration_sha256")
                    == second.get("configuration_sha256")
                )
            }

            matching = sum(comparisons.values())

            first_stats = first.get("final_statistics", {})
            second_stats = second.get("final_statistics", {})

            first_values = first_stats.get("statistics", {})
            second_values = second_stats.get("statistics", {})

            return {
                "status": "completed",
                "first_experiment": first_id,
                "second_experiment": second_id,
                "matching_checks": matching,
                "total_checks": len(comparisons),
                "environment_matches": all(comparisons.values()),
                "comparisons": comparisons,
                "fuzzing_statistics": {
                    "first": {
                        "available": first_stats.get("available", False),
                        "statistics": first_values
                    },
                    "second": {
                        "available": second_stats.get("available", False),
                        "statistics": second_values
                    }
                },
                "interpretation": (
                    "Recorded fingerprints match."
                    if all(comparisons.values())
                    else "One or more recorded fingerprints differ."
                )
            }

        except Exception as error:
            return {
                "status": "failed",
                "message": str(error)
            }

    # --------------------------------------------------
    # MAIN ENTRY POINT
    # --------------------------------------------------

    def run(
        self,
        action,
        host=None,
        username=None,
        experiment_id=None,
        second_id=None
    ):

        if action == "create":
            return self.create_experiment(host, username)

        if action == "finalize":
            return self.finalize_experiment(
                experiment_id,
                host,
                username
            )

        if action == "list":
            return self.list_experiments()

        if action == "compare":
            return self.compare_experiments(
                experiment_id,
                second_id
            )

        return {
            "status": "failed",
            "message": "Use create, finalize, list or compare."
        }
