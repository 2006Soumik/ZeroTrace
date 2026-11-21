
import json
import shlex
import time

from pathlib import Path
from datetime import datetime, timezone

from integrations.kali_worker import KaliWorker


class FuzzingManager:

    def __init__(self):
        self.remote_lab = None
        self.output_dir = "findings_zerotrace_test2"
        self.pid_file = "zerotrace_fuzzing.pid"
        self.log_file = "zerotrace_fuzzing.log"

        self.project_root = Path(__file__).resolve().parent.parent
        self.experiments_dir = self.project_root / "reports" / "experiments"

    # --------------------------------------------------
    # GENERAL HELPERS
    # --------------------------------------------------

    def _timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    def _result(self, status, message, **kwargs):
        result = {
            "status": status,
            "message": message
        }
        result.update(kwargs)
        return result

    def _safe_experiment_id(self, experiment_id):
        if not experiment_id:
            raise ValueError("Experiment ID is required.")

        if not experiment_id.startswith("EXP-"):
            raise ValueError("Invalid experiment ID.")

        allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

        if any(char not in allowed for char in experiment_id):
            raise ValueError("Experiment ID contains invalid characters.")

        return experiment_id

    def _load_manifest(self, experiment_id):
        experiment_id = self._safe_experiment_id(experiment_id)

        manifest_path = (
            self.experiments_dir /
            experiment_id /
            "manifest.json"
        )

        if not manifest_path.is_file():
            raise FileNotFoundError(
                f"Experiment manifest not found: {experiment_id}"
            )

        with open(manifest_path, "r", encoding="utf-8") as file:
            manifest = json.load(file)

        return manifest_path, manifest

    def _save_manifest(self, manifest_path, manifest):
        temporary_path = manifest_path.with_suffix(".tmp")

        with open(temporary_path, "w", encoding="utf-8") as file:
            json.dump(manifest, file, indent=4)

        temporary_path.replace(manifest_path)

    def _update_experiment_metadata(self, experiment_id, updates):
        manifest_path, manifest = self._load_manifest(experiment_id)

        fuzzing = manifest.get("fuzzing", {})
        fuzzing.update(updates)

        manifest["fuzzing"] = fuzzing
        manifest["updated_at"] = self._timestamp()

        self._save_manifest(manifest_path, manifest)

        return manifest

    def _parse_stats(self, raw_stats):
        stats = {}

        for line in raw_stats.splitlines():
            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            stats[key.strip()] = value.strip()

        return stats

    def _write_local_stats(self, experiment_id, stats):
        local_dir = self.experiments_dir / experiment_id
        local_dir.mkdir(parents=True, exist_ok=True)

        stats_path = local_dir / "fuzzer_stats.json"
        temporary_path = stats_path.with_suffix(".tmp")

        with open(temporary_path, "w", encoding="utf-8") as file:
            json.dump(
                {
                    "collected_at": self._timestamp(),
                    "stats": stats
                },
                file,
                indent=4
            )

        temporary_path.replace(stats_path)

        return str(stats_path)

    def _remote_paths(self, username, experiment_id):
        lab = f"/home/{username}/zerotrace_worker/lab"
        experiment_dir = f"{lab}/experiments/{experiment_id}"

        return {
            "lab": lab,
            "experiment_dir": experiment_dir,
            "output_dir": f"{experiment_dir}/findings",
            "pid_file": f"{experiment_dir}/fuzzer.pid",
            "log_file": f"{experiment_dir}/fuzzer.log",
            "stats_file": (
                f"{experiment_dir}/findings/default/fuzzer_stats"
            )
        }

    def _remote_process_check(self, worker, paths):
        pid_file = shlex.quote(paths["pid_file"])
        output_dir = shlex.quote(paths["output_dir"])

        command = (
            f"if [ ! -f {pid_file} ]; then "
            "echo NOT_RUNNING; "
            "else "
            f"PID=$(cat {pid_file}); "
            'if [ -n "$PID" ] && '
            'kill -0 "$PID" 2>/dev/null && '
            'tr "\\0" " " < "/proc/$PID/cmdline" '
            f'| grep -F -- {output_dir} >/dev/null; '
            "then echo RUNNING; "
            "else echo NOT_RUNNING; fi; "
            "fi"
        )

        result = worker.execute_command(command)
        output = result.get("output", "").strip()

        return "RUNNING" in output.splitlines()

    # --------------------------------------------------
    # MAIN DISPATCHER
    # --------------------------------------------------

    def run(
        self,
        action,
        host,
        username,
        experiment_id=None,
        duration=60
    ):
        worker = None

        try:
            if action in (
                "start_experiment",
                "status_experiment",
                "stop_experiment"
            ):
                experiment_id = self._safe_experiment_id(
                    experiment_id
                )

                manifest_path, manifest = self._load_manifest(
                    experiment_id
                )

                if manifest.get("status") == "finalized":
                    return self._result(
                        "failed",
                        "This experiment is already finalized."
                    )

            if action == "start_experiment":
                try:
                    duration = int(duration)
                except (TypeError, ValueError):
                    return self._result(
                        "failed",
                        "Fuzzing duration must be an integer."
                    )

                if duration < 1 or duration > 3600:
                    return self._result(
                        "failed",
                        "Fuzzing duration must be between 1 and 3600 seconds."
                    )

            self.remote_lab = (
                f"/home/{username}/zerotrace_worker/lab"
            )

            worker = KaliWorker(host, username)

            if not worker.connect():
                return self._result(
                    "failed",
                    "Could not connect to Kali Linux."
                )

            if action == "start":
                return self.start_fuzzing(worker)

            elif action == "status":
                return self.check_status(worker)

            elif action == "stop":
                return self.stop_fuzzing(worker)

            elif action == "start_experiment":
                return self.start_experiment_fuzzing(
                    worker,
                    experiment_id,
                    username,
                    duration
                )

            elif action == "status_experiment":
                return self.check_experiment_status(
                    worker,
                    experiment_id,
                    username
                )

            elif action == "stop_experiment":
                return self.stop_experiment_fuzzing(
                    worker,
                    experiment_id,
                    username
                )

            return self._result(
                "failed",
                f"Unknown fuzzing action: {action}"
            )

        except Exception as error:
            return self._result("failed", str(error))

        finally:
            if worker is not None:
                worker.close()

    # --------------------------------------------------
    # LEGACY FUZZING
    # --------------------------------------------------

    def _paths(self):
        lab = shlex.quote(self.remote_lab)

        return {
            "lab": lab,
            "output": shlex.quote(self.output_dir),
            "pid": shlex.quote(self.pid_file),
            "log": shlex.quote(self.log_file)
        }

    def _process_check(self, worker):
        paths = self._paths()

        command = (
            f"cd {paths['lab']} && "
            f"if [ -f {paths['pid']} ]; then "
            f"PID=$(cat {paths['pid']}); "
            'if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null '
            '&& tr "\\0" " " < "/proc/$PID/cmdline" '
            f"| grep -F -- {paths['output']} >/dev/null; "
            "then echo RUNNING; "
            "else echo NOT_RUNNING; fi; "
            "else echo NOT_RUNNING; fi"
        )

        result = worker.execute_command(command)

        return "RUNNING" in result.get("output", "").splitlines()

    def start_fuzzing(self, worker):
        paths = self._paths()

        preflight = (
            f"cd {paths['lab']} && "
            "command -v afl-fuzz >/dev/null 2>&1 && "
            "test -x ./target && "
            "test -d ./seeds && "
            "find ./seeds -type f -print -quit | grep -q ."
        )

        result = worker.execute_command(preflight)

        if result.get("exit_code") != 0:
            return self._result(
                "failed",
                "Preflight failed. Check AFL++, target executable and seed corpus."
            )

        if self._process_check(worker):
            return self._result(
                "running",
                "Legacy fuzzing is already running."
            )

        existing = worker.execute_command(
            f"cd {paths['lab']} && "
            f"test -e {paths['output']}"
        )

        if existing.get("exit_code") == 0:
            return self._result(
                "failed",
                "Existing legacy findings directory detected. "
                "It will not be overwritten."
            )

        command = (
            f"cd {paths['lab']} && "
            f"(nohup afl-fuzz -i seeds -o {paths['output']} "
            f"-- ./target > {paths['log']} 2>&1 "
            f"< /dev/null & echo $! > {paths['pid']})"
        )

        result = worker.execute_command(command)

        if result.get("exit_code") != 0:
            return self._result(
                "failed",
                result.get("error", "Could not start AFL++.")
            )

        time.sleep(2)

        if self._process_check(worker):
            return self._result(
                "running",
                "Legacy AFL++ fuzzing started successfully."
            )

        return self._result(
            "failed",
            "AFL++ did not remain running. Check the fuzzer log."
        )

    def check_status(self, worker):
        paths = self._paths()
        running = self._process_check(worker)

        stats_path = (
            f"{self.remote_lab}/{self.output_dir}/default/fuzzer_stats"
        )

        command = (
            f"if [ -f {shlex.quote(stats_path)} ]; then "
            f"cat {shlex.quote(stats_path)}; "
            "else echo STATS_NOT_AVAILABLE; fi"
        )

        result = worker.execute_command(command)
        stats = self._parse_stats(result.get("output", ""))

        return self._result(
            "running" if running else "stopped",
            "Legacy fuzzing status collected.",
            process_state=(
                "FUZZING_RUNNING" if running else "FUZZING_STOPPED"
            ),
            statistics=stats
        )

    def stop_fuzzing(self, worker):
        paths = self._paths()

        if not self._process_check(worker):
            return self._result(
                "stopped",
                "Legacy fuzzing is not currently running."
            )

        command = (
            f"cd {paths['lab']} && "
            f"PID=$(cat {paths['pid']}) && "
            'kill -INT "$PID" 2>/dev/null'
        )

        result = worker.execute_command(command)

        if result.get("exit_code") != 0:
            return self._result(
                "failed",
                "Could not send stop signal to the legacy fuzzer."
            )

        for _ in range(20):
            time.sleep(1)

            if not self._process_check(worker):
                break

        if self._process_check(worker):
            return self._result(
                "running",
                "Fuzzer did not stop within 20 seconds."
            )

        worker.execute_command(
            f"cd {paths['lab']} && rm -f {paths['pid']}"
        )

        return self._result(
            "stopped",
            "Legacy AFL++ fuzzing stopped successfully."
        )

    # --------------------------------------------------
    # EXPERIMENT-ISOLATED FUZZING
    # --------------------------------------------------

    def start_experiment_fuzzing(
        self,
        worker,
        experiment_id,
        username,
        duration=60
    ):
        manifest_path, manifest = self._load_manifest(
            experiment_id
        )

        if manifest.get("status") == "finalized":
            return self._result(
                "failed",
                "Cannot start fuzzing on a finalized experiment."
            )

        try:
            duration = int(duration)
        except (TypeError, ValueError):
            return self._result(
                "failed",
                "Fuzzing duration must be an integer."
            )

        if duration < 1 or duration > 3600:
            return self._result(
                "failed",
                "Fuzzing duration must be between 1 and 3600 seconds."
            )

        paths = self._remote_paths(username, experiment_id)

        lab = shlex.quote(paths["lab"])
        experiment_dir = shlex.quote(paths["experiment_dir"])
        output_dir = shlex.quote(paths["output_dir"])
        pid_file = shlex.quote(paths["pid_file"])
        log_file = shlex.quote(paths["log_file"])

        preflight = (
            f"cd {lab} && "
            "command -v afl-fuzz >/dev/null 2>&1 && "
            "test -x ./target && "
            "test -d ./seeds && "
            "find ./seeds -type f -print -quit | grep -q ."
        )

        result = worker.execute_command(preflight)

        if result.get("exit_code") != 0:
            return self._result(
                "failed",
                "Preflight failed. Verify AFL++, target and seed corpus."
            )

        existence_check = worker.execute_command(
            f"if [ -e {experiment_dir} ]; then "
            "echo EXISTS; else echo AVAILABLE; fi"
        )

        if "EXISTS" in existence_check.get("output", ""):
            return self._result(
                "failed",
                "Experiment directory already exists. "
                "Existing experiment data will not be overwritten.",
                remote_directory=paths["experiment_dir"]
            )

        mkdir_result = worker.execute_command(
            f"mkdir -p {experiment_dir}"
        )

        if mkdir_result.get("exit_code") != 0:
            return self._result(
                "failed",
                "Could not create experiment directory."
            )

        # AFL++ -V sets the maximum fuzzing runtime in seconds.
        command = (
            f"cd {lab} && "
            f"(nohup afl-fuzz -V {duration} "
            f"-i seeds -o {output_dir} "
            f"-- ./target > {log_file} 2>&1 "
            f"< /dev/null & echo $! > {pid_file})"
        )

        result = worker.execute_command(command)

        if result.get("exit_code") != 0:
            return self._result(
                "failed",
                "Failed to launch experiment AFL++."
            )

        time.sleep(3)

        if not self._remote_process_check(worker, paths):
            log_result = worker.execute_command(
                f"tail -n 30 {log_file}"
            )

            return self._result(
                "failed",
                "AFL++ did not remain running. Check the experiment log.",
                log=log_result.get("output", "")
            )

        metadata = {
            "status": "running",
            "started_at": self._timestamp(),
            "requested_duration_seconds": duration,
            "runtime_limit": "AFL++ -V",
            "remote_directory": paths["experiment_dir"],
            "output_directory": paths["output_dir"],
            "pid_file": paths["pid_file"],
            "log_file": paths["log_file"],
            "stats_path": paths["stats_file"],
            "host": manifest.get("host", "")
        }

        self._update_experiment_metadata(
            experiment_id,
            metadata
        )

        return self._result(
            "running",
            "Experiment-isolated AFL++ fuzzing started with an automatic runtime limit.",
            experiment_id=experiment_id,
            requested_duration_seconds=duration,
            remote_directory=paths["experiment_dir"],
            output_directory=paths["output_dir"],
            pid_file=paths["pid_file"],
            log_file=paths["log_file"],
            stats_path=paths["stats_file"]
        )

    # --------------------------------------------------
    # EXPERIMENT STATUS
    # --------------------------------------------------

    def check_experiment_status(
        self,
        worker,
        experiment_id,
        username
    ):
        self._load_manifest(experiment_id)

        paths = self._remote_paths(username, experiment_id)

        running = self._remote_process_check(worker, paths)

        stats_command = (
            f"if [ -f {shlex.quote(paths['stats_file'])} ]; then "
            f"cat {shlex.quote(paths['stats_file'])}; "
            "else echo STATS_NOT_AVAILABLE; fi"
        )

        stats_result = worker.execute_command(stats_command)
        stats_output = stats_result.get("output", "")
        stats = self._parse_stats(stats_output)

        stats_local_path = None

        if stats and "STATS_NOT_AVAILABLE" not in stats_output:
            stats_local_path = self._write_local_stats(
                experiment_id,
                stats
            )

        log_result = worker.execute_command(
            f"if [ -f {shlex.quote(paths['log_file'])} ]; "
            f"then tail -n 15 {shlex.quote(paths['log_file'])}; "
            "else echo LOG_NOT_AVAILABLE; fi"
        )

        state = "running" if running else "stopped"

        self._update_experiment_metadata(
            experiment_id,
            {
                "status": state,
                "last_checked_at": self._timestamp()
            }
        )

        return self._result(
            state,
            "Experiment fuzzing status collected.",
            experiment_id=experiment_id,
            process_state=(
                "FUZZING_RUNNING" if running else "FUZZING_STOPPED"
            ),
            statistics=stats,
            local_stats_file=stats_local_path,
            log_tail=log_result.get("output", ""),
            remote_directory=paths["experiment_dir"]
        )

    # --------------------------------------------------
    # EXPERIMENT STOP
    # --------------------------------------------------

    def stop_experiment_fuzzing(
        self,
        worker,
        experiment_id,
        username
    ):
        self._load_manifest(experiment_id)

        paths = self._remote_paths(username, experiment_id)

        if not self._remote_process_check(worker, paths):
            self._update_experiment_metadata(
                experiment_id,
                {
                    "status": "stopped",
                    "stopped_at": self._timestamp()
                }
            )

            return self._result(
                "stopped",
                "This experiment's fuzzer is not currently running.",
                experiment_id=experiment_id
            )

        pid_file = shlex.quote(paths["pid_file"])

        command = (
            f"PID=$(cat {pid_file}) && "
            'kill -INT "$PID" 2>/dev/null'
        )

        result = worker.execute_command(command)

        if result.get("exit_code") != 0:
            return self._result(
                "failed",
                "Could not send stop signal to this experiment's fuzzer."
            )

        stopped = False

        for _ in range(20):
            time.sleep(1)

            if not self._remote_process_check(worker, paths):
                stopped = True
                break

        if not stopped:
            return self._result(
                "running",
                "Fuzzer did not stop within 20 seconds. "
                "No other processes were terminated.",
                experiment_id=experiment_id
            )

        worker.execute_command(f"rm -f {pid_file}")

        stats_command = (
            f"if [ -f {shlex.quote(paths['stats_file'])} ]; then "
            f"cat {shlex.quote(paths['stats_file'])}; "
            "fi"
        )

        stats_result = worker.execute_command(stats_command)

        stats = self._parse_stats(
            stats_result.get("output", "")
        )

        local_stats_path = None

        if stats:
            local_stats_path = self._write_local_stats(
                experiment_id,
                stats
            )

        self._update_experiment_metadata(
            experiment_id,
            {
                "status": "stopped",
                "stopped_at": self._timestamp(),
                "final_stats_path": local_stats_path,
                "final_statistics": stats
            }
        )

        return self._result(
            "stopped",
            "Experiment-isolated AFL++ fuzzing stopped successfully.",
            experiment_id=experiment_id,
            final_statistics=stats,
            local_stats_file=local_stats_path,
            remote_directory=paths["experiment_dir"]
        )
