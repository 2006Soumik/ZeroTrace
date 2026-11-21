
import inspect
import json
import re
import time

from pathlib import Path
from datetime import datetime, timezone


class WorkflowManager:

    def __init__(self, *args, **kwargs):
        self.base_dir = Path(__file__).resolve().parent.parent

        self.reports_dir = self.base_dir / "reports"
        self.workflow_dir = self.reports_dir / "workflow_runs"
        self.crashes_dir = self.reports_dir / "crashes"

        self.workflow_dir.mkdir(parents=True, exist_ok=True)
        self.crashes_dir.mkdir(parents=True, exist_ok=True)

        self.modules = {}

        self.target_manager = kwargs.get("target_manager")
        self.experiment_manager = kwargs.get("experiment_manager")
        self.fuzzing_manager = kwargs.get("fuzzing_manager")
        self.crash_collector = kwargs.get("crash_collector")
        self.crash_analyzer = kwargs.get("crash_analyzer")

        self.static_analyzer = kwargs.get("static_analyzer")
        self.dataflow_analyzer = kwargs.get("dataflow_analyzer")
        self.vulnerability_classifier = kwargs.get(
            "vulnerability_classifier"
        )
        self.crash_prioritizer = kwargs.get("crash_prioritizer")
        self.root_cause_analyzer = kwargs.get("root_cause_analyzer")
        self.exploitability_assessor = kwargs.get(
            "exploitability_assessor"
        )
        self.evidence_correlator = kwargs.get("evidence_correlator")
        self.vulnerability_correlator = kwargs.get(
            "vulnerability_correlator"
        )
        self.research_report_generator = kwargs.get(
            "research_report_generator"
        )

        self._discover_modules(args)

        for name, module in kwargs.items():
            if module is not None:
                self.modules[name] = module

    # --------------------------------------------------
    # MODULE DISCOVERY
    # --------------------------------------------------

    def _discover_modules(self, objects):
        for module in objects:
            if module is None:
                continue

            class_name = module.__class__.__name__

            mapping = {
                "TargetManager": "target_manager",
                "ExperimentManager": "experiment_manager",
                "FuzzingManager": "fuzzing_manager",
                "CrashCollector": "crash_collector",
                "CrashAnalyzer": "crash_analyzer",
                "StaticAnalyzer": "static_analyzer",
                "DataFlowAnalyzer": "dataflow_analyzer",
                "VulnerabilityClassifier": "vulnerability_classifier",
                "CrashPrioritizer": "crash_prioritizer",
                "RootCauseAnalyzer": "root_cause_analyzer",
                "ExploitabilityAssessor": "exploitability_assessor",
                "EvidenceCorrelator": "evidence_correlator",
                "VulnerabilityCorrelator": "vulnerability_correlator",
                "ResearchReportGenerator": "research_report_generator"
            }

            attribute = mapping.get(class_name)

            if attribute:
                setattr(self, attribute, module)

            self.modules[class_name] = module

    # --------------------------------------------------
    # GENERAL HELPERS
    # --------------------------------------------------

    @staticmethod
    def timestamp():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def is_success(result):
        if result is True:
            return True

        if result is False or result is None:
            return False

        if not isinstance(result, dict):
            return bool(result)

        status = str(result.get("status", "")).strip().lower()

        accepted = {
            "success",
            "completed",
            "complete",
            "passed",
            "running",
            "started",
            "stopped",
            "memory error classified",
            "crashes collected",
            "analysis completed"
        }

        if status in accepted:
            return True

        if result.get("success") is True:
            return True

        if result.get("valid") is True:
            return True

        if result.get("status") is None:
            if result.get("tool") or result.get("module"):
                return True

        return False

    @staticmethod
    def _extract_experiment_id(result):
        if isinstance(result, str):
            match = re.search(r"EXP-[A-Za-z0-9-]+", result)
            return match.group(0) if match else None

        if not isinstance(result, dict):
            return None

        possible_keys = (
            "experiment_id",
            "id",
            "experiment"
        )

        for key in possible_keys:
            value = result.get(key)

            if isinstance(value, str):
                match = re.search(r"EXP-[A-Za-z0-9-]+", value)

                if match:
                    return match.group(0)

        for value in result.values():
            if isinstance(value, dict):
                found = WorkflowManager._extract_experiment_id(value)

                if found:
                    return found

        return None

    def _save_json(self, path, data):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4, default=str)

        return str(path)

    def save_workflow_report(self, experiment_id, results):
        safe_id = re.sub(
            r"[^A-Za-z0-9_-]",
            "_",
            str(experiment_id)
        )

        report_path = (
            self.workflow_dir /
            f"workflow_{safe_id}.json"
        )

        report = {
            "tool": "ZeroTrace",
            "module": "Automated Workflow",
            "experiment_id": experiment_id,
            "generated_at": self.timestamp(),
            "workflow_status": results.get(
                "workflow_status",
                "unknown"
            ),
            "completed_stages": results.get(
                "completed_stages",
                []
            ),
            "failed_stage": results.get("failed_stage"),
            "errors": results.get("errors", []),
            "results": results
        }

        self._save_json(report_path, report)

        print(f"\n[+] Workflow report saved: {report_path}")

        return str(report_path)

    # --------------------------------------------------
    # MODULE EXECUTION
    # --------------------------------------------------

    def _execute(self, module, method_names, **kwargs):
        if module is None:
            return {
                "status": "failed",
                "error": "Required module is not registered"
            }

        for method_name in method_names:
            method = getattr(module, method_name, None)

            if not callable(method):
                continue

            try:
                signature = inspect.signature(method)
                parameters = signature.parameters

                accepts_kwargs = any(
                    parameter.kind == inspect.Parameter.VAR_KEYWORD
                    for parameter in parameters.values()
                )

                if accepts_kwargs:
                    filtered_kwargs = kwargs
                else:
                    filtered_kwargs = {
                        key: value
                        for key, value in kwargs.items()
                        if key in parameters
                    }

                return method(**filtered_kwargs)

            except Exception as error:
                return {
                    "status": "failed",
                    "error": str(error),
                    "method": method_name
                }

        return {
            "status": "failed",
            "error": (
                "No compatible method found: " +
                ", ".join(method_names)
            )
        }

    def _stage(self, results, name, result):
        results.setdefault("stages", {})[name] = {
            "completed_at": self.timestamp(),
            "result": result
        }

        if not self.is_success(result):
            results["failed_stage"] = name
            results["workflow_status"] = "failed"

            error = (
                result.get("error") or result.get("message")
                if isinstance(result, dict)
                else str(result)
            )

            results.setdefault("errors", []).append({
                "stage": name,
                "error": error or "Stage did not report success"
            })

            print(f"\n[-] {name} failed: {error or result}")
            return False

        results.setdefault("completed_stages", []).append(name)

        print(f"[+] {name} completed")

        return True

    # --------------------------------------------------
    # CRASH COLLECTION
    # --------------------------------------------------

    def collect_experiment_crashes(
        self,
        host,
        username,
        experiment_id
    ):
        if self.crash_collector is None:
            return {
                "status": "failed",
                "error": "CrashCollector is not registered"
            }

        return self._execute(
            self.crash_collector,
            (
                "collect_experiment_crashes",
                "collect_crashes",
                "run"
            ),
            host=host,
            username=username,
            experiment_id=experiment_id
        )

    # --------------------------------------------------
    # ANALYSIS PIPELINE
    # --------------------------------------------------

    def run_analysis_pipeline(
        self,
        host,
        username,
        target_path,
        results
    ):
        analysis_modules = [
            (
                "Static Analysis",
                self.static_analyzer,
                ("run",),
                {"target_path": target_path}
            ),
            (
                "Data Flow Analysis",
                self.dataflow_analyzer,
                ("run",),
                {"target_path": target_path}
            )
        ]

        for name, module, methods, arguments in analysis_modules:
            if module is None:
                continue

            result = self._execute(
                module,
                methods,
                **arguments
            )

            if not self._stage(results, name, result):
                return False

        return True

    # --------------------------------------------------
    # REMAINING ANALYSIS MODULES
    # --------------------------------------------------

    def run_remaining_analysis(self, results):
        analysis_modules = [
            (
                "Vulnerability Classification",
                self.vulnerability_classifier
            ),
            (
                "Crash Prioritization",
                self.crash_prioritizer
            ),
            (
                "Root Cause Analysis",
                self.root_cause_analyzer
            ),
            (
                "Exploitability Assessment",
                self.exploitability_assessor
            ),
            (
                "Evidence Correlation",
                self.evidence_correlator
            ),
            (
                "Vulnerability Correlation",
                self.vulnerability_correlator
            ),
            (
                "Research Report Generation",
                self.research_report_generator
            )
        ]

        for name, module in analysis_modules:
            if module is None:
                continue

            result = self._execute(module, ("run",))

            if not self._stage(results, name, result):
                return False

        return True

    # --------------------------------------------------
    # EXPERIMENT-SPECIFIC FUZZER CONTROL
    # --------------------------------------------------

    def _stop_fuzzer(self, host, username, experiment_id):
        if self.fuzzing_manager is None:
            return {
                "status": "failed",
                "error": "FuzzingManager is not registered"
            }

        try:
            return self.fuzzing_manager.run(
                action="stop_experiment",
                host=host,
                username=username,
                experiment_id=experiment_id
            )

        except Exception as error:
            return {
                "status": "failed",
                "error": str(error)
            }

    def _wait_for_fuzzer(
        self,
        host,
        username,
        experiment_id,
        duration
    ):
        """
        Wait for AFL++ to stop itself using its -V time limit.
        The additional 15 seconds allow for startup and polling overhead.
        """

        if self.fuzzing_manager is None:
            return {
                "status": "failed",
                "error": "FuzzingManager is not registered"
            }

        deadline = time.monotonic() + duration + 15

        print(
            f"\n[+] Waiting for AFL++ automatic stop "
            f"({duration}-second limit)..."
        )

        while time.monotonic() < deadline:
            status_result = self.fuzzing_manager.run(
                action="status_experiment",
                host=host,
                username=username,
                experiment_id=experiment_id
            )

            if not isinstance(status_result, dict):
                return {
                    "status": "failed",
                    "error": "Invalid fuzzer status response."
                }

            state = str(
                status_result.get("status", "")
            ).strip().lower()

            if state == "stopped":
                return {
                    "status": "completed",
                    "message": "AFL++ reached its automatic runtime limit.",
                    "requested_duration_seconds": duration,
                    "final_statistics": status_result.get(
                        "statistics",
                        {}
                    )
                }

            if state != "running":
                return {
                    "status": "failed",
                    "error": (
                        status_result.get("error")
                        or status_result.get("message")
                        or "Could not confirm AFL++ running status."
                    ),
                    "status_result": status_result
                }

            time.sleep(2)

        return {
            "status": "failed",
            "error": (
                "AFL++ did not stop within the expected time window. "
                "Emergency cleanup will be attempted."
            ),
            "requested_duration_seconds": duration
        }

    # --------------------------------------------------
    # MAIN AUTOMATED WORKFLOW
    # --------------------------------------------------

    def run(
        self,
        host=None,
        username=None,
        target_path=None,
        duration=None
    ):
        print("\n" + "=" * 55)
        print("          ZEROTRACE AUTOMATED WORKFLOW")
        print("=" * 55)

        if not host:
            host = input("Enter Kali IP address: ").strip()

        if not username:
            username = input("Enter Kali username: ").strip()

        if not target_path:
            target_path = input(
                "Enter local target source path (default target.c): "
            ).strip()

        if not target_path:
            target_path = "target.c"

        if duration is None:
            duration_input = input(
                "Enter fuzzing duration in seconds "
                "(default 60, max 3600): "
            ).strip()

            if not duration_input:
                duration = 60
            else:
                try:
                    duration = int(duration_input)
                except ValueError:
                    print("[-] Duration must be a number.")
                    return {
                        "status": "failed",
                        "error": "Invalid fuzzing duration"
                    }

        try:
            duration = int(duration)
        except (TypeError, ValueError):
            print("[-] Duration must be a number.")
            return {
                "status": "failed",
                "error": "Invalid fuzzing duration"
            }

        if not host or not username:
            print("[-] Kali IP and username are required.")
            return {
                "status": "failed",
                "error": "Missing Kali connection details"
            }

        if duration < 1 or duration > 3600:
            print("[-] Duration must be between 1 and 3600 seconds.")
            return {
                "status": "failed",
                "error": "Invalid fuzzing duration"
            }

        target_path = str(
            Path(target_path).expanduser().resolve()
        )

        print("\n[!] This workflow creates a NEW isolated experiment.")
        print("[!] Only use it with your authorized local lab target.")

        confirmation = input("Continue? (y/n): ").strip().lower()

        if confirmation != "y":
            print("[!] Workflow cancelled.")
            return {
                "status": "cancelled",
                "workflow_status": "cancelled"
            }

        results = {
            "tool": "ZeroTrace",
            "module": "Automated Workflow",
            "started_at": self.timestamp(),
            "workflow_status": "running",
            "host": host,
            "username": username,
            "target_path": target_path,
            "fuzzing_duration_seconds": duration,
            "experiment_id": None,
            "completed_stages": [],
            "failed_stage": None,
            "errors": [],
            "stages": {}
        }

        experiment_id = None
        fuzzing_started = False

        def finish():
            return self._finish(
                results,
                host,
                username,
                experiment_id,
                fuzzing_started
            )

        try:
            # ------------------------------------------
            # STAGE 1: TARGET VALIDATION
            # ------------------------------------------

            print("\n[1/10] Validating target...")

            target_result = self._execute(
                self.target_manager,
                ("run",),
                target_path=target_path
            )

            if not self._stage(
                results,
                "Target Validation",
                target_result
            ):
                return finish()

            # ------------------------------------------
            # STAGE 2: CREATE EXPERIMENT
            # ------------------------------------------

            print("\n[2/10] Creating isolated experiment...")

            experiment_result = self._execute(
                self.experiment_manager,
                ("create_experiment",),
                host=host,
                username=username
            )

            if not self.is_success(experiment_result):
                experiment_result = self._execute(
                    self.experiment_manager,
                    ("run",),
                    action="create",
                    host=host,
                    username=username
                )

            experiment_id = self._extract_experiment_id(
                experiment_result
            )

            if not experiment_id:
                results["stages"]["Experiment Creation"] = {
                    "result": experiment_result
                }

                results["failed_stage"] = "Experiment Creation"
                results["workflow_status"] = "failed"

                results["errors"].append({
                    "stage": "Experiment Creation",
                    "error": "Experiment ID was not returned"
                })

                return finish()

            results["experiment_id"] = experiment_id

            if not self._stage(
                results,
                "Experiment Creation",
                experiment_result
            ):
                return finish()

            # ------------------------------------------
            # STAGE 3: START ISOLATED FUZZING
            # ------------------------------------------

            print("\n[3/10] Starting isolated AFL++ fuzzing...")

            if self.fuzzing_manager is None:
                fuzz_result = {
                    "status": "failed",
                    "error": "FuzzingManager is not registered"
                }
            else:
                fuzz_result = self.fuzzing_manager.run(
                    action="start_experiment",
                    host=host,
                    username=username,
                    experiment_id=experiment_id,
                    duration=duration
                )

            if not self.is_success(fuzz_result):
                self._stage(
                    results,
                    "Fuzzing Start",
                    fuzz_result
                )
                return finish()

            fuzzing_started = True

            if not self._stage(
                results,
                "Fuzzing Start",
                fuzz_result
            ):
                return finish()

            # ------------------------------------------
            # STAGE 4: WAIT FOR AFL++ AUTOMATIC STOP
            # ------------------------------------------

            print(
                f"\n[4/10] AFL++ runtime limit: {duration} seconds..."
            )

            duration_result = self._wait_for_fuzzer(
                host,
                username,
                experiment_id,
                duration
            )

            if not self._stage(
                results,
                "Fuzzing Duration",
                duration_result
            ):
                return finish()

            # ------------------------------------------
            # STAGE 5: STOP / CONFIRM STOPPED
            # ------------------------------------------

            print("\n[5/10] Confirming experiment fuzzer stopped...")

            stop_result = self._stop_fuzzer(
                host,
                username,
                experiment_id
            )

            if not self._stage(
                results,
                "Fuzzing Stop",
                stop_result
            ):
                return finish()

            fuzzing_started = False

            # ------------------------------------------
            # STAGE 6: FINALIZE EXPERIMENT
            # ------------------------------------------

            print("\n[6/10] Finalizing experiment...")

            finalize_result = self._execute(
                self.experiment_manager,
                ("finalize_experiment",),
                experiment_id=experiment_id,
                host=host,
                username=username
            )

            if not self.is_success(finalize_result):
                finalize_result = self._execute(
                    self.experiment_manager,
                    ("run",),
                    action="finalize",
                    experiment_id=experiment_id,
                    host=host,
                    username=username
                )

            if not self._stage(
                results,
                "Experiment Finalization",
                finalize_result
            ):
                return finish()

            # ------------------------------------------
            # STAGE 7: COLLECT EXPERIMENT CRASHES
            # ------------------------------------------

            print("\n[7/10] Collecting experiment crashes...")

            crash_result = self.collect_experiment_crashes(
                host,
                username,
                experiment_id
            )

            if not self._stage(
                results,
                "Crash Collection",
                crash_result
            ):
                return finish()

            # ------------------------------------------
            # STAGE 8: STATIC AND DATAFLOW ANALYSIS
            # ------------------------------------------

            print(
                "\n[8/10] Running static and dataflow analysis..."
            )

            if not self.run_analysis_pipeline(
                host,
                username,
                target_path,
                results
            ):
                return finish()

            # ------------------------------------------
            # STAGE 9: CRASH ANALYSIS AND INTELLIGENCE
            # ------------------------------------------

            print("\n[9/10] Analyzing collected crashes...")

            crash_analysis_result = self._execute(
                self.crash_analyzer,
                ("run",),
                host=host,
                username=username
            )

            if not self._stage(
                results,
                "Crash Analysis",
                crash_analysis_result
            ):
                return finish()

            if not self.run_remaining_analysis(results):
                return finish()

            # ------------------------------------------
            # STAGE 10: SAVE FINAL WORKFLOW REPORT
            # ------------------------------------------

            print("\n[10/10] Saving workflow report...")

            results["workflow_status"] = "completed"
            results["finished_at"] = self.timestamp()

            report_path = self.save_workflow_report(
                experiment_id,
                results
            )

            results["report_path"] = report_path

            self._stage(
                results,
                "Workflow Report",
                {
                    "status": "completed",
                    "report_path": report_path
                }
            )

            results["workflow_status"] = "completed"
            results["finished_at"] = self.timestamp()

            self.save_workflow_report(
                experiment_id,
                results
            )

            print("\n" + "=" * 55)
            print("       ZEROTRACE WORKFLOW COMPLETED")
            print("=" * 55)

            print(f"Experiment ID: {experiment_id}")
            print(
                f"Completed stages: "
                f"{len(results['completed_stages'])}"
            )
            print(f"Report: {report_path}")

            return results

        except KeyboardInterrupt:
            results["workflow_status"] = "interrupted"

            results["errors"].append({
                "stage": "Workflow",
                "error": "Workflow interrupted by user"
            })

            print("\n[!] Workflow interrupted.")

            return finish()

        except Exception as error:
            results["workflow_status"] = "failed"

            results["errors"].append({
                "stage": "Workflow",
                "error": str(error)
            })

            print(f"\n[-] Workflow error: {error}")

            return finish()

    # --------------------------------------------------
    # WORKFLOW FINALIZATION AND CLEANUP
    # --------------------------------------------------

    def _finish(
        self,
        results,
        host=None,
        username=None,
        experiment_id=None,
        fuzzing_started=False
    ):
        if (
            fuzzing_started
            and host
            and username
            and experiment_id
        ):
            print("\n[!] Performing emergency fuzzer cleanup...")

            cleanup_result = self._stop_fuzzer(
                host,
                username,
                experiment_id
            )

            results["cleanup"] = cleanup_result

            if self.is_success(cleanup_result):
                print("[+] Emergency cleanup completed.")
            else:
                print("[-] Emergency cleanup reported a failure.")

        results["finished_at"] = self.timestamp()

        if results.get("workflow_status") == "running":
            results["workflow_status"] = "failed"

        report_id = (
            experiment_id
            or "EXP-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        )

        try:
            report_path = self.save_workflow_report(
                report_id,
                results
            )

            results["report_path"] = report_path

        except Exception as error:
            print(
                f"[-] Could not save workflow report: {error}"
            )

        print("\n--- Workflow Summary ---")
        print("Status:", results.get("workflow_status"))
        print(
            "Completed stages:",
            len(results.get("completed_stages", []))
        )

        if results.get("failed_stage"):
            print("Failed stage:", results["failed_stage"])

        return results
