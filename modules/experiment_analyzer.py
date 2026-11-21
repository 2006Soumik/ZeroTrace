
import json
import re

from pathlib import Path
from datetime import datetime, timezone


class ExperimentAnalyzer:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.experiments_dir = self.base_dir / "reports" / "experiments"
        self.output_dir = self.experiments_dir / "comparisons"

    # --------------------------------------------------
    # GENERAL HELPERS
    # --------------------------------------------------

    def validate_id(self, experiment_id):
        if not isinstance(experiment_id, str):
            raise ValueError("Invalid experiment ID.")

        if not re.fullmatch(r"EXP-[A-Z0-9-]+", experiment_id):
            raise ValueError("Invalid experiment ID.")

        return experiment_id

    def read_json(self, path):
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        with path.open("r", encoding="utf-8") as file:
            return json.load(file)

    def number(self, value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def percentage(self, value):
        if value is None:
            return None

        value = str(value).replace("%", "").strip()
        return self.number(value)

    # --------------------------------------------------
    # EXPERIMENT LOADING
    # --------------------------------------------------

    def load_experiment(self, experiment_id):
        experiment_id = self.validate_id(experiment_id)

        experiment_dir = self.experiments_dir / experiment_id

        results_path = experiment_dir / "results.json"
        manifest_path = experiment_dir / "manifest.json"

        results = self.read_json(results_path)
        manifest = {}

        if manifest_path.exists():
            manifest = self.read_json(manifest_path)

        if results.get("status") != "finalized":
            raise ValueError(
                f"Experiment {experiment_id} is not finalized."
            )

        stats_container = results.get("statistics", {})
        statistics = stats_container.get("statistics", {})

        if not statistics:
            fuzzing = manifest.get("fuzzing", {})
            statistics = fuzzing.get("final_statistics", {})

        if not statistics:
            raise ValueError(
                f"No finalized fuzzing statistics found for {experiment_id}."
            )

        return {
            "experiment_id": experiment_id,
            "results": results,
            "manifest": manifest,
            "statistics": statistics
        }

    # --------------------------------------------------
    # METRICS
    # --------------------------------------------------

    def get_metrics(self, statistics):
        return {
            "runtime_seconds": self.number(
                statistics.get("run_time")
            ),
            "total_executions": self.number(
                statistics.get("execs_done")
            ),
            "executions_per_second": self.number(
                statistics.get("execs_per_sec")
            ),
            "crashes": self.number(
                statistics.get("saved_crashes")
            ),
            "hangs": self.number(
                statistics.get("saved_hangs")
            ),
            "stability_percent": self.percentage(
                statistics.get("stability")
            ),
            "coverage_percent": self.percentage(
                statistics.get("bitmap_cvg")
            ),
            "peak_memory_mb": self.number(
                statistics.get("peak_rss_mb")
            ),
            "edges_found": self.number(
                statistics.get("edges_found")
            ),
            "total_edges": self.number(
                statistics.get("total_edges")
            )
        }

    # --------------------------------------------------
    # FINGERPRINT COLLECTION
    # --------------------------------------------------

    def get_fingerprints(self, experiment):
        results = experiment["results"]
        manifest = experiment["manifest"]

        manifest_target = manifest.get(
            "target_fingerprint", {}
        )

        results_target = results.get(
            "target_fingerprint", {}
        )

        environment = manifest.get(
            "environment", {}
        )

        manifest_corpus = manifest.get(
            "corpus", {}
        )

        results_corpus = results.get(
            "corpus", {}
        )

        return {
            "source_sha256": (
                manifest_target.get("source_sha256")
                or results_target.get("source_sha256")
            ),

            "binary_sha256": (
                manifest_target.get("binary_sha256")
                or results_target.get("binary_sha256")
            ),

            "afl_version": (
                environment.get("afl_version")
            ),

            "compiler_version": (
                environment.get("compiler_version")
            ),

            "seed_fingerprint": (
                results_corpus.get("seed_fingerprint")
                or manifest_corpus.get("seed_fingerprint")
            )
        }

    # --------------------------------------------------
    # METRIC COMPARISON
    # --------------------------------------------------

    def compare_metric(self, first, second):
        if first is None or second is None:
            return {
                "first": first,
                "second": second,
                "difference": None,
                "change_percent": None
            }

        difference = round(second - first, 4)

        change_percent = None

        if first != 0:
            change_percent = round(
                (difference / abs(first)) * 100,
                2
            )

        return {
            "first": first,
            "second": second,
            "difference": difference,
            "change_percent": change_percent
        }

    # --------------------------------------------------
    # AUTOMATED ANALYSIS
    # --------------------------------------------------

    def analyze_comparison(self, first, second):

        first_metrics = self.get_metrics(
            first["statistics"]
        )

        second_metrics = self.get_metrics(
            second["statistics"]
        )

        first_fingerprints = self.get_fingerprints(first)
        second_fingerprints = self.get_fingerprints(second)

        fingerprint_checks = {}

        for key in first_fingerprints:

            first_value = first_fingerprints[key]
            second_value = second_fingerprints[key]

            if first_value is None or second_value is None:
                match = None
            else:
                match = first_value == second_value

            fingerprint_checks[key] = {
                "match": match,
                "first": first_value,
                "second": second_value
            }

        comparable_metrics = {}

        for key in first_metrics:
            comparable_metrics[key] = self.compare_metric(
                first_metrics[key],
                second_metrics[key]
            )

        speed_change = comparable_metrics[
            "executions_per_second"
        ]["change_percent"]

        coverage_change = comparable_metrics[
            "coverage_percent"
        ]["difference"]

        crash_change = comparable_metrics[
            "crashes"
        ]["difference"]

        observations = []

        if speed_change is not None:
            if speed_change > 0:
                observations.append(
                    f"Execution speed increased by {speed_change}%."
                )
            elif speed_change < 0:
                observations.append(
                    f"Execution speed decreased by {abs(speed_change)}%."
                )
            else:
                observations.append(
                    "Execution speed remained unchanged."
                )

        if coverage_change is not None:
            if coverage_change > 0:
                observations.append(
                    f"Bitmap coverage increased by {coverage_change} percentage points."
                )
            elif coverage_change < 0:
                observations.append(
                    f"Bitmap coverage decreased by {abs(coverage_change)} percentage points."
                )
            else:
                observations.append(
                    "Bitmap coverage remained unchanged."
                )

        if crash_change is not None:
            if crash_change > 0:
                observations.append(
                    f"The second experiment found {int(crash_change)} more crash(es)."
                )
            elif crash_change < 0:
                observations.append(
                    f"The second experiment found {int(abs(crash_change))} fewer crash(es)."
                )
            else:
                observations.append(
                    "Both experiments found the same number of crashes."
                )

        matching = sum(
            1 for check in fingerprint_checks.values()
            if check["match"] is True
        )

        available = sum(
            1 for check in fingerprint_checks.values()
            if check["match"] is not None
        )

        if available == len(fingerprint_checks) and matching == available:
            interpretation = (
                "All available target and environment fingerprints match. "
                "The experiments used the same recorded source, binary, "
                "toolchain and seed corpus."
            )
        elif matching < available:
            interpretation = (
                "One or more available fingerprints differ. "
                "Review the differences before treating these experiments "
                "as directly comparable."
            )
        else:
            interpretation = (
                "Some fingerprints are unavailable. "
                "A complete reproducibility comparison cannot be confirmed."
            )

        interpretation += (
            " Performance differences are descriptive, not proof of "
            "statistical significance or improved security."
        )

        return {
            "first_experiment": first["experiment_id"],
            "second_experiment": second["experiment_id"],
            "fingerprint_checks": fingerprint_checks,
            "matching_fingerprints": matching,
            "total_fingerprints": len(fingerprint_checks),
            "available_fingerprints": available,
            "metrics": comparable_metrics,
            "observations": observations,
            "interpretation": interpretation
        }

    # --------------------------------------------------
    # MARKDOWN REPORT
    # --------------------------------------------------

    def generate_markdown(self, analysis):

        lines = [
            "# ZeroTrace Automated Experiment Analysis",
            "",
            f"Generated: {analysis['generated_at']}",
            "",
            "## Experiments",
            "",
            f"- First: `{analysis['first_experiment']}`",
            f"- Second: `{analysis['second_experiment']}`",
            "",
            "## Environment and Target Fingerprints",
            "",
            "| Fingerprint | Match |",
            "|---|---|"
        ]

        for name, check in analysis["fingerprint_checks"].items():

            if check["match"] is True:
                status = "Match"
            elif check["match"] is False:
                status = "Different"
            else:
                status = "Unavailable"

            lines.append(f"| {name} | {status} |")

        lines.extend([
            "",
            (
                f"Matching fingerprints: "
                f"{analysis['matching_fingerprints']}/"
                f"{analysis['total_fingerprints']}"
            ),
            "",
            "## Performance Comparison",
            "",
            "| Metric | First | Second | Difference | Change % |",
            "|---|---:|---:|---:|---:|"
        ])

        for name, values in analysis["metrics"].items():

            first = values["first"]
            second = values["second"]
            difference = values["difference"]
            change = values["change_percent"]

            lines.append(
                f"| {name} | {first} | {second} | "
                f"{difference} | {change} |"
            )

        lines.extend([
            "",
            "## Automated Observations",
            ""
        ])

        for observation in analysis["observations"]:
            lines.append(f"- {observation}")

        lines.extend([
            "",
            "## Interpretation",
            "",
            analysis["interpretation"],
            "",
            "This report describes collected experiment data. "
            "It does not prove that the target is vulnerability-free."
        ])

        return "\n".join(lines)

    # --------------------------------------------------
    # MAIN ENTRY POINT
    # --------------------------------------------------

    def run(self, action, first_id=None, second_id=None):

        try:
            if action != "compare":
                return {
                    "status": "failed",
                    "message": "Unsupported action."
                }

            first = self.load_experiment(first_id)
            second = self.load_experiment(second_id)

            analysis = self.analyze_comparison(
                first,
                second
            )

            self.output_dir.mkdir(
                parents=True,
                exist_ok=True
            )

            timestamp = datetime.now(
                timezone.utc
            ).strftime("%Y%m%d_%H%M%S")

            report_name = (
                f"analysis_{first_id}_{second_id}_{timestamp}"
            )

            json_path = self.output_dir / f"{report_name}.json"
            markdown_path = self.output_dir / f"{report_name}.md"

            report = {
                "project": "ZeroTrace",
                "status": "completed",
                "generated_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                **analysis
            }

            with json_path.open(
                "w",
                encoding="utf-8"
            ) as file:
                json.dump(report, file, indent=4)

            markdown = self.generate_markdown(report)

            markdown_path.write_text(
                markdown,
                encoding="utf-8"
            )

            return {
                "status": "completed",
                "first_experiment": first_id,
                "second_experiment": second_id,
                "matching_fingerprints": report[
                    "matching_fingerprints"
                ],
                "total_fingerprints": report[
                    "total_fingerprints"
                ],
                "available_fingerprints": report[
                    "available_fingerprints"
                ],
                "json_report": str(json_path),
                "markdown_report": str(markdown_path),
                "observations": report["observations"]
            }

        except Exception as error:
            return {
                "status": "failed",
                "message": str(error)
            }
