
import json
from pathlib import Path
from datetime import datetime, timezone


class FuzzingPerformance:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.reports_dir = self.base_dir / "reports"

        self.stats_file = self.reports_dir / "fuzzer_stats.json"

        self.history_file = (
            self.reports_dir / "fuzzing_performance_history.json"
        )

        self.report_file = (
            self.reports_dir / "fuzzing_performance.json"
        )

        self.max_snapshots = 500

    def load_json(self, path):

        try:
            with open(path, "r", encoding="utf-8") as file:
                data = json.load(file)

                return data if isinstance(data, dict) else {}

        except (OSError, json.JSONDecodeError):
            return {}

    def save_json(self, path, data):

        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

    @staticmethod
    def to_int(value, default=0):

        try:
            return int(float(value))
        except (ValueError, TypeError):
            return default

    @staticmethod
    def to_float(value, default=0.0):

        try:
            return float(str(value).replace("%", ""))
        except (ValueError, TypeError):
            return default

    def create_snapshot(self, stats):

        captured_at = datetime.now(
            timezone.utc
        ).isoformat()

        snapshot = {
            "captured_at": captured_at,
            "start_time": self.to_int(stats.get("start_time")),
            "last_update": self.to_int(stats.get("last_update")),
            "runtime_seconds": self.to_int(stats.get("run_time")),
            "executions": self.to_int(stats.get("execs_done")),
            "executions_per_second": self.to_float(
                stats.get("execs_per_sec")
            ),
            "executions_last_minute": self.to_float(
                stats.get("execs_ps_last_min")
            ),
            "corpus_count": self.to_int(stats.get("corpus_count")),
            "corpus_favored": self.to_int(
                stats.get("corpus_favored")
            ),
            "corpus_found": self.to_int(stats.get("corpus_found")),
            "corpus_imported": self.to_int(
                stats.get("corpus_imported")
            ),
            "cycles_completed": self.to_int(stats.get("cycles_done")),
            "cycles_without_finds": self.to_int(
                stats.get("cycles_wo_finds")
            ),
            "max_depth": self.to_int(stats.get("max_depth")),
            "saved_crashes": self.to_int(
                stats.get("saved_crashes")
            ),
            "saved_hangs": self.to_int(
                stats.get("saved_hangs")
            ),
            "stability_percent": self.to_float(
                stats.get("stability")
            ),
            "bitmap_coverage_percent": self.to_float(
                stats.get("bitmap_cvg")
            ),
            "edges_found": self.to_int(stats.get("edges_found")),
            "total_edges": self.to_int(stats.get("total_edges")),
            "peak_memory_mb": self.to_int(
                stats.get("peak_rss_mb")
            ),
            "slowest_execution_ms": self.to_int(
                stats.get("slowest_exec_ms")
            )
        }

        return snapshot

    def calculate_performance(self, current, previous):

        if not previous:
            return {
                "baseline_available": False,
                "session_reset": False,
                "execution_growth": 0,
                "corpus_growth": 0,
                "crash_growth": 0,
                "hang_growth": 0,
                "runtime_growth_seconds": 0
            }

        # AFL++ start_time identifies the fuzzing session.
        session_reset = (
            current["start_time"] != previous["start_time"]
        )

        if session_reset:
            return {
                "baseline_available": False,
                "session_reset": True,
                "execution_growth": 0,
                "corpus_growth": 0,
                "crash_growth": 0,
                "hang_growth": 0,
                "runtime_growth_seconds": 0
            }

        return {
            "baseline_available": True,
            "session_reset": False,

            "execution_growth": max(
                0,
                current["executions"] - previous["executions"]
            ),

            "corpus_growth": max(
                0,
                current["corpus_count"] - previous["corpus_count"]
            ),

            "crash_growth": max(
                0,
                current["saved_crashes"] - previous["saved_crashes"]
            ),

            "hang_growth": max(
                0,
                current["saved_hangs"] - previous["saved_hangs"]
            ),

            "runtime_growth_seconds": max(
                0,
                current["runtime_seconds"] - previous["runtime_seconds"]
            )
        }

    def run(self):

        print("[+] Starting Fuzzing Performance Analyzer...")

        if not self.stats_file.exists():
            return {
                "status": "error",
                "message": "fuzzer_stats.json not found. Run the AFL++ statistics collector first."
            }

        stats = self.load_json(self.stats_file)

        if not stats:
            return {
                "status": "error",
                "message": "AFL++ statistics file is empty or invalid."
            }

        current = self.create_snapshot(stats)

        if not current["start_time"]:
            return {
                "status": "error",
                "message": "Missing AFL++ start_time. Cannot identify the fuzzing session."
            }

        history_data = self.load_json(self.history_file)

        snapshots = history_data.get("snapshots", [])

        if not isinstance(snapshots, list):
            snapshots = []

        previous = snapshots[-1] if snapshots else None

        # Avoid recording identical statistics repeatedly.
        if previous:
            comparable_fields = [
                "start_time",
                "last_update",
                "executions",
                "corpus_count",
                "saved_crashes",
                "saved_hangs",
                "runtime_seconds"
            ]

            unchanged = all(
                current[field] == previous.get(field)
                for field in comparable_fields
            )

            if unchanged:
                print("[+] Statistics unchanged. No duplicate snapshot added.")

                return {
                    "status": "unchanged",
                    "message": "No new AFL++ statistics to record.",
                    "snapshots": len(snapshots),
                    "latest": previous
                }

        performance = self.calculate_performance(
            current,
            previous
        )

        snapshots.append(current)

        snapshots = snapshots[-self.max_snapshots:]

        self.save_json(
            self.history_file,
            {
                "tool": "ZeroTrace",
                "module": "Fuzzing Performance Analyzer",
                "updated_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                "total_snapshots": len(snapshots),
                "snapshots": snapshots
            }
        )

        report = {
            "tool": "ZeroTrace",
            "module": "Fuzzing Performance Analyzer",
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "status": "completed",

            "current_performance": current,

            "performance_changes": performance,

            "history": {
                "total_snapshots": len(snapshots),
                "maximum_snapshots": self.max_snapshots,
                "first_snapshot": snapshots[0]["captured_at"],
                "latest_snapshot": snapshots[-1]["captured_at"]
            },

            "limitations": [
                "Performance trends depend on the frequency of snapshots.",
                "Snapshots are recorded only when AFL++ statistics change.",
                "AFL++ counters are interpreted from the available fuzzer_stats fields.",
                "Historical data is limited to the latest 500 snapshots.",
                "Performance changes do not independently establish fuzzing effectiveness."
            ]
        }

        self.save_json(self.report_file, report)

        print("[+] Fuzzing Performance Analysis completed.")
        print(f"[+] Total snapshots: {len(snapshots)}")
        print(f"[+] Executions: {current['executions']}")
        print(f"[+] Execution speed: {current['executions_per_second']}")
        print(f"[+] Corpus count: {current['corpus_count']}")
        print(f"[+] Saved crashes: {current['saved_crashes']}")
        print(f"[+] Report: {self.report_file}")

        return {
            "status": "completed",
            "report": str(self.report_file),
            "history": str(self.history_file),
            "performance_changes": performance
        }
