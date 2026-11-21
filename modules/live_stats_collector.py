
import json
from pathlib import Path
from datetime import datetime, timezone

from integrations.kali_worker import KaliWorker
from modules.fuzzing_performance import FuzzingPerformance


class LiveStatsCollector:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent

        self.config_file = self.base_dir / "config" / "config.json"
        self.reports_dir = self.base_dir / "reports"
        self.output_file = self.reports_dir / "fuzzer_stats.json"

        self.remote_stats = (
            "/home/{username}/zerotrace_worker/"
            "lab/findings/default/fuzzer_stats"
        )

    def load_config(self):
        with open(self.config_file, "r", encoding="utf-8") as file:
            config = json.load(file)

        kali = config.get("kali", {})

        host = kali.get("host")
        username = kali.get("username")

        if not host or not username:
            raise ValueError("Kali host or username missing in config.json")

        return host, username

    def parse_stats(self, raw_data):
        stats = {}

        for line in raw_data.splitlines():
            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()

            if key:
                stats[key] = value

        required = ["start_time", "last_update", "execs_done"]
        missing = [key for key in required if key not in stats]

        if missing:
            raise ValueError(f"Missing AFL++ fields: {missing}")

        return stats

    def update_local_report(self, stats):
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        stats["zerotrace_collected_at"] = (
            datetime.now(timezone.utc).isoformat()
        )

        temporary_file = self.output_file.with_suffix(".tmp")

        with open(temporary_file, "w", encoding="utf-8") as file:
            json.dump(stats, file, indent=4)

        temporary_file.replace(self.output_file)

        print("[+] Local AFL++ statistics updated")

    def run_performance_analysis(self):
        print("\n[+] Starting performance analysis...")

        analyzer = FuzzingPerformance()
        result = analyzer.run()

        print(f"[+] Performance analyzer status: {result['status']}")

        if result["status"] == "completed":
            print("[+] Performance history updated")
        elif result["status"] == "unchanged":
            print("[+] No new performance snapshot required")
        else:
            print(f"[-] Performance analysis: {result.get('message')}")

        return result

    def collect(self):
        worker = None

        try:
            host, username = self.load_config()

            remote_path = self.remote_stats.format(
                username=username
            )

            print("\n[+] Connecting to Kali Linux...")

            worker = KaliWorker(host, username)

            if not worker.connect():
                return False

            print("[+] Reading remote AFL++ statistics...")

            with worker.sftp.open(remote_path, "r") as remote_file:
                raw_data = remote_file.read()

            if isinstance(raw_data, bytes):
                raw_data = raw_data.decode("utf-8", errors="replace")

            stats = self.parse_stats(raw_data)

            self.update_local_report(stats)

            print("\n--- Live AFL++ Statistics ---")
            print(f"Executions: {stats.get('execs_done', 'N/A')}")
            print(f"Speed: {stats.get('execs_per_sec', 'N/A')} exec/sec")
            print(f"Corpus: {stats.get('corpus_count', 'N/A')}")
            print(f"Crashes: {stats.get('saved_crashes', 'N/A')}")
            print(f"Hangs: {stats.get('saved_hangs', 'N/A')}")
            print(f"Coverage: {stats.get('bitmap_cvg', 'N/A')}")

        except Exception as error:
            print(f"\n[-] Collection failed: {error}")
            return False

        finally:
            if worker:
                worker.close()

        # Analyze only after fresh statistics have been saved.
        try:
            performance_result = self.run_performance_analysis()

            return performance_result["status"] in (
                "completed",
                "unchanged"
            )

        except Exception as error:
            print(f"[-] Performance analysis failed: {error}")
            return False


if __name__ == "__main__":
    collector = LiveStatsCollector()
    collector.collect()
