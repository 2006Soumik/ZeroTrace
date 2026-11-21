
import json
from pathlib import Path

from integrations.kali_worker import KaliWorker


class AFLStatsCollector:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.config_file = self.base_dir / "config" / "config.json"
        self.report_file = self.base_dir / "reports" / "fuzzer_stats.json"

    def run(self):

        if not self.config_file.exists():
            return {
                "status": "error",
                "message": "Configuration file not found."
            }

        with open(self.config_file, "r", encoding="utf-8") as file:
            config = json.load(file)

        kali = config.get("kali", {})
        host = kali.get("host")
        username = kali.get("username")
        stats_path = kali.get("fuzzer_stats")

        if not all([host, username, stats_path]):
            return {
                "status": "error",
                "message": "Kali connection settings are incomplete."
            }

        worker = KaliWorker(host, username)

        try:
            print("[+] Connecting to Kali Linux...")

            worker.connect()

            print("[+] Reading AFL++ statistics...")

            with worker.sftp.open(stats_path, "r") as remote_file:
                raw_stats = remote_file.read().decode("utf-8", errors="replace")

            stats = {}

            for line in raw_stats.splitlines():
                if ":" not in line:
                    continue

                key, value = line.split(":", 1)
                stats[key.strip()] = value.strip()

            if not stats:
                return {
                    "status": "error",
                    "message": "No AFL++ statistics found."
                }

            self.report_file.parent.mkdir(parents=True, exist_ok=True)

            with open(self.report_file, "w", encoding="utf-8") as file:
                json.dump(stats, file, indent=4)

            print("[+] AFL++ statistics collected.")
            print(f"[+] Report: {self.report_file}")

            return {
                "status": "completed",
                "statistics": stats,
                "report": str(self.report_file)
            }

        except Exception as error:
            return {
                "status": "error",
                "message": str(error)
            }

        finally:
            worker.close()
