
import time

from integrations.kali_worker import KaliWorker
from modules.live_stats_collector import LiveStatsCollector
from modules.fuzzing_performance import FuzzingPerformance


class LiveMonitor:

    def __init__(self, interval=60):
        self.interval = interval
        self.collector = LiveStatsCollector()
        self.analyzer = FuzzingPerformance()
        self.worker = None

    def connect(self):
        host, username = self.collector.load_config()

        self.worker = KaliWorker(host, username)

        return self.worker.connect()

    def collect_once(self):
        username = self.worker.username

        remote_path = self.collector.remote_stats.format(
            username=username
        )

        with self.worker.sftp.open(remote_path, "r") as remote_file:
            raw_data = remote_file.read()

        if isinstance(raw_data, bytes):
            raw_data = raw_data.decode("utf-8", errors="replace")

        stats = self.collector.parse_stats(raw_data)

        self.collector.update_local_report(stats)

        result = self.analyzer.run()

        print("\n--- ZeroTrace Live Monitoring ---")
        print(f"Executions: {stats.get('execs_done', 'N/A')}")
        print(f"Speed: {stats.get('execs_per_sec', 'N/A')} exec/sec")
        print(f"Corpus: {stats.get('corpus_count', 'N/A')}")
        print(f"Crashes: {stats.get('saved_crashes', 'N/A')}")
        print(f"Coverage: {stats.get('bitmap_cvg', 'N/A')}")
        print(f"Performance status: {result.get('status', 'unknown')}")

    def run(self):
        print("[+] ZeroTrace Live Monitor")
        print(f"[+] Collection interval: {self.interval} seconds")

        try:
            if not self.connect():
                print("[-] Could not connect to Kali")
                return

            print("[+] Persistent SSH connection established")

            while True:
                try:
                    self.collect_once()

                except Exception as error:
                    print(f"[-] Monitoring cycle failed: {error}")

                print(
                    f"\n[+] Next collection in {self.interval} seconds"
                )

                time.sleep(self.interval)

        except KeyboardInterrupt:
            print("\n[+] Monitoring stopped by user")

        finally:
            if self.worker:
                self.worker.close()


if __name__ == "__main__":
    monitor = LiveMonitor(interval=60)
    monitor.run()
