import paramiko
import getpass
import os
import posixpath


class KaliWorker:

    def __init__(self, host, username):
        self.host = host
        self.username = username
        self.client = None
        self.sftp = None
        self.remote_workspace = (
            f"/home/{username}/zerotrace_worker"
        )

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(
                paramiko.RejectPolicy()
            )

            password = getpass.getpass(
                "Enter Kali SSH password: "
            )

            self.client.connect(
                hostname=self.host,
                username=self.username,
                password=password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )

            self.sftp = self.client.open_sftp()

            print("[+] Connected to Kali Linux")
            return True

        except Exception as error:
            print(f"[-] Connection failed: {error}")
            self.close()
            return False

    def prepare_workspace(self):
        try:
            self.sftp.stat(self.remote_workspace)
        except FileNotFoundError:
            self.sftp.mkdir(self.remote_workspace)

        print("[+] ZeroTrace workspace ready")
        return self.remote_workspace

    def upload_file(self, local_path):
        if not os.path.isfile(local_path):
            print("[-] Local file does not exist")
            return False

        filename = os.path.basename(local_path)
        remote_path = posixpath.join(
            self.remote_workspace, filename
        )

        self.sftp.put(local_path, remote_path)

        print(f"[+] Uploaded: {filename}")
        return remote_path

    def download_file(self, remote_path, local_path):
        self.sftp.get(remote_path, local_path)
        print(f"[+] Downloaded: {local_path}")

    def execute_command(self, command):
        if self.client is None:
            raise RuntimeError("Connect to Kali first.")

        stdin, stdout, stderr = self.client.exec_command(
            command,
            timeout=30
        )

        output = stdout.read().decode(errors="replace")
        error = stderr.read().decode(errors="replace")
        exit_code = stdout.channel.recv_exit_status()

        return {
            "exit_code": exit_code,
            "output": output,
            "error": error
        }

    def check_afl(self):
        result = self.execute_command(
            "afl-fuzz --version && command -v afl-fuzz"
        )

        print("\n--- AFL++ Check ---")
        print(result["output"])

        if result["error"]:
            print(result["error"])

        return result

    def list_workspace(self):
        print("\n--- Kali Workspace Files ---")

        for filename in self.sftp.listdir(
            self.remote_workspace
        ):
            print(filename)

    def close(self):
        if self.sftp:
            self.sftp.close()
            self.sftp = None

        if self.client:
            self.client.close()
            self.client = None

        print("[+] Connection closed")


if __name__ == "__main__":

    host = input("Enter Kali IP: ").strip()
    username = input("Enter Kali username: ").strip()

    worker = KaliWorker(host, username)

    try:
        if worker.connect():
            worker.prepare_workspace()
            worker.check_afl()
            worker.list_workspace()

    finally:
        worker.close()
