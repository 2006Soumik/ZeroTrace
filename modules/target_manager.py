from pathlib import Path


class TargetManager:

    def __init__(self):
        self.target = None

    def run(self, target_path=None):

        if not target_path:
            return {
                "status": "error",
                "message": "No target file provided"
            }

        target = Path(target_path).expanduser()

        if not target.exists():
            return {
                "status": "error",
                "message": "Target file does not exist"
            }

        if not target.is_file():
            return {
                "status": "error",
                "message": "Target must be a file"
            }

        self.target = target.resolve()

        return {
            "status": "success",
            "target": str(self.target),
            "size_bytes": self.target.stat().st_size,
            "message": "Target validated successfully"
        }
