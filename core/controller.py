from pathlib import Path
from datetime import datetime
import logging


class ZeroTraceController:

    def __init__(self):
        self.name = "ZeroTrace"
        self.version = "0.1.0"

        self.modules = {}
        self.results = {}

        self.setup_logging()

    def setup_logging(self):
        Path("logs").mkdir(exist_ok=True)

        logging.basicConfig(
            filename="logs/zerotrace.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

    # Register a module
    def register_module(self, module_name, module):
        self.modules[module_name] = module

        logging.info(
            f"Module registered: {module_name}"
        )

    # Run a particular module
    def run_module(self, module_name, **kwargs):

        if module_name not in self.modules:
            return {
                "status": "error",
                "message": f"Module not found: {module_name}"
            }

        try:
            module = self.modules[module_name]

            logging.info(
                f"Starting module: {module_name}"
            )

            result = module.run(**kwargs)

            self.results[module_name] = result

            return {
                "status": "success",
                "module": module_name,
                "result": result
            }

        except Exception as error:
            logging.exception(
                f"Module failed: {module_name}"
            )

            return {
                "status": "error",
                "module": module_name,
                "message": str(error)
            }

    # Display available modules
    def list_modules(self):
        return list(self.modules.keys())

    # Display collected results
    def get_results(self):
        return self.results

    # Display software information
    def information(self):
        return {
            "name": self.name,
            "version": self.version,
            "modules": self.list_modules(),
            "time": datetime.now().isoformat()
        }
