from core.controller import ZeroTraceController

from modules.target_manager import TargetManager
from modules.fuzzing_manager import FuzzingManager
from modules.crash_collector import CrashCollector
from modules.crash_analyzer import CrashAnalyzer

from modules.vulnerability_classifier import VulnerabilityClassifier
from modules.crash_prioritizer import CrashPrioritizer
from modules.root_cause_analyzer import RootCauseAnalyzer
from modules.exploitability_assessor import ExploitabilityAssessor
from modules.evidence_correlator import EvidenceCorrelator
from modules.vulnerability_correlator import VulnerabilityCorrelator
from modules.research_report_generator import ResearchReportGenerator

from modules.static_analyzer import StaticAnalyzer
from modules.dataflow_analyzer import DataFlowAnalyzer

from modules.automated_patch_verifier import AutomatedPatchVerifier
from modules.cvss_assessor import CVSSAssessor

from modules.report_generator import ReportGenerator

from modules.corpus_manager import CorpusManager
from modules.corpus_intelligence import CorpusIntelligence

from modules.experiment_manager import ExperimentManager
from modules.experiment_analyzer import ExperimentAnalyzer
from modules.experiment_integrity_verifier import ExperimentIntegrityVerifier
from modules.remote_integrity_verifier import RemoteIntegrityVerifier

from modules.workflow_manager import WorkflowManager


# ==================================================
# INPUT HELPERS
# ==================================================

def get_kali_details():
    print("\n--- Kali Linux Connection ---")

    host = input("Enter Kali IP address: ").strip()
    username = input("Enter Kali username: ").strip()

    return host, username


def get_experiment_id():
    return input("\nEnter experiment ID: ").strip()


def print_section(title, result):
    print(f"\n========== {title} ==========")
    print(result)
    print("=" * (len(title) + 22))


# ==================================================
# MAIN APPLICATION
# ==================================================

def main():

    app = ZeroTraceController()

    # ==================================================
    # CREATE SHARED MODULE INSTANCES
    # ==================================================

    target_manager = TargetManager()
    fuzzing_manager = FuzzingManager()
    crash_collector = CrashCollector()
    crash_analyzer = CrashAnalyzer()

    vulnerability_classifier = VulnerabilityClassifier()
    crash_prioritizer = CrashPrioritizer()
    root_cause_analyzer = RootCauseAnalyzer()
    exploitability_assessor = ExploitabilityAssessor()
    evidence_correlator = EvidenceCorrelator()
    vulnerability_correlator = VulnerabilityCorrelator()
    research_report_generator = ResearchReportGenerator()

    static_analyzer = StaticAnalyzer()
    dataflow_analyzer = DataFlowAnalyzer()

    experiment_manager = ExperimentManager()

    # ==================================================
    # REGISTER CORE MODULES
    # ==================================================

    app.register_module("Target Manager", target_manager)
    app.register_module("Fuzzing Manager", fuzzing_manager)
    app.register_module("Crash Collector", crash_collector)
    app.register_module("Crash Analyzer", crash_analyzer)

    # ==================================================
    # REGISTER VULNERABILITY ANALYSIS MODULES
    # ==================================================

    app.register_module(
        "Vulnerability Classifier",
        vulnerability_classifier
    )

    app.register_module(
        "Crash Prioritizer",
        crash_prioritizer
    )

    app.register_module(
        "Root Cause Analyzer",
        root_cause_analyzer
    )

    app.register_module(
        "Exploitability Assessor",
        exploitability_assessor
    )

    app.register_module(
        "Evidence Correlator",
        evidence_correlator
    )

    app.register_module(
        "Vulnerability Correlator",
        vulnerability_correlator
    )

    app.register_module(
        "Research Report Generator",
        research_report_generator
    )

    # ==================================================
    # REGISTER STATIC AND DATAFLOW ANALYSIS
    # ==================================================

    app.register_module(
        "Static Analyzer",
        static_analyzer
    )

    app.register_module(
        "Data Flow Analyzer",
        dataflow_analyzer
    )

    # ==================================================
    # AUTOMATED SECURITY MODULES
    # ==================================================

    app.register_module(
        "Automated Patch Verifier",
        AutomatedPatchVerifier()
    )

    app.register_module(
        "CVSS Assessor",
        CVSSAssessor()
    )

    # ==================================================
    # CORPUS INTELLIGENCE
    # ==================================================

    app.register_module(
        "Corpus Manager",
        CorpusManager()
    )

    app.register_module(
        "Corpus Intelligence",
        CorpusIntelligence()
    )

    # ==================================================
    # REPRODUCIBLE RESEARCH
    # ==================================================

    app.register_module(
        "Experiment Manager",
        experiment_manager
    )

    app.register_module(
        "Experiment Analyzer",
        ExperimentAnalyzer()
    )

    app.register_module(
        "Experiment Integrity Verifier",
        ExperimentIntegrityVerifier()
    )

    app.register_module(
        "Remote Integrity Verifier",
        RemoteIntegrityVerifier()
    )

    # ==================================================
    # AUTOMATED WORKFLOW - SHARED MODULE CONNECTIONS
    # ==================================================

    workflow_manager = WorkflowManager(
        target_manager=target_manager,
        experiment_manager=experiment_manager,
        fuzzing_manager=fuzzing_manager,
        crash_collector=crash_collector,
        crash_analyzer=crash_analyzer,
        static_analyzer=static_analyzer,
        dataflow_analyzer=dataflow_analyzer,
        vulnerability_classifier=vulnerability_classifier,
        crash_prioritizer=crash_prioritizer,
        root_cause_analyzer=root_cause_analyzer,
        exploitability_assessor=exploitability_assessor,
        evidence_correlator=evidence_correlator,
        vulnerability_correlator=vulnerability_correlator,
        research_report_generator=research_report_generator
    )

    app.register_module(
        "Workflow Manager",
        workflow_manager
    )

    report_generator = ReportGenerator()

    # ==================================================
    # MAIN MENU
    # ==================================================

    while True:

        print("\n========== ZeroTrace ==========")

        print("\n--- CORE OPERATIONS ---")
        print("1.  Software Information")
        print("2.  List Modules")
        print("3.  Validate Target")
        print("4.  Start Fuzzing (Legacy)")
        print("5.  Check Fuzzing Status (Legacy)")
        print("6.  Stop Fuzzing (Legacy)")
        print("7.  Collect Crashes")
        print("8.  Analyze Crash")
        print("9.  Generate HTML Security Report")
        print("10. Classify Vulnerability")
        print("11. Prioritize Crash")
        print("12. Analyze Root Cause")
        print("13. Assess Exploitability")
        print("14. Correlate Evidence")
        print("15. Unified Vulnerability Correlation")
        print("16. Generate Research Report")
        print("17. View Results")
        print("18. Exit")

        print("\n--- SECURITY ASSESSMENT ---")
        print("19. Automated Patch Verification")
        print("20. CVSS 3.1 Vulnerability Assessment")

        print("\n--- CORPUS INTELLIGENCE ---")
        print("21. Corpus Manager")
        print("22. Corpus Intelligence")

        print("\n--- REPRODUCIBLE RESEARCH ---")
        print("23. Create Experiment")
        print("24. Finalize Experiment")
        print("25. List Experiments")
        print("26. Compare Experiments")

        print("\n--- EXPERIMENT-ISOLATED FUZZING ---")
        print("27. Start Experiment Fuzzing")
        print("28. Check Experiment Fuzzing Status")
        print("29. Stop Experiment Fuzzing")

        print("\n--- AUTOMATED EXPERIMENT ANALYSIS ---")
        print("30. Analyze and Compare Experiments")

        print("\n--- EXPERIMENT INTEGRITY ---")
        print("31. Verify Experiment Integrity")
        print("32. Verify Remote Environment Integrity")

        print("\n--- AUTOMATED RESEARCH ---")
        print("33. Run Automated Research Workflow")

        choice = input("\nChoose an option: ").strip()

        # ==================================================
        # CORE OPERATIONS
        # ==================================================

        if choice == "1":
            print(app.information())

        elif choice == "2":
            print(app.list_modules())

        elif choice == "3":

            target_path = input(
                "\nEnter target file path: "
            ).strip()

            result = app.run_module(
                "Target Manager",
                target_path=target_path
            )

            print(result)

        elif choice in ("4", "5", "6"):

            host, username = get_kali_details()

            actions = {
                "4": "start",
                "5": "status",
                "6": "stop"
            }

            result = app.run_module(
                "Fuzzing Manager",
                action=actions[choice],
                host=host,
                username=username
            )

            print(result)

        elif choice == "7":

            host, username = get_kali_details()

            result = app.run_module(
                "Crash Collector",
                host=host,
                username=username
            )

            print(result)

        elif choice == "8":

            host, username = get_kali_details()

            crash_path = input(
                "\nEnter crash file path "
                "(press Enter for automatic selection): "
            ).strip()

            result = app.run_module(
                "Crash Analyzer",
                host=host,
                username=username,
                crash_path=crash_path if crash_path else None
            )

            print(result)

        elif choice == "9":

            result = report_generator.generate()

            print(result)

            if (
                isinstance(result, dict)
                and result.get("status") == "success"
            ):
                print("\nOpen the HTML report using:")
                print(
                    "Start-Process .\\reports\\zerotrace_report.html"
                )

        elif choice == "10":
            print(app.run_module("Vulnerability Classifier"))

        elif choice == "11":
            print(app.run_module("Crash Prioritizer"))

        elif choice == "12":
            print(app.run_module("Root Cause Analyzer"))

        elif choice == "13":
            print(app.run_module("Exploitability Assessor"))

        elif choice == "14":
            print(app.run_module("Evidence Correlator"))

        elif choice == "15":
            print(app.run_module("Vulnerability Correlator"))

        elif choice == "16":
            print(app.run_module("Research Report Generator"))

        elif choice == "17":
            print(app.get_results())

        elif choice == "18":
            print("Exiting ZeroTrace...")
            break
        # ==================================================
        # AUTOMATED SECURITY ASSESSMENT
        # ==================================================

        elif choice == "19":

            patched_path = input(
                "\nEnter patched source file path: "
            ).strip()

            host, username = get_kali_details()

            fuzz_seconds_input = input(
                "Enter fuzzing duration in seconds (default 60): "
            ).strip()

            try:
                fuzz_seconds = (
                    int(fuzz_seconds_input)
                    if fuzz_seconds_input else 60
                )

                result = app.run_module(
                    "Automated Patch Verifier",
                    patched_path=patched_path,
                    host=host,
                    username=username,
                    fuzz_seconds=fuzz_seconds
                )

                print(result)

            except ValueError:
                print("[!] Enter a valid fuzzing duration.")

        elif choice == "20":

            print(
                app.run_module("CVSS Assessor")
            )

        # ==================================================
        # CORPUS INTELLIGENCE
        # ==================================================

        elif choice == "21":

            host, username = get_kali_details()

            result = app.run_module(
                "Corpus Manager",
                host=host,
                username=username
            )

            print(result)

        elif choice == "22":

            result = app.run_module(
                "Corpus Intelligence"
            )

            print(result)

        # ==================================================
        # EXPERIMENT MANAGEMENT
        # ==================================================

        elif choice == "23":

            host, username = get_kali_details()

            result = app.run_module(
                "Experiment Manager",
                action="create",
                host=host,
                username=username
            )

            print_section(
                "EXPERIMENT CREATED",
                result
            )

        elif choice == "24":

            experiment_id = get_experiment_id()

            host, username = get_kali_details()

            result = app.run_module(
                "Experiment Manager",
                action="finalize",
                experiment_id=experiment_id,
                host=host,
                username=username
            )

            print_section(
                "EXPERIMENT FINALIZATION",
                result
            )

        elif choice == "25":

            result = app.run_module(
                "Experiment Manager",
                action="list"
            )

            print_section(
                "EXPERIMENT HISTORY",
                result
            )

        elif choice == "26":

            first_id = input(
                "\nEnter first experiment ID: "
            ).strip()

            second_id = input(
                "Enter second experiment ID: "
            ).strip()

            result = app.run_module(
                "Experiment Manager",
                action="compare",
                experiment_id=first_id,
                second_id=second_id
            )

            print_section(
                "EXPERIMENT COMPARISON",
                result
            )

        # ==================================================
        # EXPERIMENT-ISOLATED FUZZING
        # ==================================================

        elif choice in ("27", "28", "29"):

            experiment_id = get_experiment_id()

            host, username = get_kali_details()

            actions = {
                "27": "start_experiment",
                "28": "status_experiment",
                "29": "stop_experiment"
            }

            result = app.run_module(
                "Fuzzing Manager",
                action=actions[choice],
                host=host,
                username=username,
                experiment_id=experiment_id
            )

            titles = {
                "27": "EXPERIMENT FUZZING START",
                "28": "EXPERIMENT FUZZING STATUS",
                "29": "EXPERIMENT FUZZING STOP"
            }

            print_section(
                titles[choice],
                result
            )

        # ==================================================
        # AUTOMATED EXPERIMENT ANALYSIS
        # ==================================================

        elif choice == "30":

            first_id = input(
                "\nEnter first experiment ID: "
            ).strip()

            second_id = input(
                "Enter second experiment ID: "
            ).strip()

            result = app.run_module(
                "Experiment Analyzer",
                action="compare",
                first_id=first_id,
                second_id=second_id
            )

            print_section(
                "AUTOMATED EXPERIMENT ANALYSIS",
                result
            )

        # ==================================================
        # LOCAL EXPERIMENT INTEGRITY
        # ==================================================

        elif choice == "31":

            experiment_id = get_experiment_id()

            result = app.run_module(
                "Experiment Integrity Verifier",
                experiment_id=experiment_id
            )

            print_section(
                "EXPERIMENT INTEGRITY VERIFICATION",
                result
            )

        # ==================================================
        # REMOTE ENVIRONMENT INTEGRITY
        # ==================================================

        elif choice == "32":

            experiment_id = get_experiment_id()

            host, username = get_kali_details()

            result = app.run_module(
                "Remote Integrity Verifier",
                experiment_id=experiment_id,
                host=host,
                username=username
            )

            print_section(
                "REMOTE ENVIRONMENT INTEGRITY VERIFICATION",
                result
            )

        # ==================================================
        # AUTOMATED END-TO-END RESEARCH WORKFLOW
        # ==================================================

        elif choice == "33":

            host, username = get_kali_details()

            target_path = input(
                "\nEnter local target source path "
                "(default target.c): "
            ).strip()

            if not target_path:
                target_path = "target.c"

            duration_input = input(
                "Enter fuzzing duration in seconds "
                "(default 60, max 3600): "
            ).strip()

            try:
                duration = (
                    int(duration_input)
                    if duration_input else 60
                )

                if not 1 <= duration <= 3600:
                    raise ValueError

            except ValueError:
                print(
                    "[!] Enter a whole-number duration "
                    "between 1 and 3600 seconds."
                )
                continue

            result = app.run_module(
                "Workflow Manager",
                host=host,
                username=username,
                target_path=target_path,
                duration=duration
            )

            print_section(
                "AUTOMATED RESEARCH WORKFLOW",
                result
            )

        else:
            print("[!] Invalid option. Try again.")


# ==================================================
# APPLICATION ENTRY POINT
# ==================================================

if __name__ == "__main__":
    main()