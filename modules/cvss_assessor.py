
import json
import math
from pathlib import Path
from datetime import datetime


class CVSSAssessor:

    def __init__(self):
        self.root = Path(__file__).resolve().parent.parent
        self.reports = self.root / "reports"
        self.crashes = self.reports / "crashes"

        self.input_file = (
            self.reports / "unified_vulnerability_report.json"
        )

        self.output_file = (
            self.crashes / "cvss_assessment.json"
        )

        self.metrics = {
            "AV": {
                "N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20
            },
            "AC": {
                "L": 0.77, "H": 0.44
            },
            "UI": {
                "N": 0.85, "R": 0.62
            },
            "C": {
                "H": 0.56, "L": 0.22, "N": 0.0
            },
            "I": {
                "H": 0.56, "L": 0.22, "N": 0.0
            },
            "A": {
                "H": 0.56, "L": 0.22, "N": 0.0
            }
        }

    def load_report(self):
        try:
            with self.input_file.open("r", encoding="utf-8") as file:
                return json.load(file)
        except (OSError, json.JSONDecodeError):
            return {}

    def ask_metric(self, name, description, choices):
        print(f"\n{name} - {description}")
        print("Options:", ", ".join(choices))

        while True:
            value = input(f"Enter {name}: ").strip().upper()

            if value in choices:
                return value

            print("[!] Invalid value. Try again.")

    def collect_metrics(self):
        print("\n========== CVSS 3.1 Assessment ==========")
        print("Enter values based on the vulnerability's actual behavior.")

        metrics = {}

        metrics["AV"] = self.ask_metric(
            "AV", "Attack Vector", ["N", "A", "L", "P"]
        )

        metrics["AC"] = self.ask_metric(
            "AC", "Attack Complexity", ["L", "H"]
        )

        metrics["PR"] = self.ask_metric(
            "PR", "Privileges Required", ["N", "L", "H"]
        )

        metrics["UI"] = self.ask_metric(
            "UI", "User Interaction", ["N", "R"]
        )

        metrics["S"] = self.ask_metric(
            "S", "Scope", ["U", "C"]
        )

        metrics["C"] = self.ask_metric(
            "C", "Confidentiality Impact", ["H", "L", "N"]
        )

        metrics["I"] = self.ask_metric(
            "I", "Integrity Impact", ["H", "L", "N"]
        )

        metrics["A"] = self.ask_metric(
            "A", "Availability Impact", ["H", "L", "N"]
        )

        return metrics

    def roundup(self, value):
        return math.ceil(value * 10 - 1e-10) / 10

    def calculate_score(self, metrics):

        av = self.metrics["AV"][metrics["AV"]]
        ac = self.metrics["AC"][metrics["AC"]]
        ui = self.metrics["UI"][metrics["UI"]]

        scope_changed = metrics["S"] == "C"

        pr_values = {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.50}
        }

        pr = pr_values[metrics["S"]][metrics["PR"]]

        confidentiality = self.metrics["C"][metrics["C"]]
        integrity = self.metrics["I"][metrics["I"]]
        availability = self.metrics["A"][metrics["A"]]

        iss = 1 - (
            (1 - confidentiality)
            * (1 - integrity)
            * (1 - availability)
        )

        if scope_changed:
            impact = (
                7.52 * (iss - 0.029)
                - 3.25 * ((iss - 0.02) ** 15)
            )
        else:
            impact = 6.42 * iss

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            score = 0.0
        elif scope_changed:
            score = self.roundup(
                min(1.08 * (impact + exploitability), 10)
            )
        else:
            score = self.roundup(
                min(impact + exploitability, 10)
            )

        if score == 0:
            severity = "None"
        elif score < 4.0:
            severity = "Low"
        elif score < 7.0:
            severity = "Medium"
        elif score < 9.0:
            severity = "High"
        else:
            severity = "Critical"

        vector = (
            f"CVSS:3.1/AV:{metrics['AV']}"
            f"/AC:{metrics['AC']}"
            f"/PR:{metrics['PR']}"
            f"/UI:{metrics['UI']}"
            f"/S:{metrics['S']}"
            f"/C:{metrics['C']}"
            f"/I:{metrics['I']}"
            f"/A:{metrics['A']}"
        )

        return {
            "cvss_version": "3.1",
            "base_score": score,
            "severity": severity,
            "vector": vector,
            "impact_sub_score": round(impact, 4),
            "exploitability_sub_score": round(exploitability, 4),
            "metrics": metrics
        }

    def identify_cwe(self, report):
        for finding in report.get("correlated_findings", []):
            for evidence in finding.get("evidence", []):
                cwe = evidence.get("cwe")

                if isinstance(cwe, str) and cwe.startswith("CWE-"):
                    return cwe

        return "CWE-120"

    def run(self):

        report = self.load_report()

        if not report:
            print("[!] Unified vulnerability report not found.")
            print("[!] Run Vulnerability Correlator first.")
            return {"status": "error"}

        findings = report.get("correlated_findings", [])

        if not findings:
            print("[!] No correlated vulnerability findings found.")
            return {"status": "error"}

        print("\n[+] Unified vulnerability report loaded.")
        print(f"[+] Findings available: {len(findings)}")

        metrics = self.collect_metrics()
        assessment = self.calculate_score(metrics)

        result = {
            "tool": "ZeroTrace",
            "module": "CVSS Assessor",
            "generated_at": datetime.now().isoformat(),
            "vulnerability_count": len(findings),
            "cwe": self.identify_cwe(report),
            "assessment": assessment,
            "source_findings": findings,
            "limitations": [
                "CVSS metrics are analyst-supplied.",
                "The score depends on the accuracy of selected metrics.",
                "A crash alone does not prove confidentiality or integrity impact.",
                "This module calculates CVSS 3.1 Base Score only.",
                "The score does not establish real-world exploitability."
            ]
        }

        self.crashes.mkdir(parents=True, exist_ok=True)

        with self.output_file.open("w", encoding="utf-8") as file:
            json.dump(result, file, indent=4)

        print("\n[+] CVSS assessment completed.")
        print(f"[+] CWE: {result['cwe']}")
        print(f"[+] CVSS Score: {assessment['base_score']}")
        print(f"[+] Severity: {assessment['severity']}")
        print(f"[+] Vector: {assessment['vector']}")
        print(f"[+] Report: {self.output_file}")

        return result
