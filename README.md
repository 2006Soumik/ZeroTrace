# ZeroTrace

**Automated C/C++ Vulnerability Research and Fuzzing Framework**

ZeroTrace is a Python-based security research framework that integrates with a Kali Linux worker to run AFL++ fuzzing experiments on native C/C++ targets. It collects and analyzes crash evidence and provides a local web dashboard for monitoring research results.

## Features

- Target validation
- Remote Kali Linux integration over SSH
- AFL++ fuzzing experiment management
- Crash collection and analysis
- AddressSanitizer-based crash investigation
- Crash deduplication and prioritization
- Static and basic data-flow analysis
- Vulnerability classification and correlation
- CVSS assessment
- Root-cause and exploitability assessment
- Corpus and experiment management
- Patch validation and regression testing
- Evidence export and research report generation
- Local read-only Flask dashboard

## Architecture

- **Python application:** Main command-line interface and research workflow.
- **Kali Linux worker:** Executes AFL++ fuzzing experiments.
- **Analysis modules:** Process crash data and generate research findings.
- **Flask dashboard:** Displays experiment information and analysis results.

## Requirements

- Windows or another supported Python environment
- Python 3.14 (tested in the development environment)
- Kali Linux
- AFL++ installed on Kali Linux
- SSH access from the Windows machine to Kali Linux
- Compatible C/C++ target and fuzzing harness

## Installation

Clone the repository:

```bash
git clone https://github.com/2006Soumik/ZeroTrace.git
cd ZeroTrace
```

Install Python dependencies:

```bash
py -m pip install -r requirements.txt
```

Create your local configuration:

```powershell
Copy-Item .\config\config.example.json .\config\config.json
```

Edit `config/config.json` with your own Kali Linux IP address, username, and workspace paths.

Make sure SSH host verification is configured and your Kali Linux SSH host key is trusted.

## Usage

Start the main application:

```powershell
py app.py
```

Start the dashboard separately:

```powershell
py dashboard\app.py
```

Open the dashboard in your browser:

```text
http://127.0.0.1:5000
```

The dashboard is designed for local, read-only monitoring.

## Demonstrated Test

The development workflow was demonstrated using a sample C program and AFL++ on Kali Linux.

The test demonstrated:

- A completed 30-second fuzzing experiment
- Crash collection
- AddressSanitizer confirmation of a stack-based buffer overflow
- Static and data-flow analysis
- Vulnerability classification
- Evidence correlation and research reporting
- Experiment integrity verification

## Scope and Limitations

ZeroTrace is a research framework, not a universal application scanner.

It currently focuses on native C/C++ targets that have compatible fuzzing harnesses and instrumented builds. Testing complex software such as FFmpeg, SQLite, or image-processing libraries requires target-specific setup.

A detected crash does not automatically prove a remotely exploitable vulnerability or a zero-day. Analysis scores and classifications are research aids, not guarantees.

Web application penetration testing and Android APK testing are not currently supported as direct target types.

## Safety

Only test software that you own or have explicit permission to assess. Use isolated test environments and non-production targets.

## Project Status

Core framework and a sample end-to-end fuzzing workflow have been implemented. Further compatibility testing, documentation, and validation are ongoing.

## Author

Soumik Sarkar

GitHub: https://github.com/2006Soumik
