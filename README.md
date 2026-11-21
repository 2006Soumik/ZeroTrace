# ZeroTrace

**An Automated Software Vulnerability Research and Fuzzing Framework**

ZeroTrace is a Python-based cybersecurity research framework designed to automate software vulnerability research through fuzzing, crash analysis, and security reporting.

It integrates a Windows-based Python application with a Kali Linux worker to execute fuzzing experiments using AFL++ and analyze crashes using AddressSanitizer (ASAN).

## Features

- **Target Management:** Manage and validate C/C++ fuzzing targets.
- **Automated Fuzzing:** Execute AFL++ fuzzing experiments through Kali Linux.
- **Remote Integration:** Connect Windows and Kali Linux using SSH/SFTP.
- **Crash Detection:** Collect and organize crashes generated during fuzzing.
- **Crash Analysis:** Replay crashes using AddressSanitizer.
- **Crash Deduplication:** Identify and group duplicate crash results.
- **Vulnerability Assessment:** Apply heuristic-based severity and exploitability analysis.
- **Static Analysis:** Perform basic source-code security analysis.
- **Security Reports:** Generate structured vulnerability research reports.
- **CVSS Calculator:** Estimate vulnerability severity using CVSS.
- **Patch Validation:** Support regression testing after code changes.
- **Web Dashboard:** Monitor experiments and view security analytics locally.

## Architecture

```text
Windows Application
       |
       v
ZeroTrace Python Framework
       |
       v
SSH / SFTP Connection
       |
       v
Kali Linux Worker
       |
       v
AFL++ Fuzzing Engine
       |
       v
Crash Collection
       |
       v
ASAN Crash Analysis
       |
       v
Reports and Dashboard
```

## Technologies Used

- Python
- Flask
- Kali Linux
- AFL++
- AddressSanitizer (ASAN)
- C/C++
- SSH / SFTP
- Paramiko
- HTML / CSS / JavaScript

## Requirements

- Windows 10/11 or compatible system
- Python 3.14 (tested)
- Kali Linux environment
- SSH access to the Kali Linux worker
- AFL++ installed on Kali Linux
- GCC or Clang compiler
- A compatible C/C++ fuzzing target

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/2006Soumik/ZeroTrace.git
```

### 2. Open the project directory

```bash
cd ZeroTrace
```

### 3. Install dependencies

```bash
py -m pip install -r requirements.txt
```

### 4. Configure the application

Copy the example configuration:

```powershell
Copy-Item .\config\config.example.json .\config\config.json
```

Edit `config/config.json` with your Kali Linux connection details and local configuration.

Never upload passwords, private keys, or other credentials to GitHub.

### 5. Run ZeroTrace

```powershell
py app.py
```

Follow the application menu to configure a target and run an experiment.

## Dashboard

ZeroTrace includes a local Flask-based web dashboard for monitoring experiments, viewing crash information, and reviewing security analytics.

Open the dashboard in your browser:

```text
http://127.0.0.1:5000
```

The dashboard is intended for local monitoring and reporting.

## Demonstration

ZeroTrace has been tested using a sample C program designed for controlled fuzzing experiments.

A demonstrated 30-second experiment produced:

- 20,765 fuzzing executions
- 1 detected crash
- AddressSanitizer confirmation of a stack-buffer-overflow
- 22.22% bitmap coverage
- 100% reported execution stability

These results demonstrate the framework's workflow against a test target. They do not establish that ZeroTrace can discover zero-day vulnerabilities in arbitrary software.

## Scope and Limitations

- Currently focused on native C/C++ fuzzing targets.
- Requires a compatible fuzzing harness and instrumented build.
- Uses Kali Linux and AFL++ for fuzzing.
- Vulnerability classification and exploitability assessments are heuristic-based.
- Results require manual security validation.
- It does not directly scan arbitrary websites, Android applications, or installed software.
- It is a research and learning project, not a replacement for professional security testing tools.

## Safety

Use ZeroTrace only on software you own or have explicit permission to test.

Use isolated environments and controlled test targets when conducting fuzzing experiments.

## Project Status

**Status:** Active Development

ZeroTrace is an ongoing cybersecurity research and portfolio project. Features and testing coverage may change as development continues.

## Author

**Soumik Sarkar**

- GitHub: https://github.com/2006Soumik
- Project: https://github.com/2006Soumik/ZeroTrace
- Research: https://github.com/2006Soumik/zero-day-research-paper
