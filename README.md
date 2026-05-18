# RansomTriage 🛡️✈️

RansomTriage is a platform-independent desktop decision-support flight deck designed for high-pressure early ransomware triage. Built using Python 3 and PyQt6, the platform guides defensive security analysts through a structured telemetry matrix, automated MITRE ATT&CK mapping, evidence prioritization loops, and clean Markdown report exports.

## 🎯 Project Scope & Guardrails

RansomTriage functions strictly as a **human-in-the-loop decision support engine** to mitigate automation bias during critical containment windows. 
* **In-Scope:** Structured intake profiling, platform-specific telemetry triage matrices, visibility gap tracking, and standardized case documentation.
* **Out-of-Scope:** RansomTriage does not perform active asset containment, live production telemetry ingestion, raw file forensics, or definitive incident classification.

---

## 🛠️ Core Functional Architecture

1. **Home Flight Deck:** An operational dashboard providing immediate workspace instructions, structural playbooks, and safe execution boundaries.
2. **Incident Triage Matrix:** An interactive, panel-driven wizard tree mapping observed infrastructure anomalies (Windows Core, Linux Hosts, ESXi Hypervisors, Cloud IdP) to defensive signatures.
3. **Case Intake Profile:** Seamless automatic translation of matrix notes into structured case records tracking target assets, investigating analysts, and custom notes.
4. **Visibility & Telemetry Audit:** An environment-aware logic block that cross-references available logs and isolates critical unchecked visibility pipelines.
5. **Jinja2 Reporting Engine:** Compiles metadata, candidate ATT&CK techniques, and confidence tracking into a clean, sanitized Markdown summary document.
6. **Hardened Dual-Stream Logging:** Initialized instantly on boot to feed live terminal debugging and a persistent, unbuffered historical forensic log file (`logs/ransomtriage.log`).

---

## 📂 Repository Structure

The project strictly follows modular software design principles, decoupling backend analytical services from front-end desktop layouts:

RansomTriage/
├── data/                  # Public, synthetic, and sanitized test data profiles
├── design/                # System design blueprints, safeguards, and requirements
├── exports/               # Target output folder for compiled case markdown files
├── logs/                  # Persistent runtime operational log streams
├── runtime/               # Local data cache and session state persistence layer
└── src/
    ├── config/            # JSON mapping rules, evidence sources, and Jinja templates
    ├── models/            # Core object schemas and data structures (Case, Mappings)
    ├── services/          # Decoupled business logic engines (AttackMapper, ReportGenerator)
    └── ui/                # PyQt6 graphical interface implementation (MainWindow, Workflows)

---

## 🚀 Installation & Local Deployment
This prototype is engineered to operate locally on a standard security workstation (including Kali Linux) without requiring active SIEM database or cloud service API integrations.

1. Clone and Environment Initialization
	Ensure you have Python 3.10+ and virtualenv packages available in your workspace environment:
		python3 -m venv .venv
		source .venv/bin/activate
2. Dependency Resolution
	Install the required architectural third-party constraints mapped in the environment manifests:
		pip install -r requirements.txt
3. Execution Space Launch
	Execute the application booster from the root workspace directory to spin up the UI context:
		python3 src/main.py

---

## 📝 License
This project is distributed openly under the permissive legal terms of the MIT License. See the accompanying LICENSE file at the root layout context for comprehensive liability disclaimers and permissions data.
