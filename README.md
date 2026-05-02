# RansomTriage

RansomTriage is a platform independent desktop decision support prototype for early ransomware triage. The tool guides analysts through structured observations, branching triage questions, candidate MITRE ATT&CK mappings, evidence recommendations, analyst review, and structured case note export.

## Project Scope

RansomTriage supports early triage only. It does not perform automated detection, containment, forensic analysis, production telemetry ingestion, full ATT&CK coverage, or definitive incident classification.

## Core Functions

1. Case intake and observation entry
2. Branching triage workflow
3. Candidate MITRE ATT&CK mapping
4. Evidence recommendation
5. Risk summary and analyst review
6. Structured case summary export
7. Local storage and configuration
8. Scenario based testing

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 src/main.py
