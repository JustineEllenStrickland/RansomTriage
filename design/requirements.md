# Requirements

## Functional Requirements

| ID | Requirement |
|---|---|
| FR1 | The system shall allow an analyst to create a new ransomware triage case with a structured tracking index schema. |
| FR2 | The system shall allow an analyst to enter suspicious observations related to script execution, account anomalies, rapid file changes, endpoint behavior, or other early ransomware indicators. |
| FR3 | The system shall guide the analyst through an interactive telemetry triage matrix panel based on platform-specific ransomware observation categories. |
| FR4 | The system shall map selected matrix indicators and analyst responses to candidate ransomware-related MITRE ATT&CK techniques with associated confidence scores. |
| FR5 | The system shall evaluate visibility gaps and recommend relevant evidence sources based on candidate technique mappings and available vs. unavailable telemetry pipelines. |
| FR6 | The system shall compile a structured case summary that includes metadata, raw observations, candidate mappings, evidence recommendations, operational limitations, and analyst notes. |
| FR7 | The system shall explicitly label ATT&CK mappings as candidate findings rather than confirmed incident classifications to mitigate automation bias. |
| FR8 | The system shall separate user-generated case notes from mapping data and workflow rule definitions using decoupled external configuration files (`attack_mappings.json`, `evidence_sources.json`). |
| FR9 | The system shall support offline, scenario-based evaluation using public, synthetic, or sanitized data profiles. |
| FR10 | The system shall allow the permanent export of the finalized case summary to disk as a production-ready Markdown (.md) document. |

## Nonfunctional Requirements

| Category | Requirement |
|---|---|
| Performance | The desktop prototype shall execute rapid, unbuffered scenario-based triage cycles locally without requiring live enterprise SIEM or cloud service API integrations. |
| Usability | The graphical interface shall use a clean, tabbed layout understandable to tier-1/tier-2 defensive security analysts, reducing missed evidence through grouped telemetry checklists. |
| Reliability | The application shall enforce runtime logging tracking all case configurations, state updates, and file I/O operations seamlessly into a persistent diagnostic file. |
| Scalability | The schema architecture shall allow additional ATT&CK techniques, matrix indicators, and evidence sources to be injected directly via JSON modifications without restructuring the source code. |
| Security | The system shall enforce data minimization, process analysis via local workspace parameters, and explicitly exclude active runtime case logs from public repositories via robust `.gitignore` boundaries. |
| Maintainability | Rules logic, mapping arrays, and reporting templates shall reside strictly outside the core user interface module to ensure clean version control isolation. |
| Portability | The prototype application shall remain platform-independent, operating seamlessly across Linux (including Kali Linux), macOS, and Windows environments running Python 3.x and PyQt6. |
| Privacy | The system shall utilize synthetic staging profiles and explicitly prompt analysts to omit unnecessary personal identifiers, hostnames, or production-sensitive raw logs. |
| Ethical Use | The interface and final summary output shall maintain persistent, prominent classification disclaimers stating that the application functions strictly as a human-in-the-loop decision support system. |
