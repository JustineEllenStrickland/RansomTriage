# Requirements

## Functional Requirements

| ID | Requirement |
|---|---|
| FR1 | The system shall allow an analyst to create a new ransomware triage case. |
| FR2 | The system shall allow an analyst to enter suspicious observations related to script execution, account anomalies, rapid file changes, endpoint behavior, or other early ransomware indicators. |
| FR3 | The system shall guide the analyst through branching triage questions based on the selected observation type. |
| FR4 | The system shall map selected observations and analyst responses to candidate ransomware-related MITRE ATT&CK techniques. |
| FR5 | The system shall recommend relevant evidence sources based on candidate technique mappings and available telemetry. |
| FR6 | The system shall generate a structured case summary that includes observations, candidate mappings, evidence recommendations, limitations, and analyst notes. |
| FR7 | The system shall label ATT&CK mappings as possible or candidate findings rather than confirmed incident classifications. |
| FR8 | The system shall separate user-generated case notes from mapping and workflow rule files. |
| FR9 | The system shall support scenario-based evaluation using sample, public, or sanitized data. |
| FR10 | The system shall allow export of the reviewed case summary for documentation or escalation. |

## Nonfunctional Requirements

| Category | Requirement |
|---|---|
| Performance | The prototype should support rapid scenario-based triage on a standard workstation without requiring live enterprise integrations. |
| Usability | The interface should be understandable to junior or mid-level analysts and should reduce missed evidence through structured prompts. |
| Reliability | The system should preserve entered case data during a session and reduce incomplete or inconsistent case summaries. |
| Scalability | The system should allow additional ATT&CK techniques, workflow questions, and evidence sources to be added without redesigning the full application. |
| Security | The system should minimize stored sensitive data, rely on local operating system access controls, and exclude sensitive case files from public repositories. |
| Maintainability | ATT&CK mappings and workflow logic should be stored separately from the interface so that rules can be reviewed, updated, and version controlled. |
| Portability | The prototype should remain platform-independent where feasible. |
| Privacy | The system should use sanitized testing data and avoid requiring analysts to paste full raw logs or unnecessary personal identifiers. |
| Ethical Use | The system should disclose that it provides decision support and does not make definitive incident classifications. |
