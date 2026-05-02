# Requirements

## Functional Requirements

| ID | Requirement |
|---|---|
| FR1 | The system shall allow an analyst to create a new ransomware triage case. |
| FR2 | The system shall allow an analyst to enter suspicious observations. |
| FR3 | The system shall guide the analyst through branching triage questions. |
| FR4 | The system shall map selected observations to candidate ransomware related ATT&CK techniques. |
| FR5 | The system shall recommend relevant evidence sources. |
| FR6 | The system shall generate a structured case summary. |
| FR7 | The system shall label ATT&CK mappings as possible or candidate findings. |
| FR8 | The system shall separate user generated case notes from mapping and workflow rule files. |
| FR9 | The system shall support scenario based evaluation using sample, public, or sanitized data. |
| FR10 | The system shall allow export of the reviewed case summary. |

## Nonfunctional Requirements

| Category | Requirement |
|---|---|
| Performance | The prototype should support rapid scenario based triage on a standard workstation. |
| Usability | The interface should be understandable to junior or mid level analysts. |
| Reliability | The system should preserve entered case data during a session. |
| Scalability | The system should allow additional techniques, questions, and evidence sources to be added without redesigning the full application. |
| Security | The system should minimize stored sensitive data and exclude sensitive files from public repositories. |
| Maintainability | Mapping and workflow logic should be stored separately from the interface. |
| Portability | The prototype should remain platform independent where feasible. |
| Privacy | The system should use sanitized data and avoid unnecessary identifiers. |
| Ethical Use | The system should disclose that it provides decision support, not final incident classification. |
