# Problem Statement

Security operations personnel frequently encounter uncertain early indicators that may signal ransomware activity, yet they often lack a lightweight, standardized, and evidence driven workflow for evaluating those indicators across multiple security data sources.

RansomTriage addresses this problem by guiding analysts through structured triage questions, mapping observed behaviors to a constrained set of ransomware related MITRE ATT&CK techniques, recommending relevant evidence sources, and generating structured case notes for documentation or escalation.

## Included Scope

- Desktop decision support prototype
- Structured question driven workflow
- Five to eight ransomware related candidate ATT&CK mappings
- Evidence source recommendations
- Local storage for minimal case data
- Markdown case summary export
- Scenario based testing

## Excluded Scope

- Live SIEM or EDR integration
- Automated containment
- Production telemetry ingestion
- Full ATT&CK coverage
- Machine learning model development
- Definitive incident classification
