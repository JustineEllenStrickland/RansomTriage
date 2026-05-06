# Module Design

| Module | Input | Methodology | Output |
|---|---|---|---|
| Case Intake and Observation Entry Module | Case title, analyst notes, affected asset details, and suspicious behaviors | Structured form fields and input validation | New triage case and normalized observation record |
| Branching Triage Workflow Engine | Selected observation category and analyst responses | Rule-based branching questions organized around early ransomware indicators | Follow-up prompts and triage path |
| ATT&CK Mapping and Rule Logic Module | Analyst responses, selected behaviors, and workflow results | Constrained mapping to ransomware-related MITRE ATT&CK techniques | Candidate ATT&CK techniques with rationale |
| Evidence Recommendation Module | Candidate mappings and available telemetry sources | Environment-aware evidence selection based on available logs and tools | Recommended evidence sources for analyst review |
| Risk Summary and Analyst Review Module | Candidate mappings, evidence recommendations, limitations, and analyst notes | Structured review with uncertainty labels | Analyst-reviewed triage summary |
| Export and Case Documentation Module | Final observations, candidate mappings, evidence recommendations, and notes | Template-based report generation | Structured Markdown case summary |
| Local Storage and Configuration Module | Workflow prompts, mappings, settings, and structured case note content | Local JSON or SQLite storage | Saved sanitized scenario data and reusable workflow content |
