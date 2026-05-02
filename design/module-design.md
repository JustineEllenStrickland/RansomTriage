# Module Design

| Module | Input | Methodology | Output |
|---|---|---|---|
| Case Intake and Observation Entry Module | Case title, analyst notes, affected asset details, suspicious behaviors | Structured form fields and input validation | New triage case and normalized observation record |
| Branching Triage Workflow Engine | Selected observation category and analyst responses | Rule based branching questions | Follow up prompts and triage path |
| ATT&CK Mapping and Rule Logic Module | Analyst responses, selected behaviors, workflow results | Constrained mapping to ransomware related ATT&CK techniques | Candidate ATT&CK techniques with rationale |
| Evidence Recommendation Module | Candidate mappings and available telemetry sources | Environment aware evidence selection | Recommended evidence sources |
| Risk Summary and Analyst Review Module | Candidate mappings, recommendations, limitations, notes | Structured review with uncertainty labels | Analyst reviewed triage summary |
| Export and Case Documentation Module | Final observations, mappings, recommendations, notes | Template based report generation | Structured Markdown case summary |
| Local Storage and Configuration Module | Workflow prompts, mappings, settings, case note content | Local JSON or SQLite storage | Saved sanitized scenario data and reusable workflow content |
