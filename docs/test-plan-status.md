# Test Report

## Summary

Unit-level and configuration testing were completed using pytest. The final automated test run passed all checks, with 9 tests passing in 0.08 seconds. Testing focused on workflow configuration integrity, ATT&CK mapping behavior, evidence recommendation logic, report generation, storage reliability, and export readiness.

## Evaluation Areas

- Workflow completion
- Workflow configuration integrity
- Candidate ATT&CK mapping consistency
- Evidence recommendation relevance
- Telemetry gap documentation
- Documentation completeness
- Export formatting
- Storage service reliability
- Sensitive data warning visibility

## Results

| Test Area | Status | Notes |
|---|---|---|
| Workflow configuration | Passed | Confirmed root nodes, threat nodes, UI mapping keys, and MITRE ATT&CK technique ID formatting. |
| ATT&CK mapper | Passed | Confirmed case-insensitive matching, weighted threshold behavior, and normalized technique lookup. |
| Evidence recommender | Passed | Confirmed available telemetry is recommended and unavailable telemetry is documented without duplicate gap errors. |
| Report generator | Passed | Confirmed Markdown generation and fallback behavior when a malformed template is encountered. |
| Storage service | Passed | Confirmed local JSON persistence, load behavior, and atomic save cleanup. |
| Export formatting | Passed | Confirmed the generated Markdown report includes case metadata, observations, candidate mappings, evidence recommendations, unavailable telemetry, limitations, analyst notes, and classification language. |
| Sensitive data warning visibility | Passed | Confirmed the exported report includes a sensitive data review section before case details. |

## Final Pytest Output

```text
9 passed in 0.08s
