# Version Control Overview

## Branching Strategy

- `main`: stable, reviewed project artifacts
- `development`: active work and revisions

Optional feature branches:

- `feature/workflow-engine`
- `feature/attack-mapping`
- `feature/evidence-recommendation`
- `feature/gui`
- `feature/export`

## Commit Message Examples

- Add initial repository structure
- Add module design specifications
- Add workflow question configuration
- Add ATT&CK mapping configuration
- Implement workflow engine
- Add evidence recommender tests
- Update progress log

## Security Boundary

Do not commit:

- Runtime databases
- Exported case files
- Real logs
- Credentials
- Production telemetry
- Personal identifiers
- Confidential incident details
