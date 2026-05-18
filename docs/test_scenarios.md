# Scenario Test Plan

## Scenario 1: Suspicious Encoded PowerShell

Expected:

- Candidate technique: T1059.001 PowerShell
- Evidence sources: Windows Event Logs, Sysmon, EDR
- Output classification language: candidate or possible only

## Scenario 2: Multiple Failed Logons

Expected:

- Candidate technique: T1110 Brute Force
- Evidence sources: Identity logs, Entra ID logs, Windows Event Logs
- Unavailable telemetry documented where applicable

## Scenario 3: Rapid File Extension Changes

Expected:

- Candidate technique: T1486 Data Encrypted for Impact
- Evidence sources: EDR, file server logs, Windows Event Logs
- Limitations documented if telemetry is missing
