# RansomTriage Case Summary

## Sensitive Data Review

Before sharing this report, review and remove unnecessary personal identifiers, hostnames, IP addresses, file paths, raw logs, or confidential investigation details.

## Case Metadata

- **Case Title:** {{ case_title }}
- **Analyst:** {{ analyst }}
- **Target System Asset:** {{ affected_asset }}
- **Observation Category:** {{ observation_category }}

## Observations

{{ observations }}

## Candidate ATT&CK Mappings

| Technique ID | Technique Name | Confidence Score |
| :--- | :--- | :--- |
{% for mapping in candidate_mappings -%}
| `{{ mapping.technique_id }}` | {{ mapping.technique_name }} | {{ mapping.confidence_score }} |
{% else -%}
| *None* | No techniques mapped during triage. | N/A |
{% endfor %}

## Unavailable Telemetry

> ⚠️ **The following log pipelines were marked as UNCHECKED/UNAVAILABLE during triage. Verify if these visibility gaps can be retroactively closed:**

{% for telemetry in unavailable_telemetry -%}
- [ ] {{ telemetry }}
{% else -%}
- All core telemetry pipelines were marked as available during this triage window.
{% endfor %}

## Limitations

{% for limitation in limitations -%}
- {{ limitation }}
{% else -%}
- No operational limitations or scoping constraints were noted for this triage cycle.
{% endfor %}

## Analyst Notes

{{ analyst_notes }}

## Classification Statement

This report provides decision support only. Candidate mappings require analyst validation and do not represent confirmed incident classification.
