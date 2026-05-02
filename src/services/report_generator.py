from pathlib import Path


class ReportGenerator:
    def __init__(self, template_path: str | Path):
        self.template_path = Path(template_path)
        self.template = self.template_path.read_text(encoding="utf-8")

    def generate_markdown(self, case) -> str:
        replacements = {
            "{{case_title}}": case.case_title,
            "{{analyst}}": case.analyst,
            "{{created_at}}": case.created_at,
            "{{observation_category}}": case.observation_category,
            "{{observations}}": case.observations or "No observations recorded.",
            "{{triage_responses}}": self._format_dict(case.triage_responses),
            "{{candidate_mappings}}": self._format_mappings(case.candidate_mappings),
            "{{evidence_recommendations}}": self._format_evidence(case.evidence_recommendations),
            "{{unavailable_telemetry}}": self._format_list(case.unavailable_telemetry),
            "{{limitations}}": self._format_list(case.limitations),
            "{{analyst_notes}}": case.analyst_notes or "No analyst notes recorded."
        }

        output = self.template
        for key, value in replacements.items():
            output = output.replace(key, value)

        return output

    def save_markdown(self, case, output_path: str | Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.generate_markdown(case), encoding="utf-8")
        return output_path

    @staticmethod
    def _format_dict(data: dict) -> str:
        if not data:
            return "No responses recorded."
        return "\n".join(f"- {key}: {value}" for key, value in data.items())

    @staticmethod
    def _format_list(items: list) -> str:
        if not items:
            return "None documented."
        return "\n".join(f"- {item}" for item in items)

    @staticmethod
    def _format_mappings(mappings: list[dict]) -> str:
        if not mappings:
            return "No candidate mappings generated."
        return "\n".join(
            f"- {m['technique_id']} {m['technique_name']} ({m['label']}): {m['rationale']}"
            for m in mappings
        )

    @staticmethod
    def _format_evidence(evidence: list[dict]) -> str:
        if not evidence:
            return "No evidence recommendations generated."
        return "\n".join(
            f"- {item['name']}: {item['description']}"
            for item in evidence
        )
