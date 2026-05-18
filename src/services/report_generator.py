import logging
from pathlib import Path
from jinja2 import Template, TemplateSyntaxError

class ReportGenerator:
    def __init__(self, template_path: str | Path):
        self.template_path = Path(template_path)
        # Establish the immutable core blueprint as our guaranteed baseline fallback
        self.fallback_blueprint = (
            "# RansomTriage Case Summary\n\n"
            "## Case Metadata\n"
            "- **Case Title:** {{ case_title }}\n"
            "- **Analyst:** {{ analyst }}\n"
            "- **Target System Asset:** {{ affected_asset }}\n"
            "- **Observation Domain:** {{ observation_category }}\n\n"
            "## Observations\n{{ observations }}\n\n"
            "## Candidate MITRE ATT&CK Mappings\n"
            "{% for mapping in candidate_mappings -%}\n"
            "- **`{{ mapping['technique_id'] }}`**: {{ mapping['technique_name'] }} "
            "(Confidence: {{ mapping['confidence_score'] }})\n"
            "{% else -%}\n- No active ATT&CK mappings identified.\n{% endfor %}\n\n"
            "## Evidence Recommendations (Telemetry Gaps)\n"
            "### Recommended Forensic Sources (Available):\n"
            "{% for rec in evidence_recommendations -%}\n"
            "- {{ rec }}\n"
            "{% else -%}\n- No operational recommendations generated.\n{% endfor %}\n\n"
            "### Missing Telemetry Streams:\n"
            "{% for missing in unavailable_telemetry -%}\n"
            "- [ ] Missing Visibility: **{{ missing }}**\n"
            "{% else -%}\n- All necessary context data sources are online.\n{% endfor %}\n\n"
            "## Analyst Notes & Constraints\n"
            "{{ analyst_notes }}"
        )
        self.template_content = self._load_template()

    def _load_template(self) -> str:
        """Safely extracts raw template markdown text data if valid, otherwise falls back immediately."""
        try:
            if self.template_path.exists():
                content = self.template_path.read_text(encoding="utf-8")
                # Validate syntax right now on initialization
                Template(content)
                return content
            logging.warning(f"[-] Report template missing at '{self.template_path}'. Using embedded blueprint fallback.")
        except Exception as e:
            logging.error(f"[-] Defective export template file layout: {e}. Defaulting to dynamic fallback schema.")
        
        return self.fallback_blueprint

    def generate_markdown(self, case) -> str:
        """Compiles the case data context directly into the Jinja2 engine template loop structures."""
        try:
            template_text = self.template_content
            
            # Re-read file template context dynamically if available to allow on-the-fly modifications
            if self.template_path.exists():
                try:
                    content_check = self.template_path.read_text(encoding="utf-8")
                    Template(content_check)  # Dry-run parse checking for runtime modifications
                    template_text = content_check
                except Exception:
                    # File on disk became corrupted or unreadable mid-flight. Fallback to init cache.
                    pass

            report_context = {
                "case_title": getattr(case, "case_title", "Unknown Title"),
                "analyst": getattr(case, "analyst", "Unknown Investigator"),
                "affected_asset": getattr(case, "affected_asset", "Unknown Asset"),
                "observation_category": getattr(case, "observation_category", "General Ransomware Triage"),
                "observations": getattr(case, "observations", "") or "No operational observations recorded.",
                "candidate_mappings": getattr(case, "candidate_mappings", []) or [],
                "evidence_recommendations": getattr(case, "evidence_recommendations", []) or [],
                "unavailable_telemetry": getattr(case, "unavailable_telemetry", []) or [],
                "limitations": getattr(case, "limitations", []) or [],
                "analyst_notes": getattr(case, "analyst_notes", "") or "No analyst notes recorded."
            }

            try:
                jinja_template = Template(template_text)
                return jinja_template.render(report_context)
            except TemplateSyntaxError as syn_err:
                logging.error(f"[-] Syntax Error in external file template: {syn_err}. Dropping back to internal engine string blueprint.")
                # Guaranteed Recovery: Compile using the immutable fallback layout string
                fallback_template = Template(self.fallback_blueprint)
                return fallback_template.render(report_context)

        except Exception as e:
            logging.error(f"[-] Jinja2 rendering execution failed: {e}")
            return f"# Triage Generation Error\n\nFailed to compile reporting components. Error: {e}"

    def save_markdown(self, case, output_path: str | Path) -> Path:
        """Writes the transformed markdown file output securely to disk."""
        output_path = Path(output_path)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            rendered_content = self.generate_markdown(case)
            output_path.write_text(rendered_content, encoding="utf-8")
        except Exception as e:
            logging.error(f"[-] Failed to write forensic markdown summary at '{output_path}': {e}")
            raise e
        return output_path
