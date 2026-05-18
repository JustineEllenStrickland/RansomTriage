import logging
from typing import Dict, List, Any

class TriageWorkflowRouter:
    def __init__(self):
        # Current state tracker for the session
        self.selected_platforms: List[str] = []
        self.selected_sub_platforms: List[str] = []
        
        # FIFO Queue to safely hold multiple triage branches sequentially
        self.triage_queue: List[str] = []

    def set_initial_platforms(self, platforms: List[str]) -> Dict[str, Any]:
        """
        Processes Level 1: Core Platform Vectors.
        Determines if sub-platform choices need to be displayed or skipped.
        """
        self.selected_platforms = platforms
        logging.info(f"[+] Root platforms set to: {self.selected_platforms}")

        # Rule 1: Safety Override for "I'm Not Sure"
        if "Im Not Sure" in platforms or not platforms:
            return {
                "action": "LOAD_QUESTIONS",
                "target_node": "baseline_generic_triage",
                "message": "Routing to wide-net safety triage presets due to uncertain environment profile."
            }

        # Rule 2: Multi-path evaluation using conditional state routing
        # Fixed string routing queries to precisely match option values
        requires_enterprise_sub = "Enterprise" in platforms
        requires_mobile_sub = "Mobile" in platforms
        has_ics = "ICS" in platforms

        if requires_enterprise_sub and requires_mobile_sub:
            return {"action": "SHOW_SUB_MATRICES", "panels": ["Enterprise", "Mobile"]}
        elif requires_enterprise_sub:
            return {"action": "SHOW_SUB_MATRICES", "panels": ["Enterprise"]}
        elif requires_mobile_sub:
            return {"action": "SHOW_SUB_MATRICES", "panels": ["Mobile"]}
        elif has_ics:
            # ICS has no sub-matrix; route straight to its questions
            return {
                "action": "LOAD_QUESTIONS",
                "target_node": "ics_industrial_triage",
                "message": "Bypassing sub-platforms. Loading specialized Industrial Control System (ICS) vectors."
            }
        
        # Fallback safeguard
        return {"action": "LOAD_QUESTIONS", "target_node": "baseline_generic_triage"}

    def set_sub_platforms(self, sub_platforms: List[str]) -> Dict[str, Any]:
        """
        Processes Level 2: Sub-Platform Infrastructure Breakdown.
        Populates our tracking queue to handle non-mutually exclusive selections,
        then triggers processing for the first structural target node.
        """
        self.selected_sub_platforms = sub_platforms
        logging.info(f"[+] Sub-platforms set to: {self.selected_sub_platforms}")

        # Rule 1: Infrastructure Unknown kill-switch or empty arrays
        if "Infrastructure Unknown" in sub_platforms or "Unknown" in sub_platforms or not sub_platforms:
            return {
                "action": "LOAD_QUESTIONS",
                "target_node": "baseline_generic_triage",
                "message": "Unknown sub-platform selected. Loading safety-net discovery playbooks."
            }

        # Clear any stale data out of the queue before calculation loops
        self.triage_queue.clear()

        # Rule 2: Scan for ALL matching platforms and push them to the triage queue.
        # This completely resolves the original single-choice 'elif' limitation.
        if "Windows" in sub_platforms or "Windows Core" in sub_platforms:
            self.triage_queue.append("windows_core_ransomware")
        
        if "ESXi" in sub_platforms or "ESXi/Hypervisor" in sub_platforms:
            self.triage_queue.append("esxi_hypervisor_ransomware")

        if "Cloud: Identity Provider" in sub_platforms:
            self.triage_queue.append("cloud_idp_compromise")

        if "Linux" in sub_platforms or "Linux Host Matrix" in sub_platforms:
            self.triage_queue.append("linux_host_ransomware")

        # Fallback to generic triage profile if options were checked but didn't match our main targets
        if not self.triage_queue and sub_platforms:
            return {
                "action": "LOAD_QUESTIONS",
                "target_node": "generic_enterprise_triage",
                "message": "Loading generic multi-asset infrastructure diagnostic profile."
            }

        # Pull the very first selected option from our newly populated queue and execute it
        return self.get_next_triage_node()

    def get_next_triage_node(self) -> Dict[str, Any]:
        """
        Pops the next diagnostic node configuration off the list. 
        Provides standard interface return envelopes for clean view parsing.
        """
        if not self.triage_queue:
            return {
                "action": "COMPLETE_WORKFLOW",
                "target_node": None,
                "message": "All flagged environment nodes have been successfully evaluated."
            }

        next_target = self.triage_queue.pop(0)

        # Map targets to their explicit logging feedback responses
        messages = {
            "windows_core_ransomware": "Loading Windows Core Active Directory & Endpoint investigative tree.",
            "esxi_hypervisor_ransomware": "CRITICAL: VMware Hypervisor path detected. Loading specialized ESXi datastore/SSH locking indicators.",
            "cloud_idp_compromise": "Loading Cloud Identity Provider (Okta/Entra ID) token theft and MFA bypass vectors.",
            "linux_host_ransomware": "Loading Linux production server diagnostic logs and cron-job monitoring trees."
        }

        return {
            "action": "LOAD_QUESTIONS",
            "target_node": next_target,
            "message": messages.get(next_target, "Loading next infrastructure block configuration.")
        }
