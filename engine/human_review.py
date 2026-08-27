"""
ObsidianTrace: Human-in-the-Loop Review Manager & Responsible AI Safety Module
Enforces mandatory human verification on all AI diagnoses and maintains persistent audit trails.
"""

import os
import json
import time
from typing import Dict, Any, List, Optional

DANGEROUS_COMMANDS = [
    "reload", "erase startup-config", "write erase", "format flash",
    "delete flash", "no ip routing", "default interface", "no vlan"
]

class HumanReviewManager:
    def __init__(self, log_dir: Optional[str] = None):
        if log_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_dir = os.path.join(base_dir, "logs")
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.audit_trail_file = os.path.join(self.log_dir, "review_audit_trail.json")
        self.reviews: Dict[str, Dict[str, Any]] = self._load_reviews()

    def _load_reviews(self) -> Dict[str, Dict[str, Any]]:
        if os.path.exists(self.audit_trail_file):
            try:
                with open(self.audit_trail_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_reviews(self):
        with open(self.audit_trail_file, "w", encoding="utf-8") as f:
            json.dump(self.reviews, f, indent=2)

    def submit_review(self, case_id: str, reviewer: str, decision: str,
                      ai_diagnosis: Dict[str, Any],
                      edited_root_cause: Optional[str] = None,
                      edited_cli_fix: Optional[str] = None,
                      reviewer_notes: Optional[str] = None,
                      error_category: Optional[str] = None) -> Dict[str, Any]:
        """
        Records human reviewer decision: 'Accepted', 'Edited', 'Rejected'.
        """
        valid_decisions = ["Accepted", "Edited", "Rejected", "Pending"]
        if decision not in valid_decisions:
            raise ValueError(f"Invalid decision '{decision}'. Must be one of {valid_decisions}")

        # Safety Check: Scan remediation commands for dangerous keywords
        cli_to_check = edited_cli_fix if edited_cli_fix else ai_diagnosis.get("remediation_cli_script", "")
        safety_warnings = self._check_command_safety(cli_to_check)

        record = {
            "case_id": case_id,
            "reviewer": reviewer or "Network Lead Reviewer",
            "decision": decision,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ai_root_cause": ai_diagnosis.get("root_cause", ""),
            "ai_cli_fix": ai_diagnosis.get("remediation_cli_script", ""),
            "ai_confidence": ai_diagnosis.get("confidence", 0.0),
            "final_root_cause": edited_root_cause if (decision == "Edited" and edited_root_cause) else ai_diagnosis.get("root_cause", ""),
            "final_cli_fix": edited_cli_fix if (decision == "Edited" and edited_cli_fix) else ai_diagnosis.get("remediation_cli_script", ""),
            "reviewer_notes": reviewer_notes or ("Approved as accurate." if decision == "Accepted" else "Requires adjustments."),
            "error_category": error_category or ("None" if decision == "Accepted" else "Refinement Required"),
            "safety_warnings": safety_warnings,
            "status": decision.lower()
        }

        self.reviews[case_id] = record
        self._save_reviews()
        return record

    def get_review(self, case_id: str) -> Optional[Dict[str, Any]]:
        return self.reviews.get(case_id)

    def get_all_reviews(self) -> Dict[str, Dict[str, Any]]:
        return self.reviews

    def get_stats(self, total_cases: int = 35) -> Dict[str, Any]:
        accepted = sum(1 for r in self.reviews.values() if r.get("decision") == "Accepted")
        edited = sum(1 for r in self.reviews.values() if r.get("decision") == "Edited")
        rejected = sum(1 for r in self.reviews.values() if r.get("decision") == "Rejected")
        reviewed_total = accepted + edited + rejected
        pending = max(0, total_cases - reviewed_total)
        agreement_rate = round((accepted / max(1, reviewed_total)) * 100, 1) if reviewed_total > 0 else 0.0

        return {
            "total_cases": total_cases,
            "reviewed_count": reviewed_total,
            "accepted": accepted,
            "edited": edited,
            "rejected": rejected,
            "pending": pending,
            "ai_human_agreement_rate_pct": agreement_rate
        }

    def _check_command_safety(self, script: str) -> List[str]:
        warnings = []
        if not script:
            return warnings
        lower_script = script.lower()
        for dangerous in DANGEROUS_COMMANDS:
            if dangerous in lower_script:
                warnings.append(f"HIGH RISK COMMAND DETECTED: '{dangerous}'. Destructive impact possible.")
        return warnings
