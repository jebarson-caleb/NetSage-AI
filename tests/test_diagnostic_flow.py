"""
Integration Tests for NetSage AI End-to-End Diagnostic Pipeline
Validates diagnostic engine, rule checker, human review state machine, and simulator.
"""

import unittest
import json
import os
from engine.ai_engine import DiagnosticEngine
from engine.human_review import HumanReviewManager
from engine.simulator import CiscoTerminalSimulator

class TestDiagnosticFlow(unittest.TestCase):
    def setUp(self):
        self.engine = DiagnosticEngine(provider="local")
        self.review_manager = HumanReviewManager()
        self.simulator = CiscoTerminalSimulator()

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base_dir, "data", "cases.json"), "r", encoding="utf-8") as f:
            self.cases = json.load(f)

    def test_end_to_end_case_01(self):
        case = self.cases[0]  # NET-001
        
        # Step 1: Diagnose
        diagnosis = self.engine.diagnose_case(case)
        self.assertEqual(diagnosis["case_id"], "NET-001")
        self.assertTrue(len(diagnosis["evidence_citations"]) > 0)
        self.assertIn("encapsulation dot1Q", diagnosis["remediation_cli_script"])
        self.assertTrue(diagnosis["requires_human_approval"])

        # Step 2: Human Review (Accept)
        review_record = self.review_manager.submit_review(
            case_id="NET-001",
            reviewer="Test CCIE Engineer",
            decision="Accepted",
            ai_diagnosis=diagnosis,
            reviewer_notes="Approved for production application."
        )
        self.assertEqual(review_record["decision"], "Accepted")
        self.assertEqual(review_record["status"], "accepted")

        # Step 3: Simulation
        sim_res = self.simulator.simulate_apply_fix(case, diagnosis["remediation_cli_script"])
        self.assertTrue(sim_res["success"])
        self.assertEqual(sim_res["verification_status"], "PASSED")
        self.assertEqual(sim_res["ping_success_rate"], "100%")

    def test_human_edit_flow(self):
        case = self.cases[2]  # NET-003 DHCP Relay
        diagnosis = self.engine.diagnose_case(case)
        
        # Human edits the fix
        corrected_fix = "interface GigabitEthernet0/0.30\n ip helper-address 192.168.10.100"
        review_record = self.review_manager.submit_review(
            case_id="NET-003",
            reviewer="Architect Reviewer",
            decision="Edited",
            ai_diagnosis=diagnosis,
            edited_root_cause="Missing ip helper-address pointing to centralized DHCP server",
            edited_cli_fix=corrected_fix,
            reviewer_notes="Corrected to use centralized IPAM relay.",
            error_category="Architectural Misalignment"
        )
        self.assertEqual(review_record["decision"], "Edited")
        self.assertEqual(review_record["final_cli_fix"], corrected_fix)

    def test_all_cases_batch_diagnosis(self):
        aligned_count = 0
        for case in self.cases:
            diag = self.engine.diagnose_case(case)
            self.assertIsNotNone(diag["fault_summary"])
            self.assertIsNotNone(diag["remediation_cli_script"])
            if diag.get("ground_truth_match", {}).get("is_aligned"):
                aligned_count += 1
        
    def test_packet_tracer_troubleshoot_chat(self):
        symptom = "PC-2 in VLAN 20 cannot ping its default gateway 192.168.20.1 on Router subinterface G0/0.20."
        pasted_cli = "interface GigabitEthernet0/0.20\n ip address 192.168.20.1 255.255.255.0"
        
        chat_res = self.engine.troubleshoot_chat(
            user_message=symptom,
            pasted_cli=pasted_cli,
            topology="Router-on-a-Stick ROAS Topology"
        )
        self.assertTrue(chat_res["success"])
        self.assertIn("encapsulation dot1Q", chat_res["reply"] + str(chat_res.get("diagnosis_object", {})))
        self.assertTrue(chat_res["requires_human_approval"])

    def test_groq_connection_status_handling(self):
        status_invalid_key = self.engine.test_groq_connection(api_key="gsk_invalid_test_key_abc123")
        self.assertFalse(status_invalid_key["connected"])
        self.assertIn("error", status_invalid_key)


if __name__ == "__main__":
    unittest.main()

