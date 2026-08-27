"""
Unit Tests for NetSage AI Deterministic Rule Checker
Validates that all 12+ static sanity rules catch the correct network anomalies.
"""

import unittest
import json
import os
from engine.rule_checker import NetworkRuleChecker

class TestNetworkRuleChecker(unittest.TestCase):
    def setUp(self):
        self.checker = NetworkRuleChecker()
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base_dir, "data", "cases.json"), "r", encoding="utf-8") as f:
            self.cases = json.load(f)
        self.cases_by_id = {c["case_id"]: c for c in self.cases}

    def test_admin_down_interface(self):
        case = self.cases_by_id["NET-010"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("ADMIN_DOWN_CHECK", rule_ids)

    def test_vlan_subinterface_encapsulation(self):
        case = self.cases_by_id["NET-001"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("VLAN_TRUNK_MISMATCH", rule_ids)

    def test_default_gateway_mismatch(self):
        case = self.cases_by_id["NET-002"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("SUBNET_MASK_MISMATCH", rule_ids)

    def test_missing_dhcp_helper(self):
        case = self.cases_by_id["NET-003"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("DHCP_POOL_AND_RELAY", rule_ids)

    def test_native_vlan_mismatch(self):
        case = self.cases_by_id["NET-004"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("VLAN_TRUNK_MISMATCH", rule_ids)

    def test_acl_missing_dns(self):
        case = self.cases_by_id["NET-005"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("ACL_IMPLICIT_DENY", rule_ids)

    def test_ospf_area_mismatch(self):
        case = self.cases_by_id["NET-007"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("OSPF_NEIGHBOR_ADJACENCY", rule_ids)

    def test_nat_overload_omission(self):
        case = self.cases_by_id["NET-008"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("NAT_INSIDE_OUTSIDE", rule_ids)

    def test_port_security_errdisable(self):
        case = self.cases_by_id["NET-013"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("PORT_SECURITY_ERRDISABLE", rule_ids)

    def test_speed_duplex_collisions(self):
        case = self.cases_by_id["NET-012"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("SPEED_DUPLEX_MISMATCH", rule_ids)

    def test_acl_inverted_wildcard(self):
        case = self.cases_by_id["NET-018"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("ACL_IMPLICIT_DENY", rule_ids)

    def test_hsrp_virtual_ip_mismatch(self):
        case = self.cases_by_id["NET-022"]
        result = self.checker.scan(case)
        self.assertTrue(result["has_violations"])
        rule_ids = [v["rule_id"] for v in result["violations"]]
        self.assertIn("HSRP_PRIORITY_PREEMPT", rule_ids)

if __name__ == "__main__":
    unittest.main()
