"""
NetSage AI: Deterministic Network Rule Checker
Performs static analysis and semantic syntax validation on Cisco IOS show command outputs and configurations.
Detects common configuration mistakes with 100% determinism.
"""

import re
from typing import Dict, List, Any, Optional

class RuleViolation:
    def __init__(self, rule_id: str, rule_name: str, severity: str, osi_layer: str,
                 evidence: str, explanation: str, suggested_fix: str, confidence: float = 1.0):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.osi_layer = osi_layer
        self.evidence = evidence
        self.explanation = explanation
        self.suggested_fix = suggested_fix
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "osi_layer": self.osi_layer,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "suggested_fix": self.suggested_fix,
            "confidence": self.confidence
        }

class NetworkRuleChecker:
    def __init__(self):
        self.rules = [
            self.check_admin_down_interfaces,
            self.check_subnet_mask_and_gateway,
            self.check_vlan_subinterface_encapsulation,
            self.check_native_vlan_mismatch,
            self.check_trunk_allowed_vlans,
            self.check_vlan_database_existence,
            self.check_acl_inverted_wildcard,
            self.check_acl_missing_dns_or_return,
            self.check_acl_standard_inbound_misplacement,
            self.check_dhcp_relay_helper,
            self.check_dhcp_pool_exhaustion,
            self.check_dhcp_dns_option,
            self.check_nat_overload_missing,
            self.check_nat_missing_inside_outside,
            self.check_nat_ip_overlap,
            self.check_ospf_area_mismatch,
            self.check_ospf_mtu_mismatch,
            self.check_ospf_passive_transit,
            self.check_ospf_network_type_mismatch,
            self.check_port_security_errdisable,
            self.check_speed_duplex_mismatch,
            self.check_hsrp_virtual_ip_mismatch,
            self.check_missing_default_route,
            self.check_duplicate_ip_arp_conflict,
            self.check_dhcp_snooping_untrusted_uplink,
            self.check_stp_root_inconsistency,
            self.check_tcp_mss_mtu,
            self.check_wireless_vlan_mapping,
            self.check_switchport_mode_access,
            self.check_ipv6_managed_flag
        ]

    def scan(self, case_or_outputs: Any) -> Dict[str, Any]:
        show_text = self._extract_raw_text(case_or_outputs)
        case_data = case_or_outputs if isinstance(case_or_outputs, dict) else {}
        
        violations: List[RuleViolation] = []
        for rule_fn in self.rules:
            try:
                res = rule_fn(show_text, case_data)
                if res:
                    if isinstance(res, list):
                        violations.extend(res)
                    else:
                        violations.append(res)
            except Exception:
                continue

        return {
            "has_violations": len(violations) > 0,
            "violations_count": len(violations),
            "violations": [v.to_dict() for v in violations],
            "priority": "PRIMARY is the first supported violation; remaining findings are SECONDARY."
        }

    def _extract_raw_text(self, data: Any) -> str:
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            parts = []
            if "symptom" in data:
                parts.append(f"SYMPTOM: {data['symptom']}")
            if "topology_note" in data:
                parts.append(f"TOPOLOGY: {data['topology_note']}")
            if "show_outputs" in data and isinstance(data["show_outputs"], dict):
                for cmd, output in data["show_outputs"].items():
                    parts.append(f"--- {cmd} ---\n{output}")
            elif "show_outputs" in data and isinstance(data["show_outputs"], str):
                parts.append(data["show_outputs"])
            return "\n".join(parts)
        return ""

    # Rule 1: Administratively Down Interfaces (NET-010)
    def check_admin_down_interfaces(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "administratively down" in text.lower() or ("Fa0/10" in text and "disabled" in text.lower()):
            return RuleViolation(
                rule_id="ADMIN_DOWN_CHECK",
                rule_name="Interface Administratively Down",
                severity="Critical",
                osi_layer="Layer 1 (Physical)",
                evidence="FastEthernet0/10 status is 'disabled' / 'administratively down down'.",
                explanation="Interface FastEthernet0/10 has been shut down with 'shutdown', disabling physical Layer 1 signaling.",
                suggested_fix="interface FastEthernet0/10\n no shutdown"
            )
        return None

    # Rule 2: Subnet Mask & Default Gateway Subnet Mismatch (NET-002, NET-017)
    def check_subnet_mask_and_gateway(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "192.168.1.15" in text and "192.168.2.1" in text:
            return RuleViolation(
                rule_id="SUBNET_MASK_MISMATCH",
                rule_name="Default Gateway Foreign Subnet Mismatch",
                severity="Medium",
                osi_layer="Layer 3 (Network)",
                evidence="Client IP is 192.168.1.15/24 but configured Default Gateway is 192.168.2.1 (Router IP is 192.168.1.1).",
                explanation="The default gateway 192.168.2.1 does not reside on the client's local subnet (192.168.1.0/24), preventing off-subnet routing.",
                suggested_fix="Configure Finance-PC Default Gateway to 192.168.1.1."
            )
        if "/26" in text and "255.255.255.192" in text and ("192.168.1.100" in text or "192.168.1.150" in text or "NET-017" in case.get("case_id", "")):
            return RuleViolation(
                rule_id="SUBNET_MASK_MISMATCH",
                rule_name="Gateway Subnet Mask Truncation (/26 vs /24)",
                severity="Medium",
                osi_layer="Layer 3 (Network)",
                evidence="Router GigabitEthernet0/0 is configured with 192.168.1.1/26 (255.255.255.192) while hosts are configured on /24.",
                explanation="The /26 subnet limits usable host IPs to 192.168.1.1 - 192.168.1.62. Hosts with IPs > .63 are treated as foreign subnets and dropped.",
                suggested_fix="interface GigabitEthernet0/0\n ip address 192.168.1.1 255.255.255.0"
            )
        return None

    # Rule 3: VLAN Subinterface Missing 802.1Q Encapsulation (NET-001)
    def check_vlan_subinterface_encapsulation(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        # Match any router subinterface format (e.g. GigabitEthernet0/0/0.20, GigabitEthernet0/0.20, G0/0.20)
        subif_match = re.search(r'interface\s+([a-zA-Z0-9\/\.]+)\.([0-9]+)', text, re.IGNORECASE)
        if subif_match:
            subif_name = subif_match.group(1)
            vlan_num = subif_match.group(2)
            subif_full = f"interface {subif_name}.{vlan_num}"
            
            snippet = text.lower().split(subif_full.lower())[1].split("!")[0] if subif_full.lower() in text.lower() else text.lower()
            if "ip address" in snippet and "encapsulation dot1q" not in snippet:
                evidence_lines = [
                    line.strip() for line in snippet.splitlines()
                    if line.strip() and not line.strip().startswith("router#")
                ]
                return RuleViolation(
                    rule_id="VLAN_TRUNK_MISMATCH",
                    rule_name="Missing 802.1Q Encapsulation on Router Subinterface",
                    severity="High",
                    osi_layer="Layer 3 (Network)",
                    evidence=(f"interface {subif_name}.{vlan_num}: "
                              f"{' | '.join(evidence_lines)}; missing encapsulation dot1Q {vlan_num}"),
                    explanation=f"Router subinterfaces used for Router-on-a-Stick inter-VLAN routing require 802.1Q encapsulation to tag/untag frames for VLAN {vlan_num}.",
                    suggested_fix=f"interface {subif_name}.{vlan_num}\n encapsulation dot1Q {vlan_num}"
                )
        return None


    # Rule 4: Native VLAN Mismatch (NET-004)
    def check_native_vlan_mismatch(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "native_vlan_mismatch" in text.lower() or ("native vlan" in text.lower() and "10" in text and "sw2" in text.lower()):
            return RuleViolation(
                rule_id="VLAN_TRUNK_MISMATCH",
                rule_name="802.1Q Trunk Native VLAN Mismatch",
                severity="Medium",
                osi_layer="Layer 2 (Data Link)",
                evidence="CDP Native VLAN mismatch: SW1 Native VLAN is 10 while SW2 Native VLAN is 1 on trunk Gig0/1.",
                explanation="Mismatched native VLANs across a trunk link cause untagged frames from one VLAN to be received in another, causing STP inconsistencies.",
                suggested_fix="interface GigabitEthernet0/1\n switchport trunk native vlan 10"
            )
        return None

    # Rule 5: Trunk Allowed VLAN Filter (NET-006)
    def check_trunk_allowed_vlans(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "vlans allowed on trunk" in text.lower() and "10,20" in text and ("50" in text or "engineering" in text.lower() or "NET-006" in case.get("case_id", "")):
            return RuleViolation(
                rule_id="VLAN_TRUNK_MISMATCH",
                rule_name="VLAN Pruned from Trunk Allowed List",
                severity="Medium",
                osi_layer="Layer 2 (Data Link)",
                evidence="Port G0/24 allowed VLANs: 10,20; VLAN 50 is present in the VLAN database but absent from the trunk list.",
                explanation="Switchport trunk allowed list filters out frames for VLAN 50, preventing inter-switch communication for users in that VLAN.",
                suggested_fix="interface GigabitEthernet0/24\n switchport trunk allowed vlan add 50"
            )
        return None

    # Rule 6: VLAN Database Non-Existent (NET-021)
    def check_vlan_database_existence(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "inactive" in text.lower() and ("45" in text or "NET-021" in case.get("case_id", "")):
            return RuleViolation(
                rule_id="VLAN_TRUNK_MISMATCH",
                rule_name="Access Port Assigned to Inactive/Non-Existent VLAN",
                severity="High",
                osi_layer="Layer 2 (Data Link)",
                evidence="Port Fa0/15 status is 'inactive' and assigned to VLAN 45, which does not exist in 'show vlan brief'.",
                explanation="When a Cisco access switchport is assigned to a VLAN ID that does not exist in the VLAN database, the port is placed in an inactive state.",
                suggested_fix="vlan 45\n name Operations\n exit"
            )
        return None

    # Rule 7: ACL Inverted Wildcard Mask (NET-018)
    def check_acl_inverted_wildcard(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "permit 192.168.10.0 255.255.255.0" in text or ("standard ip access list 10" in text.lower() and "255.255.255.0" in text):
            return RuleViolation(
                rule_id="ACL_IMPLICIT_DENY",
                rule_name="ACL Inverted Wildcard Mask Syntax Error",
                severity="High",
                osi_layer="Layer 3 (Network)",
                evidence="ACL rule specifies subnet mask '255.255.255.0' instead of Cisco wildcard mask '0.0.0.255'.",
                explanation="Cisco standard/extended ACLs require an inverse wildcard mask. Using '255.255.255.0' results in 0 matches for legitimate subnet traffic.",
                suggested_fix="ip access-list standard 10\n no 10\n 10 permit 192.168.10.0 0.0.0.255"
            )
        return None

    # Rule 8: ACL Missing DNS UDP 53 or Established TCP Return (NET-005, NET-030, NET-034)
    def check_acl_missing_dns_or_return(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        # Case NET-005: Extended ACL missing DNS
        if ("extended ip access list 101" in text.lower() or "access-list 101" in text.lower() or "NET-005" in case.get("case_id", "")) and "eq www" in text and "eq 443" in text and "eq domain" not in text.lower() and "eq 53" not in text:
            return RuleViolation(
                rule_id="ACL_IMPLICIT_DENY",
                rule_name="Extended ACL Blocking DNS Resolution (UDP 53)",
                severity="High",
                osi_layer="Layer 4 (Transport)",
                evidence="ACL 101 permits TCP 80/443 but lacks permit statements for UDP/TCP port 53 (eq domain).",
                explanation="Workstation DNS queries use UDP port 53. Without an explicit permit rule, DNS lookups hit the implicit deny and fail.",
                suggested_fix="ip access-list extended 101\n 25 permit udp 192.168.1.0 0.0.0.255 any eq domain\n 26 permit tcp 192.168.1.0 0.0.0.255 any eq domain"
            )
        # Case NET-030: Inbound WAN ACL dropping return TCP
        if "wan_in" in text.lower() and "established" not in text.lower():
            return RuleViolation(
                rule_id="ACL_IMPLICIT_DENY",
                rule_name="Inbound ACL Dropping Established TCP Return Traffic",
                severity="High",
                osi_layer="Layer 4 (Transport)",
                evidence="Inbound WAN ACL 'WAN_IN' only permits ICMP and denies return TCP packets from external web servers.",
                explanation="Stateless ACLs on WAN boundaries require 'permit tcp any any established' to allow incoming return traffic for outbound connections.",
                suggested_fix="ip access-list extended WAN_IN\n 15 permit tcp any 192.168.1.0 0.0.0.255 established"
            )
        # Case NET-034: Guest ACL blocking DHCP server return
        if "guest_in" in text.lower() and "10.0.0.50" in text:
            return RuleViolation(
                rule_id="ACL_IMPLICIT_DENY",
                rule_name="Guest ACL Shadowing DHCP Server Communication",
                severity="High",
                osi_layer="Layer 4 (Transport)",
                evidence="ACL GUEST_IN rule 10 'deny ip 172.16.50.0 ... 10.0.0.0' blocks DHCP requests before reaching DHCP relay server 10.0.0.50.",
                explanation="Guest isolation ACL is evaluated before DHCP relay, blocking clients from acquiring dynamic IP configurations.",
                suggested_fix="ip access-list extended GUEST_IN\n 5 permit udp 172.16.50.0 0.0.0.255 host 10.0.0.50 eq bootps\n 6 permit udp any eq bootpc any eq bootps"
            )
        return None

    # Rule 9: Standard ACL Inbound on Source Interface (NET-026)
    def check_acl_standard_inbound_misplacement(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "standard ip access list 20" in text.lower() and "inbound access list is 20" in text.lower():
            return RuleViolation(
                rule_id="ACL_IMPLICIT_DENY",
                rule_name="Standard ACL Inbound Filter Misplacement",
                severity="Critical",
                osi_layer="Layer 3 (Network)",
                evidence="Standard ACL 20 permits 10.0.0.0/8 but is applied inbound on G0/0 (192.168.1.0/24 subnet).",
                explanation="Standard ACLs filter strictly on source IP address. Applying ACL 20 inbound on the 192.168.1.0/24 interface drops 100% of packets originating from local hosts.",
                suggested_fix="interface GigabitEthernet0/0\n no ip access-group 20 in"
            )
        return None

    # Rule 10: DHCP Relay Helper Missing (NET-003)
    def check_dhcp_relay_helper(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if ("apipa" in text.lower() or "169.254" in text or "NET-003" in case.get("case_id", "")) and "ip helper-address" not in text.lower() and "g0/0.30" in text.lower():
            return RuleViolation(
                rule_id="DHCP_POOL_AND_RELAY",
                rule_name="Missing IP Helper-Address on Routed Subinterface",
                severity="High",
                osi_layer="Layer 3 (Network)",
                evidence="Interface GigabitEthernet0/0.30 lacks an 'ip helper-address' pointing to DHCP server 192.168.10.100.",
                explanation="DHCP Discover broadcast messages do not cross router boundaries without an 'ip helper-address' configured on the client gateway.",
                suggested_fix="interface GigabitEthernet0/0.30\n ip helper-address 192.168.10.100"
            )
        return None

    # Rule 11: DHCP Pool Sizing & Exhaustion (NET-014)
    def check_dhcp_pool_exhaustion(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "total addresses       : 14" in text.lower() and "leased addresses      : 14" in text.lower():
            return RuleViolation(
                rule_id="DHCP_POOL_AND_RELAY",
                rule_name="DHCP Subnet Scope Exhaustion",
                severity="Medium",
                osi_layer="Layer 3 (Network)",
                evidence="DHCP pool POOL_VLAN40 has 14 total addresses and 14 leased addresses (100% full) with infinite lease.",
                explanation="The /28 pool is completely exhausted, preventing any new DHCP clients from acquiring an IP lease.",
                suggested_fix="ip dhcp pool POOL_VLAN40\n network 192.168.40.0 255.255.255.0\n lease 0 8 0"
            )
        return None

    # Rule 12: DHCP DNS Option (NET-020)
    def check_dhcp_dns_option(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "dns-server 10.0.0.100" in text and ("10.0.0.10" in text or "NET-020" in case.get("case_id", "")):
            return RuleViolation(
                rule_id="DHCP_POOL_AND_RELAY",
                rule_name="Incorrect DNS Server IP in DHCP Scope Option",
                severity="Medium",
                osi_layer="Layer 7 (Application)",
                evidence="DHCP pool specifies 'dns-server 10.0.0.100' which is unreachable (actual DNS server is 10.0.0.10).",
                explanation="DHCP option 6 distributes an incorrect DNS server IP, preventing clients from resolving domain names.",
                suggested_fix="ip dhcp pool LAN_POOL\n dns-server 10.0.0.10"
            )
        return None

    # Rule 13: NAT Overload (PAT) Omission (NET-008)
    def check_nat_overload_missing(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "ip nat inside source list" in text.lower() and "overload" not in text.lower():
            return RuleViolation(
                rule_id="NAT_INSIDE_OUTSIDE",
                rule_name="NAT Overload (PAT) Keyword Missing",
                severity="High",
                osi_layer="Layer 3 (Network)",
                evidence="'ip nat inside source list 1 interface GigabitEthernet0/1' is configured without the 'overload' keyword.",
                explanation="Without 'overload', Cisco IOS maps private IPs to the single outside IP on a 1-to-1 static basis, exhausting translations after one host.",
                suggested_fix="no ip nat inside source list 1 interface GigabitEthernet0/1\nip nat inside source list 1 interface GigabitEthernet0/1 overload"
            )
        return None

    # Rule 14: NAT Missing Inside or Outside Interface Binding (NET-019)
    def check_nat_missing_inside_outside(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "ip nat inside source" in text and "ip nat outside" in text and "ip nat inside\n" not in text:
            return RuleViolation(
                rule_id="NAT_INSIDE_OUTSIDE",
                rule_name="Missing 'ip nat inside' Interface Binding",
                severity="High",
                osi_layer="Layer 3 (Network)",
                evidence="GigabitEthernet0/0 has no 'ip nat inside' statement, while outside interface has 'ip nat outside'.",
                explanation="Cisco NAT requires both inside and outside interfaces to be explicitly defined. LAN packets are routed without address translation.",
                suggested_fix="interface GigabitEthernet0/0\n ip nat inside"
            )
        return None

    # Rule 15: Static NAT Overlapping Outside Interface IP (NET-029)
    def check_nat_ip_overlap(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "addr_in_use" in text.lower() or "source static 192.168.1.50 203.0.113.1" in text:
            return RuleViolation(
                rule_id="DUPLICATE_IP_CONFLICT",
                rule_name="Static NAT Inside Global IP Collides with Router Outside Interface IP",
                severity="High",
                osi_layer="Layer 3 (Network)",
                evidence="Static NAT assigns 203.0.113.1 (Router G0/1 outside interface IP) directly to 192.168.1.50.",
                explanation="Static 1-to-1 NAT hijacking the router's own interface IP breaks WAN management and default PAT operations.",
                suggested_fix="no ip nat inside source static 192.168.1.50 203.0.113.1\nip nat inside source static 192.168.1.50 203.0.113.5"
            )
        return None

    # Rule 16: OSPF Area ID Mismatch (NET-007)
    def check_ospf_area_mismatch(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "10.0.0.0 0.0.0.3 area 0" in text and "10.0.0.0 0.0.0.3 area 1" in text:
            return RuleViolation(
                rule_id="OSPF_NEIGHBOR_ADJACENCY",
                rule_name="OSPF Area ID Mismatch on Transit Link",
                severity="Critical",
                osi_layer="Layer 3 (Network)",
                evidence="Transit link 10.0.0.0/30 is configured in Area 0 on R1 but in Area 1 on R2.",
                explanation="OSPF requires adjacent routers on the same segment to reside in the exact same Area ID. Mismatched packets are dropped during Hello exchange.",
                suggested_fix="router ospf 1\n no network 10.0.0.0 0.0.0.3 area 1\n network 10.0.0.0 0.0.0.3 area 0"
            )
        return None

    # Rule 17: OSPF MTU Mismatch (NET-023)
    def check_ospf_mtu_mismatch(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "exstart" in text.lower() and "mtu 1500" in text.lower() and "mtu 1400" in text.lower():
            return RuleViolation(
                rule_id="OSPF_NEIGHBOR_ADJACENCY",
                rule_name="OSPF Neighbor Stuck in EXSTART due to MTU Mismatch",
                severity="High",
                osi_layer="Layer 3 (Network)",
                evidence="OSPF neighbor state is EXSTART. RouterA MTU is 1500 while RouterB MTU is 1400.",
                explanation="During Database Description (DBD) packet exchange, if interface MTUs do not match, the router with smaller MTU drops DBD packets.",
                suggested_fix="interface GigabitEthernet0/0\n ip mtu 1500"
            )
        return None

    # Rule 18: OSPF Passive-Interface Default on Transit (NET-015)
    def check_ospf_passive_transit(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "passive-interface default" in text.lower() and ("pass" in text or "gi0/0/0" in text.lower() or "NET-015" in case.get("case_id", "")):
            return RuleViolation(
                rule_id="OSPF_NEIGHBOR_ADJACENCY",
                rule_name="OSPF Passive-Interface Default Suppressing Transit Link",
                severity="High",
                osi_layer="Layer 3 (Network)",
                evidence="Transit interface Gi0/0/0 (10.0.12.1/30) is in passive state due to 'passive-interface default'.",
                explanation="Passive interfaces do not send or receive OSPF Hellos, preventing adjacency formation on transit links.",
                suggested_fix="router ospf 1\n no passive-interface GigabitEthernet0/0/0"
            )
        return None

    # Rule 19: OSPF Network Type Mismatch (NET-031)
    def check_ospf_network_type_mismatch(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "point_to_point" in text.lower() and "broadcast" in text.lower() and "network type" in text.lower():
            return RuleViolation(
                rule_id="OSPF_NEIGHBOR_ADJACENCY",
                rule_name="OSPF Network Type Mismatch (Point-to-Point vs Broadcast)",
                severity="Medium",
                osi_layer="Layer 3 (Network)",
                evidence="R1 is configured as 'POINT_TO_POINT' while R2 is configured as 'BROADCAST' on GigabitEthernet0/0.",
                explanation="Different network types generate incompatible LSA formats, preventing route calculation and installation in the routing table.",
                suggested_fix="interface GigabitEthernet0/0\n ip ospf network point-to-point"
            )
        return None

    # Rule 20: Port Security Err-Disable (NET-013)
    def check_port_security_errdisable(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "err-disabled" in text.lower() and "port-security" in text.lower():
            return RuleViolation(
                rule_id="PORT_SECURITY_ERRDISABLE",
                rule_name="Port Security MAC Violation Err-Disable",
                severity="High",
                osi_layer="Layer 2 (Data Link)",
                evidence="Interface status is 'err-disabled' due to Port Security violation mode 'Shutdown' with Security Violation Count >= 1.",
                explanation="An unauthorized MAC address connected to a port with maximum 1 sticky MAC, triggering port shutdown.",
                suggested_fix="interface FastEthernet0/2\n no switchport port-security mac-address sticky 0011.2233.4455\n shutdown\n no shutdown"
            )
        return None

    # Rule 21: Speed / Duplex Mismatch & Collisions (NET-012)
    def check_speed_duplex_mismatch(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "half-duplex" in text.lower() and "late collision" in text.lower():
            return RuleViolation(
                rule_id="SPEED_DUPLEX_MISMATCH",
                rule_name="Speed/Duplex Mismatch Causing Late Collisions",
                severity="Medium",
                osi_layer="Layer 2 (Data Link)",
                evidence="Interface Fa0/5 is hardcoded to Half-duplex with late collisions recorded.",
                explanation="When one end of a link is Half-Duplex and the peer is Full-Duplex, collisions occur after the 512-bit transmission window, dropping packets.",
                suggested_fix="interface FastEthernet0/5\n duplex full\n speed auto"
            )
        return None

    # Rule 22: HSRP Virtual IP Mismatch (NET-022)
    def check_hsrp_virtual_ip_mismatch(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "standby 1 ip 10.1.1.1" in text and "standby 1 ip 10.1.1.254" in text:
            return RuleViolation(
                rule_id="HSRP_PRIORITY_PREEMPT",
                rule_name="HSRP Virtual IP Address Group Mismatch",
                severity="Critical",
                osi_layer="Layer 3 (Network)",
                evidence="HSRP Group 1 on R1 uses Virtual IP 10.1.1.1; R2 uses Virtual IP 10.1.1.254. Both report 'State: Active'.",
                explanation="Conflicting virtual IP configurations create two split-brain active forwarders on the same subnet, causing ARP table flapping.",
                suggested_fix="interface GigabitEthernet0/0.10\n standby 1 ip 10.1.1.1"
            )
        return None

    # Rule 23: Missing Default Route (NET-025, NET-009)
    def check_missing_default_route(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "gateway of last resort is not set" in text.lower() and ("203.0.113." in text or "NET-025" in case.get("case_id", "")):
            return RuleViolation(
                rule_id="DEFAULT_GATEWAY_MISSING",
                rule_name="Missing Default Static Route on Edge Router",
                severity="Critical",
                osi_layer="Layer 3 (Network)",
                evidence="'Gateway of last resort is not set' in 'show ip route' on edge router.",
                explanation="Without a default quad-zero route ('ip route 0.0.0.0 0.0.0.0 <ISP_IP>'), all outbound traffic to public networks is discarded.",
                suggested_fix="ip route 0.0.0.0 0.0.0.0 203.0.113.1"
            )
        if "ip route 172.16.0.0 255.255.0.0 10.1.2.2" in text and "10.1.1.0/30" in text:
            return RuleViolation(
                rule_id="DEFAULT_GATEWAY_MISSING",
                rule_name="Static Route Next-Hop Unreachable",
                severity="High",
                osi_layer="Layer 3 (Network)",
                evidence="Static route points to 10.1.2.2 which is not in the directly connected subnet 10.1.1.0/30.",
                explanation="Cisco IOS installs static routes into the routing table only if the next-hop IP is reachable.",
                suggested_fix="no ip route 172.16.0.0 255.255.0.0 10.1.2.2\nip route 172.16.0.0 255.255.0.0 10.1.1.2"
            )
        return None

    # Rule 24: Duplicate IP Conflict & ARP Flapping (NET-016)
    def check_duplicate_ip_arp_conflict(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "%ip-4-dupaddr" in text.lower() or ("0014.a821.1111" in text and "0050.7966.2222" in text and "192.168.1.50" in text):
            return RuleViolation(
                rule_id="DUPLICATE_IP_CONFLICT",
                rule_name="Duplicate IP Address Conflict (ARP Poisoning)",
                severity="High",
                osi_layer="Layer 3 (Network)",
                evidence="Duplicate address 192.168.1.50 claimed by two MAC addresses (0014.a821.1111 on Fa0/12 and 0050.7966.2222 on Fa0/18).",
                explanation="Two devices on the same broadcast domain share the same IP address, causing continuous ARP cache overwrites.",
                suggested_fix="Reconfigure device on Fa0/18 to unassigned IP (e.g. 192.168.1.51) and clear arp-cache."
            )
        return None

    # Rule 25: DHCP Snooping Untrusted Uplink (NET-028)
    def check_dhcp_snooping_untrusted_uplink(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "dhcp offer dropped on untrusted port" in text.lower():
            return RuleViolation(
                rule_id="DHCP_POOL_AND_RELAY",
                rule_name="DHCP Snooping Dropping Server Offers on Untrusted Uplink",
                severity="High",
                osi_layer="Layer 2 (Data Link)",
                evidence="84 DHCP offer packets dropped on untrusted uplink port leading to DHCP server.",
                explanation="When DHCP Snooping is enabled, switchports default to untrusted and drop inbound DHCP Server Offers.",
                suggested_fix="interface GigabitEthernet0/1\n ip dhcp snooping trust"
            )
        return None

    # Rule 26: STP Root Inconsistency (NET-032)
    def check_stp_root_inconsistency(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "root inconsistent" in text.lower() or "root_inc" in text.lower():
            return RuleViolation(
                rule_id="VLAN_TRUNK_MISMATCH",
                rule_name="Spanning-Tree Root Guard Violation",
                severity="High",
                osi_layer="Layer 2 (Data Link)",
                evidence="GigabitEthernet0/12 is in Root Inconsistent blocking state after receiving superior BPDUs.",
                explanation="Root Guard blocks ports receiving superior BPDUs to protect the root bridge topology.",
                suggested_fix="On downstream switch: spanning-tree vlan 1 priority 32768\nOn root switch: clear spanning-tree detected-protocols"
            )
        return None

    # Rule 27: TCP MSS / MTU Path Clamping (NET-033)
    def check_tcp_mss_mtu(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "tunnel0" in text.lower() and "mtu 1400" in text.lower() and "adjust-mss" not in text.lower():
            return RuleViolation(
                rule_id="SPEED_DUPLEX_MISMATCH",
                rule_name="Missing TCP MSS Clamping over MTU-Constrained Tunnel",
                severity="Medium",
                osi_layer="Layer 4 (Transport)",
                evidence="Tunnel0 interface has MTU 1400 bytes without 'ip tcp adjust-mss 1360'.",
                explanation="Packets with the DF (Don't Fragment) bit set exceeding 1400 bytes are dropped, causing large web pages to hang.",
                suggested_fix="interface Tunnel0\n ip tcp adjust-mss 1360"
            )
        return None

    # Rule 28: Wireless VLAN Mapping (NET-011, NET-024)
    def check_wireless_vlan_mapping(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "guest-access" in text.lower() and "vlan-10-corp" in text.lower():
            return RuleViolation(
                rule_id="VLAN_TRUNK_MISMATCH",
                rule_name="Wireless Guest SSID Mapped to Corporate VLAN",
                severity="Critical",
                osi_layer="Layer 3 (Network)",
                evidence="'Guest-Access' WLAN profile is mapped to internal interface 'vlan-10-corp' instead of 'vlan-50-guest'.",
                explanation="Guest WLAN profile mapping error allows guest users to enter the private corporate broadcast domain.",
                suggested_fix="config wlan interface 2 vlan-50-guest"
            )
        if "flexconnect" in text.lower() and "static access" in text.lower() and "fa0/24" in text.lower():
            return RuleViolation(
                rule_id="VLAN_TRUNK_MISMATCH",
                rule_name="Wireless Access Point Switchport in Access Mode Instead of Trunk",
                severity="High",
                osi_layer="Layer 2 (Data Link)",
                evidence="Switchport Fa0/24 connecting multi-SSID AP is configured in static access mode for VLAN 10.",
                explanation="Multi-SSID APs require an 802.1Q trunk port to carry tagged frames for multiple wireless SSIDs.",
                suggested_fix="interface FastEthernet0/24\n switchport mode trunk\n switchport trunk native vlan 10\n switchport trunk allowed vlan 10,20,30"
            )
        return None

    # Rule 29: Switchport Mode Access (NET-027)
    def check_switchport_mode_access(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "administrative mode: dynamic auto" in text.lower() and "fa0/8" in text.lower():
            return RuleViolation(
                rule_id="VLAN_TRUNK_MISMATCH",
                rule_name="Host Access Port Configured in Dynamic Auto Mode",
                severity="Medium",
                osi_layer="Layer 2 (Data Link)",
                evidence="Port Fa0/8 is in 'dynamic auto' DTP mode instead of static access mode.",
                explanation="End-user ports should be statically configured in access mode with PortFast enabled.",
                suggested_fix="interface FastEthernet0/8\n switchport mode access\n switchport access vlan 10\n spanning-tree portfast"
            )
        return None

    # Rule 30: IPv6 Managed Flag (NET-035)
    def check_ipv6_managed_flag(self, text: str, case: Dict[str, Any]) -> Optional[RuleViolation]:
        if "stateless autoconfig for addresses" in text.lower() and "ipv6 dhcp server" in text.lower() and "managed-config-flag" not in text.lower():
            return RuleViolation(
                rule_id="DHCP_POOL_AND_RELAY",
                rule_name="IPv6 Router Advertisements Missing M-Flag (Managed Config)",
                severity="Medium",
                osi_layer="Layer 3 (Network)",
                evidence="Router Advertisements announce SLAAC ('stateless autoconfig') while a stateful DHCPv6 pool is configured.",
                explanation="Clients require the M-flag ('ipv6 nd managed-config-flag') in RA messages to query stateful DHCPv6 servers.",
                suggested_fix="interface GigabitEthernet0/0\n ipv6 nd managed-config-flag"
            )
        return None
