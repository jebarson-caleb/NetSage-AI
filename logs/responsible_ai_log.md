# NetSage AI: Responsible AI Audit Log & Human Review Case Studies

> [!IMPORTANT]
> **Safety Rule Enforcement**: In enterprise network operations, AI recommendations must never be applied autonomously. This log documents **7 real-world troubleshooting scenarios** where initial AI diagnoses were caught, corrected, or rejected by human reviewers prior to deployment.

---

## Summary of AI Failure Modes & Human Interventions

| Case ID | Fault Domain | Initial AI Diagnosis & Failure Mode | Human Reviewer Correction | Error Taxonomy | Impact Avoided |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **NET-008** | NAT / PAT | AI suggested clearing NAT table and issuing `reload` to reset router memory. | Rejected reload; updated NAT statement to append `overload` keyword. | Unsafe / Destructive Command | Avoided unannounced router reboot and office-wide downtime. |
| **NET-018** | ACL / Security | AI suggested deleting entire ACL 10 with `no access-list 10` and rewriting from scratch. | Edited to use precise sequence line replacement (`10 permit 192.168.10.0 0.0.0.255`). | Over-Engineering / Teardown | Prevented brief open-access window during ACL replacement. |
| **NET-015** | OSPF Routing | AI suggested removing `passive-interface default` globally from OSPF process. | Preserved global hardening; applied `no passive-interface G0/0/0` to transit link only. | Security Baseline Degradation | Prevented rogue OSPF adjacency formation on all edge user ports. |
| **NET-003** | DHCP | AI recommended creating a local DHCP pool on the branch router. | Changed to `ip helper-address 192.168.10.100` to utilize centralized corporate DHCP. | Architecture Misalignment | Prevented split-brain DHCP pools and unmanaged IP assignment. |
| **NET-029** | NAT | AI suggested modifying the ISP-assigned WAN interface IP on G0/1. | Altered the inside global static NAT translation address to `203.0.113.5` from pool. | Dependency Inversion | Prevented WAN link disconnect and BGP neighbor tear-down. |
| **NET-022** | HSRP | AI diagnosed as a priority tuning issue and changed standby priority only. | Replaced mismatched virtual IP `10.1.1.254` with `10.1.1.1` on R2. | Superficial Symptom Treatment | Fixed active-active split-brain default gateway ARP oscillation. |
| **NET-034** | Wireless ACL | AI suggested removing `ip access-group GUEST_IN in` to fix DHCP boot failure. | Added targeted permit rules for UDP 67/68 before the corporate deny statement. | Security Guardrail Breach | Prevented guest Wi-Fi clients from accessing internal servers. |

---

## Detailed Incident Analysis

### Case Study 1: NET-008 — Destructive Command Hallucination (Router Reload)
- **Symptom**: Only the first internal client can browse the web; all subsequent clients fail.
- **Root Cause**: `ip nat inside source list 1 interface G0/1` was missing the `overload` keyword, restricting translation to 1 single host.
- **AI Hallucination**: The AI assumed a NAT translation state-table memory leak and suggested `clear ip nat translation *` followed by `reload`.
- **Reviewer Action**: The reviewer immediately rejected the reboot recommendation and edited the script to replace the NAT rule with `ip nat inside source list 1 interface G0/1 overload`.
- **Guardrail Added**: Implemented `_check_command_safety()` in `HumanReviewManager` that automatically flags dangerous commands (`reload`, `erase`, `format`).

---

### Case Study 2: NET-015 — Security Baseline Erosion vs Targeted Exemption
- **Symptom**: OSPF neighbor adjacency stuck on transit link G0/0/0.
- **Root Cause**: `passive-interface default` suppressed Hello exchange on all interfaces.
- **AI Blind Spot**: AI recommended disabling the security baseline entirely (`no passive-interface default`).
- **Human Correction**: Senior CCIE reviewer maintained standard CIS benchmark hardening by adding `no passive-interface GigabitEthernet0/0/0` under `router ospf 1`.
- **Key Insight**: AI systems tend toward permissive, blanket fixes unless prompted to maintain least-privilege security postures.

---

### Case Study 3: NET-034 — Security Guardrail Teardown
- **Symptom**: Guest Wi-Fi clients cannot obtain IP addresses from corporate DHCP relay.
- **Root Cause**: Inbound ACL on Guest VLAN subinterface dropped all traffic to corporate subnet `10.0.0.0/8`, including DHCP relay requests.
- **AI Failure**: Suggested removing the ACL to restore connectivity.
- **Human Correction**: Inserted `permit udp 172.16.50.0 0.0.0.255 host 10.0.0.50 eq bootps` at sequence line 5.
- **Policy Standard**: Remediation must never resolve availability at the cost of confidentiality and segmentation.
