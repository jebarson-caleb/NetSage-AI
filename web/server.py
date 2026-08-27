"""
NetSage AI: Web Backend REST API Server
Built with Python standard library ThreadingHTTPServer for zero-dependency instant execution.
Serves REST API endpoints for Packet Tracer AI diagnostics, Groq LLM reasoning, interactive chat, rule checks, human reviews, stats, and static UI assets.
"""

import sys
import os
import json
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn

# Add parent directory to path to import engine modules
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from engine.ai_engine import DiagnosticEngine
from engine.rule_checker import NetworkRuleChecker
from engine.human_review import HumanReviewManager

PACKET_TRACER_PRESETS = [
    {
        "id": "pt-roas-vlan",
        "title": "Router-on-a-Stick: Missing 802.1Q Encapsulation",
        "domain": "VLAN / Inter-VLAN Routing",
        "symptom": "PC-2 in VLAN 20 cannot ping its default gateway 192.168.20.1 or PC-1 in VLAN 10.",
        "topology": "Router R1 (ROAS) connected via trunk G0/0/0 to Catalyst 2960 Switch. PC-1 on Fa0/10 (VLAN 10), PC-2 on Fa0/20 (VLAN 20).",
        "pasted_cli": "Router# show running-config interface GigabitEthernet0/0/0.20\ninterface GigabitEthernet0/0/0.20\n ip address 192.168.20.1 255.255.255.0\n!\nRouter# show ip interface brief\nGigabitEthernet0/0/0       up                    up\nGigabitEthernet0/0/0.10    192.168.10.1    YES manual up                    up\nGigabitEthernet0/0/0.20    192.168.20.1    YES manual up                    up"
    },
    {
        "id": "pt-ospf-area",
        "title": "OSPF Multi-Area Mismatched Area ID",
        "domain": "OSPF Routing",
        "symptom": "OSPF adjacency stuck in INIT/DOWN between R1 (Core) and R2 (Distribution) across point-to-point link.",
        "topology": "R1 (Core Router) G0/0/1 (10.0.0.1/30) <---> R2 (Distribution Router) G0/0/1 (10.0.0.2/30).",
        "pasted_cli": "R1# show ip ospf interface GigabitEthernet0/0/1\nGigabitEthernet0/0/1 is up, line protocol is up\n  Internet Address 10.0.0.1/30, Area 0\n  Process ID 1, Router ID 1.1.1.1, Network Type BROADCAST, Cost: 1\n  Timer intervals configured, Hello 10, Dead 40, Wait 40, Retransmit 5\n\nR2# show ip ospf interface GigabitEthernet0/0/1\nGigabitEthernet0/0/1 is up, line protocol is up\n  Internet Address 10.0.0.2/30, Area 1\n  Process ID 1, Router ID 2.2.2.2, Network Type BROADCAST, Cost: 1\n  Timer intervals configured, Hello 10, Dead 40, Wait 40, Retransmit 5"
    },
    {
        "id": "pt-dhcp-helper",
        "title": "DHCP Relay: Missing IP Helper-Address",
        "domain": "DHCP / IPAM",
        "symptom": "Workstations in VLAN 30 fail to receive DHCP leases and get APIPA 169.254.x.x addresses.",
        "topology": "Central DHCP Server (192.168.10.100) in VLAN 10. Router R1 subinterface G0/0.30 serves VLAN 30 hosts.",
        "pasted_cli": "Router# show running-config interface GigabitEthernet0/0.30\ninterface GigabitEthernet0/0.30\n encapsulation dot1Q 30\n ip address 192.168.30.1 255.255.255.0\n!\nPC-3> ipconfig\nFastEthernet0 Connection:(default port)\n   Link-local IPv6 Address.........: FE80::260:47FF:FE11:2233\n   IP Address......................: 169.254.45.88\n   Subnet Mask.....................: 255.255.0.0\n   Default Gateway.................: 0.0.0.0"
    },
    {
        "id": "pt-nat-pat",
        "title": "NAT Overload (PAT) Keyword Omission",
        "domain": "NAT / PAT",
        "symptom": "Only one internal computer can browse the Internet at a time; other PCs receive connection timeouts.",
        "topology": "Branch Router R1 with G0/0 (LAN 192.168.1.0/24) and G0/1 (ISP WAN 203.0.113.2/30). Web Server at 8.8.8.8.",
        "pasted_cli": "Router# show running-config | include ip nat\nip nat inside source list 1 interface GigabitEthernet0/1\ninterface GigabitEthernet0/0\n ip nat inside\ninterface GigabitEthernet0/1\n ip nat outside\n!\nRouter# show access-lists 1\nStandard IP access list 1\n    10 permit 192.168.1.0 0.0.0.255"
    },
    {
        "id": "pt-port-security",
        "title": "Switchport Port Security Err-Disabled",
        "domain": "Switching / Security",
        "symptom": "Switch port Fa0/1 LED turned amber and host suddenly lost all network connectivity.",
        "topology": "Catalyst 2960 Switch connected to Engineering Workstation PC-A on interface FastEthernet0/1.",
        "pasted_cli": "Switch# show interfaces status err-disabled\nPort      Name               Status       Reason               Err-disable Vlans\nFa0/1                        err-disabled psecure-violation    1\n\nSwitch# show port-security interface FastEthernet0/1\nPort Security              : Enabled\nPort Status                : Secure-down\nViolation Mode             : Shutdown\nMaximum MAC Addresses      : 1\nTotal MAC Addresses        : 1\nConfigured MAC Addresses   : 0\nSticky MAC Addresses       : 1\nLast Source Address:Vlan   : 0001.965b.7788:1\nSecurity Violation Count   : 1"
    },
    {
        "id": "pt-acl-dns",
        "title": "Extended ACL Blocking DNS Queries",
        "domain": "ACL / Firewall",
        "symptom": "PCs can ping public IP 8.8.8.8 but cannot open websites by domain name (e.g. www.cisco.com).",
        "topology": "Edge Router R1 filtering outbound traffic on G0/0 with extended ACL 101.",
        "pasted_cli": "Router# show access-lists 101\nExtended IP access list 101\n    10 permit tcp 192.168.1.0 0.0.0.255 any eq www\n    20 permit tcp 192.168.1.0 0.0.0.255 any eq 443\n    30 permit icmp 192.168.1.0 0.0.0.255 any echo\n    40 deny ip any any (142 matches)"
    }
]

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class NetSageHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.engine = DiagnosticEngine()
        self.rule_checker = NetworkRuleChecker()
        self.review_manager = HumanReviewManager()
        self.data_file = os.path.join(BASE_DIR, "data", "cases.json")
        self.resp_ai_file = os.path.join(BASE_DIR, "logs", "responsible_ai_log.json")
        super().__init__(*args, directory=os.path.join(os.path.dirname(__file__), "static"), **kwargs)

    def _load_cases(self):
        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _load_resp_ai_log(self):
        try:
            with open(self.resp_ai_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        # API Routes
        if path == "/api/health":
            self._send_json({
                "status": "healthy",
                "service": "NetSage AI Cisco Packet Tracer Assistant",
                "version": "2.2",
                "default_provider": self.engine.provider,
                "groq_configured": bool(self.engine.api_key and "gsk" in self.engine.api_key)
            })
            return

        elif path == "/api/presets":
            self._send_json(PACKET_TRACER_PRESETS)
            return

        elif path == "/api/groq-status":
            auth_header = self.headers.get("Authorization", "")
            bearer_key = auth_header.replace("Bearer ", "").strip() if "Bearer " in auth_header else ""
            test_res = self.engine.test_groq_connection(api_key=bearer_key or None)
            self._send_json(test_res)
            return
            
        elif path == "/api/cases":
            cases = self._load_cases()
            self._send_json(cases)
            return

        elif path.startswith("/api/cases/"):
            case_id = path.split("/api/cases/")[-1]
            cases = self._load_cases()
            case = next((c for c in cases if c["case_id"] == case_id), None)
            if case:
                self._send_json(case)
            else:
                self._send_json({"error": "Case not found"}, 404)
            return

        elif path == "/api/stats":
            cases = self._load_cases()
            stats = self.review_manager.get_stats(len(cases))
            # Calculate domain breakdown and layer breakdown
            layer_counts = {}
            severity_counts = {}
            domain_counts = {}
            for c in cases:
                layer = c.get("osi_layer", "Layer 3")
                layer_counts[layer] = layer_counts.get(layer, 0) + 1
                sev = c.get("severity", "Medium")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                dom = c.get("domain", "General")
                domain_counts[dom] = domain_counts.get(dom, 0) + 1

            stats["layer_distribution"] = layer_counts
            stats["severity_distribution"] = severity_counts
            stats["domain_distribution"] = domain_counts
            self._send_json(stats)
            return

        elif path == "/api/reviews":
            self._send_json(self.review_manager.get_all_reviews())
            return

        elif path == "/api/responsible-ai-log":
            self._send_json(self._load_resp_ai_log())
            return

        elif path == "/api/export/csv":
            csv_path = os.path.join(BASE_DIR, "data", "cases.csv")
            try:
                with open(csv_path, "r", encoding="utf-8") as f:
                    csv_data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="cases.csv"')
                self.end_headers()
                self.wfile.write(csv_data.encode("utf-8"))
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # Fallback to static files
        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

        if path == "/api/chat":
            message = payload.get("message", "")
            history = payload.get("history", [])
            pasted_cli = payload.get("pasted_cli", "")
            topology = payload.get("topology", "")
            api_key = payload.get("api_key")
            model = payload.get("model")

            chat_res = self.engine.troubleshoot_chat(
                user_message=message,
                history=history,
                pasted_cli=pasted_cli,
                topology=topology,
                api_key=api_key,
                model=model
            )
            self._send_json(chat_res)
            return

        elif path == "/api/diagnose":
            # Can receive a case object or custom payload
            case_id = payload.get("case_id")
            if case_id:
                cases = self._load_cases()
                case = next((c for c in cases if c["case_id"] == case_id), payload)
            else:
                case = payload
            
            use_llm = payload.get("use_llm", True)
            api_key = payload.get("api_key")
            provider = payload.get("provider", "groq")
            model = payload.get("model")

            diag = self.engine.diagnose_case(
                case,
                use_llm=use_llm,
                api_key=api_key,
                provider=provider,
                model=model
            )
            self._send_json(diag)
            return

        elif path == "/api/rule-check":
            results = self.rule_checker.scan(payload)
            self._send_json(results)
            return

        elif path == "/api/review":
            case_id = payload.get("case_id")
            reviewer = payload.get("reviewer", "Lead Reviewer")
            decision = payload.get("decision", "Accepted")
            ai_diagnosis = payload.get("ai_diagnosis", {})
            edited_root_cause = payload.get("edited_root_cause")
            edited_cli_fix = payload.get("edited_cli_fix")
            reviewer_notes = payload.get("reviewer_notes")
            error_category = payload.get("error_category")

            try:
                review_record = self.review_manager.submit_review(
                    case_id=case_id,
                    reviewer=reviewer,
                    decision=decision,
                    ai_diagnosis=ai_diagnosis,
                    edited_root_cause=edited_root_cause,
                    edited_cli_fix=edited_cli_fix,
                    reviewer_notes=reviewer_notes,
                    error_category=error_category
                )
                self._send_json(review_record)
            except Exception as e:
                self._send_json({"error": str(e)}, 400)
            return

        self._send_json({"error": "Endpoint not found"}, 404)

def run_server(port=8000):
    server_address = ("", port)
    httpd = ThreadedHTTPServer(server_address, NetSageHandler)
    print(f"============================================================")
    print(f" NetSage AI Cisco Packet Tracer Troubleshooter Active")
    print(f" Web Platform Running at http://localhost:{port}")
    print(f" Groq AI Engine: Native Ultra-Fast Llama-3.3 Reasoning Enabled")
    print(f"============================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()

if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run_server(port)

