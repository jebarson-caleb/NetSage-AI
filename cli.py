"""
ObsidianTrace: Command Line Interface (CLI)
Interactive and Batch Network Troubleshooting Helper for Cisco Packet Tracer Labs.
Powered by Groq High-Speed LLM Inference (Llama 3.3 70B / Llama 3.1 8B) & Local CCIE Expert Engine.
"""

import sys
import os
import json
import argparse
from engine.ai_engine import DiagnosticEngine
from engine.rule_checker import NetworkRuleChecker
from engine.human_review import HumanReviewManager
from engine.simulator import CiscoTerminalSimulator

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def print_banner():
    banner = r"""
  _   _      _   ____                    _    ___ 
 | \ | | ___| |_/ ___|  __ _  __ _  ___  / \  |_ _|
 |  \| |/ _ \ __\___ \ / _` |/ _` |/ _ \/ _ \  | | 
 | |\  |  __/ |_ ___) | (_| | (_| |  __/ ___ \ | | 
 |_| \_|\___|\__|____/ \__,_|\__, |\___/_/   \_\___|
                             |___/                  
   Cisco Packet Tracer Troubleshooting AI Assistant (Groq Powered)
   Mandatory Safety Rule: Human-in-the-Loop Review Active
"""
    print(banner)

def load_dataset():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(base_dir, "data", "cases.json")
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)

def run_case_diagnosis(case_id, engine, cases_by_id, use_llm=True, model=None):
    if case_id not in cases_by_id:
        print(f"[ERROR] Case '{case_id}' not found in dataset. Available: {', '.join(list(cases_by_id.keys())[:10])}...")
        return
    case = cases_by_id[case_id]
    print(f"\n=======================================================")
    print(f"DIAGNOSING [{case['case_id']}] : {case['title']}")
    print(f"Domain: {case['domain']} | OSI: {case['osi_layer']} | Severity: {case['severity']}")
    print(f"Symptom: {case['symptom']}")
    print(f"=======================================================")

    diag = engine.diagnose_case(case, use_llm=use_llm, model=model)
    
    print("\n--- [1] PRE-SCAN DETERMINISTIC RULE CHECKER ---")
    if diag["rule_checker_pre_scan"]["has_violations"]:
        for v in diag["rule_checker_pre_scan"]["violations"]:
            print(f"  [!] Violation Flag: {v['rule_name']} ({v['rule_id']})")
            print(f"      Layer: {v['osi_layer']} | Severity: {v['severity']}")
            print(f"      Evidence: {v['evidence']}")
    else:
        print("  [OK] No static configuration violations flagged.")

    print(f"\n--- [2] AI DIAGNOSTIC REASONING ({diag.get('ai_provider_used', 'Local CCIE')}) ---")
    print(f"Fault Summary : {diag['fault_summary']}")
    print(f"OSI Layer     : {diag['osi_layer']}")
    print(f"Confidence    : {int(diag['confidence']*100)}%")
    print(f"Root Cause    :\n  {diag['root_cause']}")

    print("\nEvidence Citations:")
    for cit in diag.get("evidence_citations", []):
        print(f"  * {cit}")

    print("\nRecommended Next Commands:")
    for cmd in diag.get("next_recommended_commands", []):
        print(f"  # {cmd}")

    print("\n--- [3] PROPOSED REMEDIATION SCRIPT (Requires Human Review) ---")
    print(diag.get("remediation_cli_script", ""))
    print(f"\nRisk Level : {diag.get('risk_level', 'Low')} | Rollback: {diag.get('rollback_procedure', '')}")
    print("[!] Mandatory Human Review: Test commands in Packet Tracer before applying to real hardware.")


def run_interactive_chat(engine, model=None):
    print("\n=== INTERACTIVE CISCO PACKET TRACER TROUBLESHOOTING ASSISTANT ===")
    print("Type your Packet Tracer lab symptom or paste CLI show commands.")
    print("Type 'exit' or 'quit' to end session. Type 'sample' for a demo scenario.\n")

    history = []
    while True:
        try:
            user_input = input("\n[Packet-Tracer-Lab] >> ")
            if not user_input.strip():
                continue
            if user_input.strip().lower() in ['exit', 'quit', 'q']:
                print("Exiting troubleshooting session.")
                break
            if user_input.strip().lower() == 'sample':
                user_input = "PC-2 in VLAN 20 cannot ping default gateway 192.168.20.1 on Router subinterface G0/0.20."
                print(f"[Sample Query]: {user_input}")

            print("\nAnalyzing with ObsidianTrace & Groq Engine...")
            res = engine.troubleshoot_chat(
                user_message=user_input,
                history=history,
                model=model
            )
            print("\n" + res["reply"])
            history.append({"role": "user", "content": user_input})
            history.append({"role": "assistant", "content": res["reply"]})

        except KeyboardInterrupt:
            print("\nSession interrupted.")
            break

def run_all_cases(engine, cases, use_llm=False, model=None):
    print("\n[BATCH EVALUATION] Running ObsidianTrace against all 35 Lab Cases...\n")
    header = f"{'Case ID':<9} | {'Domain':<22} | {'OSI Layer':<12} | {'AI Confidence':<14} | {'Deterministic Pre-Check':<24} | {'Status'}"
    print(header)
    print("-" * len(header))

    rule_hits = 0
    total = len(cases)
    for c in cases:
        diag = engine.diagnose_case(c, use_llm=use_llm, model=model)
        rule_flag = "FLAGGED (" + diag["rule_checker_pre_scan"]["violations"][0]["rule_id"][:12] + ")" if diag["rule_checker_pre_scan"]["has_violations"] else "CLEAN"
        if diag["rule_checker_pre_scan"]["has_violations"]:
            rule_hits += 1
        conf_str = f"{int(diag['confidence']*100)}%"
        print(f"{c['case_id']:<9} | {c['domain'][:22]:<22} | {c['osi_layer'][:12]:<12} | {conf_str:<14} | {rule_flag:<24} | READY FOR REVIEW")

    print("-" * len(header))
    print(f"\nCompleted: {total}/{total} cases evaluated.")
    print(f"Deterministic Rule Hit Rate : {(rule_hits/total)*100:.1f}% ({rule_hits}/{total})")
    print(f"AI Diagnostic Coverage      : 100.0% ({total}/{total})")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="ObsidianTrace: Cisco Packet Tracer Troubleshooting Assistant")
    parser.add_argument("--case", type=str, help="Diagnose a specific case (e.g. NET-001)")
    parser.add_argument("--chat", action="store_true", help="Launch interactive Cisco Packet Tracer chat assistant in terminal")
    parser.add_argument("--run-all", action="store_true", help="Run batch diagnosis over all 35 lab cases")
    parser.add_argument("--stats", action="store_true", help="Show human review statistics and agreement metrics")
    parser.add_argument("--provider", type=str, default="groq", help="LLM Provider: groq (default), local, gemini, openai")
    parser.add_argument("--model", type=str, default="openai/gpt-oss-120b", help="Groq / LLM Model: openai/gpt-oss-120b, openai/gpt-oss-20b, qwen/qwen3.6-27b")
    parser.add_argument("--groq-key", type=str, help="Groq API Key (or set GROQ_API_KEY environment variable)")

    
    args = parser.parse_args()
    
    cases = load_dataset()
    cases_by_id = {c["case_id"]: c for c in cases}
    engine = DiagnosticEngine(
        api_key=args.groq_key,
        provider=args.provider,
        model_name=args.model
    )
    review_manager = HumanReviewManager()

    if args.chat:
        run_interactive_chat(engine, model=args.model)
    elif args.case:
        run_case_diagnosis(args.case, engine, cases_by_id, use_llm=True, model=args.model)
    elif args.run_all:
        run_all_cases(engine, cases, use_llm=False, model=args.model)
    elif args.stats:
        stats = review_manager.get_stats(len(cases))
        print("\n--- HUMAN REVIEW & AI AGREEMENT METRICS ---")
        for k, v in stats.items():
            print(f"  {k.replace('_', ' ').title()}: {v}")
    else:
        # Default behavior: run all summary
        run_all_cases(engine, cases, use_llm=False, model=args.model)
        print("\nTip:")
        print("  * Run 'python cli.py --chat' for interactive Cisco Packet Tracer lab troubleshooting.")
        print("  * Run 'python cli.py --case NET-001' to diagnose a specific scenario.")
        print("  * Launch the web dashboard at http://localhost:8000 via 'python web/server.py'.")

if __name__ == "__main__":
    main()

