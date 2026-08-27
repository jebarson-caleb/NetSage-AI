"""
NetSage AI: Command Line Interface (CLI)
Interactive and Batch Network Troubleshooting Helper for Cisco Packet Tracer Labs.
Powered by Groq High-Speed LLM Inference (Llama 3.3 70B / Llama 3.1 8B) & Local CCIE Expert Engine.
"""

import sys
import os
import json
import argparse
import contextlib
import io
from engine.ai_engine import DiagnosticEngine
from engine.human_review import HumanReviewManager

stdout_reconfigure = getattr(sys.stdout, "reconfigure", None)
if stdout_reconfigure:
    try:
        stdout_reconfigure(encoding="utf-8", errors="replace")
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
   Cisco Packet Tracer Troubleshooting AI Assistant (Local + Groq)
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
        return None
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
    return diag


def run_interactive_chat(engine, model=None, use_llm=True):
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

            print("\nAnalyzing with NetSage AI & Groq Engine...")
            res = engine.troubleshoot_chat(
                user_message=user_input,
                history=history,
                model=model,
                use_llm=use_llm
            )
            print("\n" + res["reply"])
            history.append({"role": "user", "content": user_input})
            history.append({"role": "assistant", "content": res["reply"]})

        except KeyboardInterrupt:
            print("\nSession interrupted.")
            break

def run_all_cases(engine, cases, use_llm=False, model=None):
    print(f"\n[BATCH EVALUATION] Running NetSage AI against all {len(cases)} Lab Cases...\n")
    header = f"{'Case ID':<9} | {'Domain':<22} | {'Severity':<9} | {'AI Confidence':<14} | {'Deterministic Pre-Check':<24} | {'Status'}"
    print(header)
    print("-" * len(header))

    rule_hits = 0
    total = len(cases)
    results = []
    confidence_total = 0.0
    for c in cases:
        diag = engine.diagnose_case(c, use_llm=use_llm, model=model)
        has_violations = diag["rule_checker_pre_scan"]["has_violations"]
        rule_flag = "FLAGGED (" + diag["rule_checker_pre_scan"]["violations"][0]["rule_id"][:12] + ")" if has_violations else "CLEAN"
        if has_violations:
            rule_hits += 1
        confidence = float(diag.get("confidence", 0.0))
        confidence_total += confidence
        results.append({
            "case_id": c["case_id"],
            "domain": c.get("domain", "General"),
            "severity": c.get("severity", "Medium"),
            "confidence": confidence,
            "rule_flagged": has_violations,
            "rule_id": diag["rule_checker_pre_scan"]["violations"][0]["rule_id"] if has_violations else None,
            "status": "READY FOR REVIEW"
        })
        conf_str = f"{int(confidence*100)}%"
        print(f"{c['case_id']:<9} | {c.get('domain', 'General')[:22]:<22} | {c.get('severity', 'Medium'):<9} | {conf_str:<14} | {rule_flag:<24} | READY FOR REVIEW")

    rule_rate = (rule_hits / total) * 100 if total else 0.0
    avg_confidence = (confidence_total / total) * 100 if total else 0.0
    summary = {
        "total": total,
        "rule_hits": rule_hits,
        "rule_hit_rate_pct": round(rule_rate, 1),
        "average_confidence_pct": round(avg_confidence, 1),
        "diagnostic_coverage_pct": 100.0 if total else 0.0
    }
    print("-" * len(header))
    print(f"\nCompleted: {total}/{total} cases evaluated.")
    print(f"Deterministic Rule Hit Rate : {rule_rate:.1f}% ({rule_hits}/{total})")
    print(f"Average AI Confidence       : {avg_confidence:.1f}%")
    print(f"AI Diagnostic Coverage      : {summary['diagnostic_coverage_pct']:.1f}% ({total}/{total})")
    return {"results": results, "summary": summary}

def main():
    parser = argparse.ArgumentParser(description="NetSage AI: Cisco Packet Tracer Troubleshooting Assistant")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--case", type=str, help="Diagnose a specific case (e.g. NET-001)")
    modes.add_argument("--chat", action="store_true", help="Launch interactive Cisco Packet Tracer chat assistant in terminal")
    modes.add_argument("--run-all", action="store_true", help="Run batch diagnosis over every case in the dataset")
    modes.add_argument("--stats", action="store_true", help="Show human review statistics and agreement metrics")
    parser.add_argument("--provider", choices=["groq", "local", "gemini", "openai"], default="local", help="LLM provider (default: local/offline)")
    parser.add_argument("--model", type=str, help="Cloud model name; defaults to the provider environment setting")
    parser.add_argument("--groq-key", type=str, help="Groq API Key (or set GROQ_API_KEY environment variable)")
    parser.add_argument("--no-llm", action="store_true", help="Force deterministic + local reasoning, even when a cloud key is configured")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of the human report")

    args = parser.parse_args()
    if args.json and args.chat:
        parser.error("--json cannot be combined with --chat because chat is interactive")
    if not args.json:
        print_banner()
    
    cases = load_dataset()
    cases_by_id = {c["case_id"]: c for c in cases}
    engine = DiagnosticEngine(
        api_key=args.groq_key,
        provider=args.provider,
        model_name=args.model
    )
    use_llm = not args.no_llm
    review_manager = HumanReviewManager()

    if args.chat:
        run_interactive_chat(engine, model=args.model, use_llm=use_llm)
    elif args.case:
        if args.case not in cases_by_id:
            message = {"error": f"Case '{args.case}' not found", "available_case_ids": list(cases_by_id)}
            if args.json:
                print(json.dumps(message, indent=2))
            else:
                print(f"[ERROR] {message['error']}. Available: {', '.join(message['available_case_ids'][:10])}...")
            return 2
        if args.json:
            with contextlib.redirect_stdout(io.StringIO()):
                diagnosis = run_case_diagnosis(args.case, engine, cases_by_id, use_llm=use_llm, model=args.model)
            print(json.dumps(diagnosis, indent=2))
        else:
            run_case_diagnosis(args.case, engine, cases_by_id, use_llm=use_llm, model=args.model)
    elif args.stats:
        stats = review_manager.get_stats(len(cases))
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print("\n--- HUMAN REVIEW & AI AGREEMENT METRICS ---")
            for k, v in stats.items():
                print(f"  {k.replace('_', ' ').title()}: {v}")
    else:
        if args.json:
            with contextlib.redirect_stdout(io.StringIO()):
                batch = run_all_cases(engine, cases, use_llm=use_llm, model=args.model)
            print(json.dumps(batch, indent=2))
        else:
            run_all_cases(engine, cases, use_llm=use_llm, model=args.model)
            print("\nTip:")
            print("  * Run 'python cli.py --chat' for interactive Cisco Packet Tracer lab troubleshooting.")
            print("  * Run 'python cli.py --case NET-001 --json' for automation-friendly output.")
            print("  * Use '--provider groq' only when GROQ_API_KEY is configured.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

