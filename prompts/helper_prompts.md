# NetSage AI: Helper Prompt Templates

This library provides specialized sub-prompts for modular diagnostic tasks.

---

## 1. ACL Syntax & Wildcard Analysis Prompt (`acl_analyzer.md`)

```markdown
You are analyzing a Cisco Access Control List for logical flaws.
Given the ACL rules and the target traffic flow:
1. Identify any inverted wildcard masks (e.g. using 255.255.255.0 instead of 0.0.0.255).
2. Check if DNS (UDP 53), DHCP (UDP 67/68), or TCP return traffic (established) is blocked by implicit deny.
3. Check rule order (standard ACL placed too close to source or overly broad rule shadowing specific rule).

Input ACL:
{{ACL_CONFIG}}

Target Traffic:
{{TRAFFIC_DESCRIPTION}}

Output Format:
- Flaw Detected: [Yes/No]
- Affected Line: [Line number and text]
- Correction: [Exact Cisco CLI command]
```

---

## 2. OSPF Adjacency Triage Prompt (`ospf_triage.md`)

```markdown
You are diagnosing an OSPF neighbor failure.
Check the following common causes in order:
1. Interface Subnet Mask mismatch
2. Area ID mismatch on transit link
3. Hello / Dead timer mismatch
4. MTU size mismatch during DBD exchange
5. Passive-interface applied to transit interface
6. Authentication key mismatch

Provided Show Outputs:
{{OSPF_SHOW_OUTPUTS}}

Output Format:
- Failure Stage: [Down | Init | 2-Way | ExStart | Exchange | Loading | Full]
- Confirmed Root Cause: [Exact reason]
- Required CLI Fix: [Commands]
```

---

## 3. Human Review Correction Prompt (`human_correction_prompt.md`)

```markdown
A human network engineer has reviewed your initial diagnosis and marked it as EDITED or REJECTED with notes.
Analyze why the initial AI recommendation was incorrect or incomplete, and generate an updated diagnosis and learning note.

Initial AI Diagnosis:
{{INITIAL_DIAGNOSIS}}

Human Reviewer Feedback:
{{REVIEWER_NOTES}}

Task:
1. Explain the specific misunderstanding in the AI diagnosis.
2. Provide the corrected diagnosis that incorporates the engineer's feedback.
3. Save key learning for the Responsible AI Audit Log.
```
