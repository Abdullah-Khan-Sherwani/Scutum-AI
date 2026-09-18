# Plan/CLAUDE.md

Context for this folder. See the root `CLAUDE.md` for project-wide rules.

## What's here
- `Task1_Workflow_Design.md` — the submitted Task 1 workflow design write-up.
- `Task2_Execution_Report.md` — the Task 2 execution report, built directly
  from `agent/output/report.json` and `transcript.json` of a real run. Every
  finding, CVE, and CVSS score in it is copied from actual tool output, not
  written from memory or inferred.
- `Findings_Summary.txt` — the same findings as a flat, three-section ASCII
  table (web-layer/ZAP, dependency/SCA CVEs, agentic active-exploitation)
  for quick copy-paste into slides or a submission doc. Keep it in sync with
  `Task2_Execution_Report.md`/`report.json` if either changes.

## Folder-specific rules
- These are submitted deliverables with dates on them. Don't edit
  `Task1_Workflow_Design.md` to match later implementation changes made
  after submission — note any delta in the Task 2/3 report instead of
  rewriting history here.
- If you regenerate `Task2_Execution_Report.md` after a new run, re-pull the
  actual numbers from `agent/output/report.json` — don't hand-edit CVE IDs,
  CVSS scores, or Exploit-DB references, and don't attribute the run to any
  tool that wasn't actually used. This file was rebuilt once already after
  a version that falsely claimed a jailbreak tool ("Godmod 3") was used and
  invented Exploit-DB references that no real tool call produced — that is
  not acceptable in this repo under any framing.
- Section 7 (concept mapping) is written entirely by hand, without AI
  assistance — that's a hard rule from the assignment, not a style choice.
