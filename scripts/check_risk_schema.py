#!/usr/bin/env python3
"""The schema guard: the risk model must never authorise.

Fails the build if any field or enum value in proto/risk.proto contains a
token that grants authority. See docs/threat-model.md T8 (the rule) and T14
(why this script also verifies its own subject exists).
"""
import re
import sys
from pathlib import Path

PROTO = Path(__file__).resolve().parent.parent / "proto" / "risk.proto"
FORBIDDEN = ("allow", "deny", "decision", "permit", "authorize", "authorise", "grant", "verdict")

def main() -> int:
    # T14: the guard verifies its subject exists — a deleted contract must
    # fail loudly, not pass because there was nothing to check.
    if not PROTO.is_file():
        print(f"GUARD FAIL: {PROTO} is missing — the contract the guard protects is gone.")
        return 1
    text = PROTO.read_text(encoding="utf-8")
    text = re.sub(r"//[^\n]*", "", text)  # strip comments

    names = []
    # field declarations:  [repeated|optional] <type> <name> = N;
    names += re.findall(r"^\s*(?:repeated\s+|optional\s+)?[\w.<>,\s]+?\s(\w+)\s*=\s*\d+\s*;", text, re.M)
    # enum values:  NAME = N;
    names += re.findall(r"^\s*([A-Z][A-Z0-9_]*)\s*=\s*\d+\s*;", text, re.M)

    bad = [n for n in names if any(tok in n.lower() for tok in FORBIDDEN)]
    if bad:
        print("GUARD FAIL: authorising field(s) in RiskAssessment:", ", ".join(sorted(set(bad))))
        print("The risk model is advisory. It must never authorise. See docs/threat-model.md T8.")
        return 1
    print(f"guard ok: {len(set(names))} identifiers checked, none grant authority")
    return 0

if __name__ == "__main__":
    sys.exit(main())
