#!/usr/bin/env python3
"""The schema guard: the risk model must never authorise.

Fails the build if any field or enum value in proto/risk.proto contains a
token that grants authority. See docs/threat-model.md T8 (the rule) and T14
(why this script also verifies its own subject exists).
"""
import re
import sys
from pathlib import Path

RISK_DIR = Path(__file__).resolve().parent.parent / "proto" / "aiauth" / "risk"
FORBIDDEN = ("allow", "deny", "decision", "permit", "authorize", "authorise", "grant", "verdict")

def main() -> int:
    # T14: the guard verifies its subject exists — a deleted contract must
    # fail loudly, not pass because there was nothing to check.
    protos = sorted(RISK_DIR.rglob("*.proto")) if RISK_DIR.is_dir() else []
    if not protos:
        print(f"GUARD FAIL: no .proto files under {RISK_DIR} — the contract the guard protects is gone.")
        return 1
    text = chr(10).join(f.read_text(encoding="utf-8") for f in protos)
    text = re.sub(r"//[^\n]*", "", text)  # strip comments

    # Any identifier assigned a field/enum number — `name = N;` — regardless of
    # line layout. Anchoring to line starts let a single-line
    # `message Sneaky { bool allow_login = 1; }` slip past; this form does not.
    names = re.findall(r"(\w+)\s*=\s*\d+\s*;", text)

    bad = [n for n in names if any(tok in n.lower() for tok in FORBIDDEN)]
    if bad:
        print("GUARD FAIL: authorising field(s) in RiskAssessment:", ", ".join(sorted(set(bad))))
        print("The risk model is advisory. It must never authorise. See docs/threat-model.md T8.")
        return 1
    print(f"guard ok: {len(protos)} files, {len(set(names))} identifiers checked, none grant authority")
    return 0

if __name__ == "__main__":
    sys.exit(main())
