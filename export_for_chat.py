#!/usr/bin/env python3
"""Make a triage prompt from the latest TrendSAST scan to paste into Claude chat."""
import json, glob, sys, os
from pathlib import Path
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10
out = max(glob.glob("trendsast-out/*/findings.json"), key=os.path.getmtime)
d = json.load(open(out)); root = Path(d["target"])
rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
fs = [f for f in d["findings"] if f["line"] and f["category"] not in ("vulnerable-dependency", "misconfig")]
fs.sort(key=lambda f: -rank[f["severity"]])
parts = ["Triage these SAST findings. For each: true/false positive, reasoning, how to verify safely on a local instance, and anything the scanner missed.\n"]
for i, f in enumerate(fs[:N], 1):
    try: lines = (root / f["file"]).read_text(errors="replace").splitlines()
    except Exception: lines = []
    s, e = max(1, f["line"] - 25), min(len(lines), f["line"] + 15)
    code = "\n".join(f"{'>' if n == f['line'] else ' '}{n:5d} | {lines[n-1]}" for n in range(s, e + 1))
    parts.append(f"## {i}. [{f['severity']}] {f['category']} {f['cwe']} - {f['file']}:{f['line']}\nTools: {', '.join(f['tools'])}\n{f['title']}\n```\n{code}\n```\n")
Path(out).with_name("chat_triage.md").write_text("\n".join(parts))
print(f"Wrote {Path(out).with_name('chat_triage.md')} ({min(N, len(fs))} findings)")
