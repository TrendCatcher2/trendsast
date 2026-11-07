# TrendSAST

Multi-scanner SAST orchestrator for bug bounty source-code review. It runs every scanner you have installed, merges and de-duplicates their output, maps HTTP endpoints for IDOR hunting, optionally has Claude triage each finding, and writes one report.

**Only scan source code that is in scope for the program you are testing.** Every finding is a lead. Confirm it with a working PoC on a local instance before you report.

## What's inside

```
trendsast/
├── trendsast.py        # the orchestrator (no pip dependencies)
├── install.sh          # installs all scanners
├── rules/              # ~150 custom Semgrep rules (taint-tracking)
│   ├── python.yaml     # Flask / Django / FastAPI
│   ├── javascript.yaml # Express / Koa / Next / React / Vue / DOM
│   ├── php.yaml        # plain PHP / Laravel / WordPress
│   ├── java.yaml       # Spring / Servlets
│   └── go_ruby_csharp_sol.yaml
└── tests/vulnapp/      # intentionally vulnerable samples to test the tool
```

Scanners it drives: Semgrep (custom + registry packs), built-in secret/regex engine, Bandit, njsscan, gosec, Brakeman, mobsfscan, Gitleaks, TruffleHog (verifies live secrets), Trivy (dependencies + IaC + secrets), Checkov, Hadolint, Slither, Aderyn, CodeQL (optional).

## Step 1: Install

Requirements are Python 3.9+, git, and curl. Ruby (for Brakeman) and Node/npm (for Aderyn) are optional.

```bash
git clone https://github.com/TrendCatcher2/trendsast.git && cd trendsast
bash install.sh               # add --codeql to also get CodeQL (~1 GB)
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"   # also put this in ~/.bashrc
python3 trendsast.py doctor   # shows [OK] / [MISSING] per scanner
```

Missing scanners are skipped automatically. Semgrep alone plus the built-in engine already gives useful results.

## Step 2: Test on the bundled vulnerable app

```bash
python3 trendsast.py scan tests/vulnapp --include-tests
```

You should see critical findings for command injection, SQLi, eval, and pickle. Open the `report.md` path printed at the end. If this works, your setup is correct.

## Step 3: Get the target's source

Pick an in-scope asset that has public source (an open-source product, a repo listed in scope, or verified contracts on Immunefi). Check out the version that is actually deployed:

```bash
git clone https://github.com/<org>/<repo>.git && cd <repo>
git tag --sort=-creatordate | head      # find the latest release
git checkout <latest-release-tag>
cd ..
```

## Step 4: Scan

```bash
# full scan
python3 trendsast.py scan ./<repo>

# only code changed between two releases (best ROI on mature programs)
python3 trendsast.py scan ./<repo> --diff v1.4.0..v1.5.0

# deeper taint analysis (slow)
python3 trendsast.py scan ./<repo> --codeql

# pick scanners
python3 trendsast.py scan ./<repo> --scanners semgrep,gitleaks,trufflehog
```

## Step 5: AI triage (optional, costs API credits)

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # from console.anthropic.com
python3 trendsast.py scan ./<repo> --triage --triage-max 30 --triage-min high
```

Each finding plus about 70 lines of surrounding code goes to Claude. Claude returns a verdict (true/false positive), its reasoning, an idea for verifying it, and anything else it spotted that the scanners missed. Add `--drop-fp` to hide confirmed false positives.

Check the program rules first: if code was shared with you privately, don't send it to a third-party API without permission.

## Step 6: Read the report (in this order)

1. **AI-confirmed leads**, if you used `--triage`.
2. **CRITICAL findings.** These were flagged by two or more independent tools on a dangerous bug class.
3. **Endpoint map.** Routes with an `{id}` and no ownership check nearby are IDOR candidates, and scanners can't find these. Test with two accounts: request account B's object using account A's session.
4. **High and medium findings**, by category.

Outputs are `report.md` (read this), `findings.json` (for scripts), `report.sarif` (opens in the VS Code "SARIF Viewer" extension with click-to-code), and `raw/` (each tool's original output).

## Step 7: Verify every lead before reporting

1. Trace the flow by hand: from the source (request parameter) to the sink, and check whether anything sanitizes or authorizes it along the way.
2. Run the app locally (most open-source projects ship `docker-compose.yml`).
3. Reproduce with a minimal, harmless PoC, for example `sleep 5` or `id` for command injection, a time-based payload for SQLi, or `alert(document.domain)` for XSS.
4. Confirm the vulnerable code is in the deployed version.
5. Write the report with the vulnerable code path, your PoC request, and the impact.

Never submit raw scanner output. Programs close those reports as N/A.

## Tuning

| Option | What it does |
|---|---|
| `--offline` | Use only the local rules (no Semgrep registry download) |
| `--include-tests` | Keep findings in tests/, examples/, docs/ (hidden by default) |
| `--min-severity medium` | Shorter `report.md` |
| `--skip trivy,checkov` | Skip slow or noisy scanners |
| `--timeout 3600` | For very large repos |

To add your own rule, drop a `.yaml` file into `rules/`. Semgrep loads the whole folder. Rules that model bugs you have already been paid for are your edge: public rulesets are run by everyone.

## Known limitations

- Static analysis can't see runtime configuration, WAFs, or global middleware. That's why the endpoint map says "verify".
- The custom Java rules expect normal imports. Fully-qualified names like `new java.io.File(...)` without an import may be missed, and CodeQL covers this case.
- Business-logic bugs (race conditions, payment flows, multi-step authorization) need manual testing. Use the endpoint map as your checklist.
