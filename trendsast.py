#!/usr/bin/env python3
"""
TrendSAST - multi-scanner SAST orchestrator for bug bounty source-code review.

  python3 trendsast.py scan <path> [options]
  python3 trendsast.py doctor            # show which scanners are installed

Runs every installed scanner that fits the target's languages, normalizes all
output into one format, de-duplicates across tools, maps HTTP endpoints for IDOR
hunting, optionally triages findings with Claude, and writes Markdown/JSON/SARIF.

Only scan code that is IN SCOPE for the program you are testing.
"""
import argparse, json, os, re, shutil, subprocess, sys, time, urllib.request, urllib.error
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES_DIR = HERE / "rules"

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv",
             "__pycache__", ".next", ".nuxt", "coverage", "bower_components", ".idea", ".gradle",
             "out", "lib/bower", "third_party", "Pods", ".terraform"}
EXT_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".vue": "javascript", ".php": "php", ".phtml": "php",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".go": "go", ".rb": "ruby",
    ".erb": "ruby", ".cs": "csharp", ".sol": "solidity", ".rs": "rust", ".c": "c", ".cpp": "cpp",
    ".h": "c", ".swift": "swift", ".m": "objc", ".tf": "terraform", ".yaml": "yaml", ".yml": "yaml",
    ".sh": "shell", ".dart": "dart",
}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CRITICAL_CATS = {"sqli", "cmdi", "code-injection", "deserialization", "ssti", "lfi", "xxe", "jwt"}

CWE_CATEGORY = {
    "89": "sqli", "78": "cmdi", "77": "cmdi", "88": "argument-injection", "94": "code-injection", "95": "code-injection",
    "22": "path-traversal", "23": "path-traversal", "98": "lfi", "918": "ssrf", "79": "xss",
    "601": "open-redirect", "502": "deserialization", "611": "xxe", "943": "nosqli", "90": "ldapi",
    "643": "xpath-injection", "1336": "ssti", "1321": "prototype-pollution", "915": "mass-assignment",
    "347": "jwt", "798": "hardcoded-secret", "259": "hardcoded-secret", "321": "hardcoded-secret",
    "327": "weak-crypto", "328": "weak-crypto", "326": "weak-crypto", "338": "insecure-random",
    "330": "insecure-random", "295": "tls", "352": "csrf", "942": "cors", "614": "cookie",
    "1004": "cookie", "200": "info-disclosure", "209": "info-disclosure", "532": "info-disclosure",
    "489": "misconfig", "434": "file-upload", "1333": "redos", "113": "header-injection",
    "117": "log-injection", "284": "broken-access-control", "285": "broken-access-control",
    "639": "idor", "862": "broken-access-control", "863": "broken-access-control",
    "1035": "vulnerable-dependency", "1104": "vulnerable-dependency",
}
KEYWORD_CATEGORY = [
    (r"sql", "sqli"), (r"command|shell|os[-_]?exec|subprocess", "cmdi"), (r"eval|code[-_ ]?inj|rce", "code-injection"),
    (r"path[-_ ]?trav|directory[-_ ]?trav|lfi|file[-_ ]?inclusion", "path-traversal"), (r"ssrf", "ssrf"),
    (r"xss|cross[-_ ]?site[-_ ]?script|html[-_ ]?inj", "xss"), (r"redirect", "open-redirect"),
    (r"deserial|pickle|unserial|marshal|yaml[-_ ]?load", "deserialization"), (r"xxe|external[-_ ]?entit", "xxe"),
    (r"nosql|mongo", "nosqli"), (r"ssti|template[-_ ]?inj", "ssti"), (r"jwt", "jwt"),
    (r"secret|password|api[-_ ]?key|token|credential|private[-_ ]?key", "hardcoded-secret"),
    (r"md5|sha1|des\b|rc4|ecb|weak[-_ ]?(hash|cipher|crypto)", "weak-crypto"), (r"random", "insecure-random"),
    (r"tls|ssl|cert", "tls"), (r"csrf", "csrf"), (r"cors", "cors"), (r"cookie", "cookie"),
    (r"prototype", "prototype-pollution"), (r"mass[-_ ]?assign", "mass-assignment"), (r"upload", "file-upload"),
    (r"redos|regex", "redos"), (r"debug", "misconfig"),
]


@dataclass
class Finding:
    tool: str
    rule_id: str
    title: str
    severity: str
    file: str
    line: int = 0
    end_line: int = 0
    cwe: str = ""
    category: str = ""
    message: str = ""
    confidence: str = ""
    snippet: str = ""
    tools: list = field(default_factory=list)
    rules: list = field(default_factory=list)
    triage: dict = field(default_factory=dict)


# ----------------------------------------------------------------------------- helpers
def log(msg, color=None):
    colors = {"g": "\033[32m", "y": "\033[33m", "r": "\033[31m", "c": "\033[36m", "b": "\033[1m"}
    if color and sys.stdout.isatty():
        print(f"{colors[color]}{msg}\033[0m", flush=True)
    else:
        print(msg, flush=True)


def which(name):
    return shutil.which(name)


def run(cmd, cwd=None, timeout=1800, capture=True):
    """Run a command; never raise. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, cwd=cwd, timeout=timeout, capture_output=capture, text=True, errors="replace")
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except Exception as e:  # noqa
        return -1, "", str(e)


def load_json(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def norm_sev(s):
    s = str(s or "").strip().lower()
    return {
        "error": "high", "critical": "critical", "high": "high", "warning": "medium", "medium": "medium",
        "moderate": "medium", "info": "low", "low": "low", "note": "low", "weak": "low", "style": "info",
        "informational": "info", "optimization": "info", "none": "info", "unknown": "medium",
    }.get(s, "medium")


def norm_cwe(c):
    if not c:
        return ""
    if isinstance(c, list):
        c = c[0] if c else ""
    if isinstance(c, dict):
        c = c.get("id", "")
    m = re.search(r"(\d+)", str(c))
    return f"CWE-{m.group(1)}" if m else ""


def categorize(f: Finding):
    if f.category:
        return f.category
    num = f.cwe.replace("CWE-", "")
    if num in CWE_CATEGORY:
        return CWE_CATEGORY[num]
    hay = f"{f.rule_id} {f.title} {f.message}".lower()
    for rx, cat in KEYWORD_CATEGORY:
        if re.search(rx, hay):
            return cat
    return "other"


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            yield Path(dirpath) / fn


def detect_languages(root: Path):
    langs = Counter()
    extra = set()
    for p in iter_files(root):
        lang = EXT_LANG.get(p.suffix.lower())
        if lang:
            langs[lang] += 1
        name = p.name.lower()
        if name == "dockerfile" or name.startswith("dockerfile."):
            extra.add("docker")
        if name in ("gemfile", "routes.rb"):
            extra.add("rails")
        if name in ("androidmanifest.xml", "info.plist"):
            extra.add("mobile")
        if p.suffix in (".tf", ".bicep") or name in ("chart.yaml", "kustomization.yaml", "serverless.yml"):
            extra.add("iac")
    return langs, extra


_file_cache = {}


def read_lines(root: Path, rel: str):
    if rel not in _file_cache:
        try:
            _file_cache[rel] = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            _file_cache[rel] = []
    return _file_cache[rel]


def snippet(root, rel, line, before=2, after=2):
    lines = read_lines(root, rel)
    if not lines or not line:
        return ""
    s, e = max(1, line - before), min(len(lines), line + after)
    return "\n".join(f"{'>' if i == line else ' '}{i:5d} | {lines[i - 1][:220]}" for i in range(s, e + 1))


def relpath(root: Path, p):
    if not p:
        return ""
    p = str(p)
    try:
        pp = Path(p)
        if pp.is_absolute():
            return str(pp.resolve().relative_to(root.resolve()))
    except Exception:
        pass
    p = p.replace("\\", "/")
    for prefix in ("./", str(root).rstrip("/") + "/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p


# ----------------------------------------------------------------------------- scanners
SEMGREP_PACKS = {
    "_base": ["p/default", "p/owasp-top-ten", "p/cwe-top-25", "p/secrets", "p/security-audit"],
    "python": ["p/python", "p/django", "p/flask", "p/fastapi"],
    "javascript": ["p/javascript", "p/nodejs", "p/express", "p/react", "p/nextjs", "p/xss"],
    "typescript": ["p/typescript", "p/nodejs", "p/react", "p/nextjs"],
    "php": ["p/php", "p/laravel", "p/symfony"],
    "java": ["p/java", "p/spring", "p/kotlin"],
    "kotlin": ["p/kotlin"],
    "go": ["p/golang", "p/gosec"],
    "ruby": ["p/ruby", "p/rails"],
    "csharp": ["p/csharp"],
    "solidity": ["p/smart-contracts"],
    "c": ["p/c"], "cpp": ["p/c"], "rust": ["p/rust"], "scala": ["p/scala"], "swift": ["p/swift"],
    "terraform": ["p/terraform"], "docker": ["p/dockerfile"], "yaml": ["p/kubernetes"],
    "_jwt": ["p/jwt", "p/sql-injection", "p/command-injection", "p/insecure-transport"],
}


def scan_semgrep(ctx):
    configs = [str(RULES_DIR)]
    if not ctx.offline:
        packs = list(SEMGREP_PACKS["_base"]) + SEMGREP_PACKS["_jwt"]
        for lang in list(ctx.langs) + list(ctx.extra):
            packs += SEMGREP_PACKS.get(lang, [])
        configs += list(dict.fromkeys(packs))
    out = ctx.raw / "semgrep.json"

    def build(cfgs):
        cmd = ["semgrep", "scan", "--json", "-o", str(out), "--metrics=off", "--timeout", "45",
               "--max-target-bytes", "3000000", "--disable-version-check", "-j", "2", "--max-memory", "3000"]
        for c in cfgs:
            cmd += ["--config", c]
        for d in SKIP_DIRS:
            cmd += ["--exclude", d]
        return cmd + [str(ctx.root)]

    run(build(configs), timeout=ctx.timeout)
    data = load_json(out)
    if (data is None or (not data.get("results") and data.get("errors"))) and len(configs) > 1:
        log("    registry packs unreachable, retrying with local rules only", "y")
        run(build([str(RULES_DIR)]), timeout=ctx.timeout)
        data = load_json(out)
    res = []
    for r in (data or {}).get("results", []):
        ex = r.get("extra", {})
        md = ex.get("metadata", {}) or {}
        res.append(Finding(
            tool="semgrep", rule_id=r.get("check_id", "").split(".")[-1], title=ex.get("message", "")[:160],
            severity=norm_sev(ex.get("severity")), file=relpath(ctx.root, r.get("path")),
            line=r.get("start", {}).get("line", 0), end_line=r.get("end", {}).get("line", 0),
            cwe=norm_cwe(md.get("cwe")), category=md.get("category", "") if r.get("check_id", "").split(".")[-1].startswith("ts-") else "",
            message=ex.get("message", ""), confidence=str(md.get("confidence", ""))))
    return res


def scan_bandit(ctx):
    out = ctx.raw / "bandit.json"
    run(["bandit", "-r", str(ctx.root), "-f", "json", "-o", str(out), "-q",
         "-x", ",".join(str(ctx.root / d) for d in SKIP_DIRS)], timeout=ctx.timeout)
    res = []
    for r in (load_json(out) or {}).get("results", []):
        res.append(Finding(
            tool="bandit", rule_id=f"{r.get('test_id')}-{r.get('test_name')}", title=r.get("issue_text", "")[:160],
            severity=norm_sev(r.get("issue_severity")), file=relpath(ctx.root, r.get("filename")),
            line=r.get("line_number", 0), cwe=norm_cwe(r.get("issue_cwe")), message=r.get("issue_text", ""),
            confidence=r.get("issue_confidence", "")))
    return res


def scan_gosec(ctx):
    out = ctx.raw / "gosec.json"
    run(["gosec", "-fmt=json", f"-out={out}", "-no-fail", "-quiet", "./..."], cwd=ctx.root, timeout=ctx.timeout)
    res = []
    for r in (load_json(out) or {}).get("Issues", []) or []:
        res.append(Finding(
            tool="gosec", rule_id=r.get("rule_id", ""), title=r.get("details", "")[:160],
            severity=norm_sev(r.get("severity")), file=relpath(ctx.root, r.get("file")),
            line=int(str(r.get("line", "0")).split("-")[0] or 0), cwe=norm_cwe(r.get("cwe")),
            message=r.get("details", ""), confidence=r.get("confidence", "")))
    return res


def scan_brakeman(ctx):
    out = ctx.raw / "brakeman.json"
    run(["brakeman", "-q", "-f", "json", "-o", str(out), "--no-exit-on-warn", "--no-exit-on-error",
         "--force", "--no-pager", str(ctx.root)], timeout=ctx.timeout)
    res = []
    for r in (load_json(out) or {}).get("warnings", []):
        res.append(Finding(
            tool="brakeman", rule_id=r.get("check_name", ""), title=f"{r.get('warning_type')}: {r.get('message')}"[:160],
            severity=norm_sev({"High": "high", "Medium": "medium", "Weak": "low"}.get(r.get("confidence"), "medium")),
            file=relpath(ctx.root, r.get("file")), line=r.get("line") or 0, cwe=norm_cwe(r.get("cwe_id")),
            message=r.get("message", ""), confidence=r.get("confidence", "")))
    return res


def _libsast_parse(ctx, data, tool):
    """njsscan / mobsfscan share the libsast output shape."""
    res = []

    def walk(d):
        for rule_id, v in (d or {}).items():
            if isinstance(v, dict) and "files" in v:
                md = v.get("metadata", {})
                for fobj in v.get("files", []):
                    lines = fobj.get("match_lines") or [0]
                    res.append(Finding(
                        tool=tool, rule_id=rule_id, title=(md.get("description") or rule_id)[:160],
                        severity=norm_sev(md.get("severity")), file=relpath(ctx.root, fobj.get("file_path")),
                        line=lines[0] if lines else 0, cwe=norm_cwe(md.get("cwe")),
                        message=md.get("description", "")))
            elif isinstance(v, dict):
                walk(v)
    walk(data if isinstance(data, dict) else {})
    return res


def scan_njsscan(ctx):
    out = ctx.raw / "njsscan.json"
    run(["njsscan", "--json", "-o", str(out), str(ctx.root)], timeout=ctx.timeout)
    d = load_json(out) or {}
    return _libsast_parse(ctx, {k: v for k, v in d.items() if k in ("nodejs", "templates")}, "njsscan")


def scan_mobsfscan(ctx):
    out = ctx.raw / "mobsfscan.json"
    run(["mobsfscan", "--json", "-o", str(out), str(ctx.root)], timeout=ctx.timeout)
    return _libsast_parse(ctx, (load_json(out) or {}).get("results", {}), "mobsfscan")


def _redact(s):
    s = str(s or "")
    return s[:4] + "…" + f"[{len(s)} chars]" if len(s) > 8 else "****"


def scan_gitleaks(ctx):
    out = ctx.raw / "gitleaks.json"
    rc, so, se = run(["gitleaks", "dir", str(ctx.root), "-f", "json", "-r", str(out), "--exit-code", "0", "--no-banner"],
                     timeout=ctx.timeout)
    if load_json(out) is None:
        run(["gitleaks", "detect", "--source", str(ctx.root), "--no-git", "-f", "json", "-r", str(out),
             "--exit-code", "0", "--no-banner"], timeout=ctx.timeout)
    res = []
    for r in load_json(out) or []:
        res.append(Finding(
            tool="gitleaks", rule_id=r.get("RuleID", ""), title=f"Secret: {r.get('Description', '')} ({_redact(r.get('Secret'))})",
            severity="high", file=relpath(ctx.root, r.get("File")), line=r.get("StartLine", 0),
            cwe="CWE-798", category="hardcoded-secret", message=r.get("Description", "")))
    return res


def scan_trufflehog(ctx):
    rc, so, se = run(["trufflehog", "filesystem", str(ctx.root), "--json", "--no-update"], timeout=ctx.timeout)
    (ctx.raw / "trufflehog.jsonl").write_text(so)
    res = []
    for ln in so.splitlines():
        try:
            r = json.loads(ln)
        except Exception:
            continue
        fsm = (r.get("SourceMetadata", {}).get("Data", {}) or {}).get("Filesystem", {})
        verified = r.get("Verified")
        res.append(Finding(
            tool="trufflehog", rule_id=r.get("DetectorName", "secret"),
            title=f"{'VERIFIED LIVE ' if verified else ''}secret: {r.get('DetectorName')} ({_redact(r.get('Raw'))})",
            severity="critical" if verified else "medium", file=relpath(ctx.root, fsm.get("file")),
            line=fsm.get("line", 0), cwe="CWE-798", category="hardcoded-secret",
            message="Credential verified live against the provider API" if verified else "Unverified credential",
            confidence="HIGH" if verified else "LOW"))
    return res


def scan_trivy(ctx):
    out = ctx.raw / "trivy.json"
    run(["trivy", "fs", "--scanners", "vuln,misconfig,secret", "--format", "json", "-o", str(out), "-q",
         "--skip-dirs", "node_modules", str(ctx.root)], timeout=ctx.timeout)
    res = []
    for block in (load_json(out) or {}).get("Results", []) or []:
        target = relpath(ctx.root, block.get("Target", ""))
        for v in block.get("Vulnerabilities") or []:
            res.append(Finding(
                tool="trivy", rule_id=v.get("VulnerabilityID", ""),
                title=f"{v.get('VulnerabilityID')} in {v.get('PkgName')} {v.get('InstalledVersion')} (fix: {v.get('FixedVersion') or 'none'}) - {v.get('Title', '')}"[:200],
                severity=norm_sev(v.get("Severity")), file=target, cwe=norm_cwe(v.get("CweIDs")),
                category="vulnerable-dependency", message=v.get("Description", "")[:500]))
        for m in block.get("Misconfigurations") or []:
            res.append(Finding(
                tool="trivy", rule_id=m.get("ID", ""), title=f"{m.get('Title')}: {m.get('Message', '')}"[:200],
                severity=norm_sev(m.get("Severity")), file=target,
                line=(m.get("CauseMetadata") or {}).get("StartLine", 0), category="misconfig",
                message=m.get("Description", "")))
        for s in block.get("Secrets") or []:
            res.append(Finding(
                tool="trivy", rule_id=s.get("RuleID", ""), title=f"Secret: {s.get('Title')}", severity=norm_sev(s.get("Severity")),
                file=target, line=s.get("StartLine", 0), cwe="CWE-798", category="hardcoded-secret"))
    return res


def scan_checkov(ctx):
    rc, so, se = run(["checkov", "-d", str(ctx.root), "-o", "json", "--quiet", "--compact",
                      "--skip-path", "node_modules"], timeout=ctx.timeout)
    (ctx.raw / "checkov.json").write_text(so)
    try:
        data = json.loads(so)
    except Exception:
        return []
    blocks = data if isinstance(data, list) else [data]
    res = []
    for b in blocks:
        for c in (b.get("results", {}) or {}).get("failed_checks", []):
            rng = c.get("file_line_range") or [0]
            res.append(Finding(
                tool="checkov", rule_id=c.get("check_id", ""), title=c.get("check_name", "")[:160],
                severity=norm_sev(c.get("severity") or "medium"), file=relpath(ctx.root, (c.get("file_path") or "").lstrip("/")),
                line=rng[0], category="misconfig", message=c.get("check_name", "")))
    return res


def scan_hadolint(ctx):
    files = [str(p) for p in iter_files(ctx.root) if p.name.lower().startswith("dockerfile")]
    if not files:
        return []
    rc, so, se = run(["hadolint", "-f", "json", *files], timeout=ctx.timeout)
    (ctx.raw / "hadolint.json").write_text(so)
    res = []
    try:
        for r in json.loads(so or "[]"):
            res.append(Finding(
                tool="hadolint", rule_id=r.get("code", ""), title=r.get("message", "")[:160],
                severity={"error": "medium", "warning": "low"}.get(r.get("level"), "info"),
                file=relpath(ctx.root, r.get("file")), line=r.get("line", 0), category="misconfig",
                message=r.get("message", "")))
    except Exception:
        pass
    return res


def scan_slither(ctx):
    out = ctx.raw / "slither.json"
    if out.exists():
        out.unlink()
    run(["slither", str(ctx.root), "--json", str(out), "--exclude-dependencies"], cwd=ctx.root, timeout=ctx.timeout)
    res = []
    for d in ((load_json(out) or {}).get("results", {}) or {}).get("detectors", []):
        el = (d.get("elements") or [{}])[0].get("source_mapping", {}) or {}
        lines = el.get("lines") or [0]
        res.append(Finding(
            tool="slither", rule_id=d.get("check", ""), title=d.get("description", "").split("\n")[0][:200],
            severity=norm_sev(d.get("impact")), file=el.get("filename_relative", ""), line=lines[0],
            category="smart-contract", message=d.get("description", ""), confidence=d.get("confidence", "")))
    return res


def scan_aderyn(ctx):
    out = ctx.raw / "aderyn.json"
    run(["aderyn", str(ctx.root), "-o", str(out)], timeout=ctx.timeout)
    data = load_json(out) or {}
    res = []
    for key, sev in (("high_issues", "high"), ("medium_issues", "medium"), ("low_issues", "low")):
        for iss in (data.get(key) or {}).get("issues", []):
            for inst in iss.get("instances", [])[:25]:
                res.append(Finding(
                    tool="aderyn", rule_id=iss.get("detector_name", ""), title=iss.get("title", "")[:160],
                    severity=sev, file=inst.get("contract_path", ""), line=inst.get("line_no", 0),
                    category="smart-contract", message=iss.get("description", "")))
    return res


CODEQL_LANGS = {  # our lang -> (codeql language, build-mode, query pack, suite)
    "python": ("python", "none", "codeql/python-queries", "python"),
    "javascript": ("javascript-typescript", "none", "codeql/javascript-queries", "javascript"),
    "typescript": ("javascript-typescript", "none", "codeql/javascript-queries", "javascript"),
    "ruby": ("ruby", "none", "codeql/ruby-queries", "ruby"),
    "java": ("java-kotlin", "none", "codeql/java-queries", "java"),
    "csharp": ("csharp", "none", "codeql/csharp-queries", "csharp"),
    "go": ("go", "autobuild", "codeql/go-queries", "go"),
}


def parse_sarif(ctx, path, tool):
    data = load_json(path) or {}
    res = []
    for run_ in data.get("runs", []):
        rules = {}
        for r in ((run_.get("tool") or {}).get("driver") or {}).get("rules", []) or []:
            rules[r.get("id")] = r
        for r in run_.get("results", []):
            rule = rules.get(r.get("ruleId"), {})
            props = rule.get("properties", {}) or {}
            tags = " ".join(props.get("tags", []))
            loc = ((r.get("locations") or [{}])[0].get("physicalLocation") or {})
            sev = props.get("security-severity")
            if sev:
                sv = float(sev)
                sev = "critical" if sv >= 9 else "high" if sv >= 7 else "medium" if sv >= 4 else "low"
            res.append(Finding(
                tool=tool, rule_id=r.get("ruleId", ""), title=(r.get("message") or {}).get("text", "")[:200],
                severity=sev or norm_sev(r.get("level")), file=relpath(ctx.root, (loc.get("artifactLocation") or {}).get("uri", "")),
                line=(loc.get("region") or {}).get("startLine", 0), cwe=norm_cwe(re.findall(r"cwe-(\d+)", tags)),
                message=(r.get("message") or {}).get("text", "")))
    return res


def scan_codeql(ctx):
    res, done = [], set()
    for lang in ctx.langs:
        if lang not in CODEQL_LANGS:
            continue
        cl, mode, pack, suite = CODEQL_LANGS[lang]
        if cl in done:
            continue
        done.add(cl)
        db = ctx.out / f"codeql-db-{cl}"
        sarif = ctx.raw / f"codeql-{cl}.sarif"
        log(f"    codeql: building database for {cl} (slow)...")
        rc, so, se = run(["codeql", "database", "create", str(db), f"--language={cl}", f"--source-root={ctx.root}",
                          f"--build-mode={mode}", "--overwrite"], timeout=ctx.timeout * 2)
        if rc != 0:
            log(f"    codeql {cl} db failed: {se.strip()[-200:]}", "y")
            continue
        run(["codeql", "database", "analyze", str(db), "--format=sarif-latest", f"--output={sarif}", "--download",
             f"{pack}:codeql-suites/{suite}-security-extended.qls"], timeout=ctx.timeout * 2)
        res += parse_sarif(ctx, sarif, "codeql")
    return res


# ----------------------------------------------------------------------------- built-in engine (works with zero tools installed)
BUILTIN = [
    # (id, regex, severity, cwe, category, title)
    ("aws-access-key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "high", "CWE-798", "hardcoded-secret", "AWS access key ID"),
    ("aws-secret", r"(?i)aws(.{0,20})?(secret|private).{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "critical", "CWE-798", "hardcoded-secret", "AWS secret access key"),
    ("private-key", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY", "critical", "CWE-321", "hardcoded-secret", "Private key in repo"),
    ("github-token", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{60,}", "critical", "CWE-798", "hardcoded-secret", "GitHub token"),
    ("gitlab-token", r"\bglpat-[A-Za-z0-9\-_]{20}\b", "critical", "CWE-798", "hardcoded-secret", "GitLab personal access token"),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}", "high", "CWE-798", "hardcoded-secret", "Slack token"),
    ("slack-webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "medium", "CWE-798", "hardcoded-secret", "Slack webhook"),
    ("google-api-key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "medium", "CWE-798", "hardcoded-secret", "Google API key"),
    ("stripe-key", r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b", "critical", "CWE-798", "hardcoded-secret", "Stripe live secret key"),
    ("twilio-key", r"\bSK[0-9a-fA-F]{32}\b", "medium", "CWE-798", "hardcoded-secret", "Twilio API key"),
    ("sendgrid-key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", "high", "CWE-798", "hardcoded-secret", "SendGrid API key"),
    ("openai-key", r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b", "high", "CWE-798", "hardcoded-secret", "OpenAI-style API key"),
    ("anthropic-key", r"\bsk-ant-[A-Za-z0-9_-]{32,}\b", "high", "CWE-798", "hardcoded-secret", "Anthropic API key"),
    ("jwt-literal", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "medium", "CWE-798", "hardcoded-secret", "Hardcoded JWT"),
    ("db-uri-creds", r"(?i)\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^:\s'\"/]+:[^@\s'\"]{3,}@", "high", "CWE-798", "hardcoded-secret", "Database URI with credentials"),
    ("generic-password", r"(?i)\b(password|passwd|pwd|secret|api_?key|access_?token|auth_?token)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]", "low", "CWE-798", "hardcoded-secret", "Possible hardcoded credential"),
    ("firebase-url", r"https://[a-z0-9-]+\.firebaseio\.com", "low", "CWE-200", "info-disclosure", "Firebase DB URL (test for open read/write: /.json)"),
    ("s3-bucket", r"\b[a-z0-9.-]{3,63}\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com\b", "low", "CWE-200", "info-disclosure", "S3 bucket reference (test for public list/write)"),
    ("internal-url", r"https?://(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|[a-z0-9.-]+\.(internal|corp|local|intranet))\b", "info", "CWE-200", "info-disclosure", "Internal host/URL disclosed"),
    ("todo-security", r"(?i)(TODO|FIXME|HACK|XXX).{0,40}(auth|security|bypass|vuln|insecure|permission|hardcod|temporar)", "info", "", "code-smell", "Developer note about security"),
    ("debug-route", r"(?i)['\"]/(debug|admin|internal|_internal|test|backdoor|phpinfo|actuator|metrics|graphiql|console|swagger)[/'\"]", "low", "CWE-489", "info-disclosure", "Debug/admin/internal route"),
]
TEXT_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".php", ".java", ".kt", ".go", ".rb", ".cs", ".sol",
            ".env", ".yml", ".yaml", ".json", ".xml", ".properties", ".conf", ".cfg", ".ini", ".toml", ".sh",
            ".tf", ".vue", ".html", ".config", ".gradle", ".swift", ".dart", ".rs", ".c", ".cpp", ".txt"}


def scan_builtin(ctx):
    res = []
    compiled = [(i, re.compile(rx), s, c, cat, t) for i, rx, s, c, cat, t in BUILTIN]
    for p in iter_files(ctx.root):
        if p.suffix.lower() not in TEXT_EXT and not p.name.startswith(".env"):
            continue
        if p.name.endswith((".min.js", ".map", "package-lock.json", "yarn.lock")):
            continue
        try:
            if p.stat().st_size > 2_000_000:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = relpath(ctx.root, p)
        is_test = bool(re.search(r"(^|/)(tests?|spec|__tests__|fixtures?|examples?|mocks?)(/|$)", rel))
        for n, line in enumerate(text.splitlines(), 1):
            if len(line) > 3000:
                continue
            for rid, rx, sev, cwe, cat, title in compiled:
                if rx.search(line):
                    s = "low" if is_test and sev in ("high", "critical", "medium") else sev
                    res.append(Finding(tool="builtin", rule_id=rid, title=title + (" (test/example file)" if is_test else ""),
                                       severity=s, file=rel, line=n, cwe=cwe, category=cat, message=title))
    return res


# ----------------------------------------------------------------------------- endpoint mapper (IDOR / access-control leads)
ROUTE_PATTERNS = [
    ("flask/fastapi", re.compile(r"@\w+\.(route|get|post|put|patch|delete|api_route)\(\s*['\"]([^'\"]+)['\"](.*)")),
    ("django", re.compile(r"\b(re_)?path\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*([\w.]+)")),
    ("express", re.compile(r"\b(?:app|router|server|r)\.(get|post|put|patch|delete|all)\(\s*['\"`]([^'\"`]+)['\"`]")),
    ("spring", re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*\"([^\"]*)\"")),
    ("rails", re.compile(r"^\s*(get|post|put|patch|delete|resources?)\s+['\":]([\w/:{}\-.]+)")),
    ("laravel", re.compile(r"Route::(get|post|put|patch|delete|any|resource)\(\s*['\"]([^'\"]+)['\"]")),
    ("go", re.compile(r"\.(HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\(\s*\"([^\"]+)\"")),
    ("nextjs-api", None),
]
ID_PARAM = re.compile(r"(<(int:|uuid:|string:)?\w*id\w*>|:\w*id\w*\b|\{\w*id\w*\}|<\w+>|:\w+\b|\{\w+\})", re.I)
AUTH_HINT = re.compile(
    r"(login_required|jwt_required|auth_required|permission_required|permission_classes|IsAuthenticated|"
    r"@PreAuthorize|@Secured|@RolesAllowed|authenticate|authorize|requireAuth|isAuthenticated|ensureAuth|"
    r"passport\.authenticate|verifyToken|checkAuth|middleware\(['\"]auth|->middleware|before_action\s*:authenticate|"
    r"Depends\(\s*get_current|current_user|@login|AuthGuard|UseGuards|requireLogin|withAuth|getServerSession)", re.I)
OWNER_HINT = re.compile(
    r"(owner|user_id\s*==|userId\s*===?|\.user\s*==|request\.user|req\.user\.id|current_user\.id|"
    r"current_user\.\w+\.find|policy|authorize\(|can\?|abilit|belongs_to|where\(\s*user|filter\(\s*user|tenant|org_id|account_id)",
    re.I)


def map_endpoints(ctx):
    eps = []
    for p in iter_files(ctx.root):
        lang = EXT_LANG.get(p.suffix.lower())
        if lang not in ("python", "javascript", "typescript", "java", "kotlin", "ruby", "php", "go", "csharp"):
            continue
        rel = relpath(ctx.root, p)
        lines = read_lines(ctx.root, rel)
        for i, line in enumerate(lines):
            for fw, rx in ROUTE_PATTERNS:
                if rx is None:
                    continue
                m = rx.search(line)
                if not m:
                    continue
                route = m.group(2)
                if fw == "django" and not route and m.group(3) == "include":
                    continue
                method = m.group(1).upper() if fw in ("express", "laravel", "rails", "go") else (
                    m.group(1).upper() if fw == "spring" else "ANY")
                window = "\n".join(lines[max(0, i - 6): i + 40])
                has_id = bool(ID_PARAM.search(route))
                auth = bool(AUTH_HINT.search(window))
                owner = bool(OWNER_HINT.search(window))
                risk = []
                if has_id and not owner:
                    risk.append("IDOR-lead: object ID in route, no ownership check seen nearby")
                if not auth:
                    risk.append("no auth hint nearby (verify middleware/global guards)")
                if method in ("POST", "PUT", "PATCH", "DELETE", "ANY") and re.search(r"(?i)admin|role|user|account|org|team|member|invite|payment|billing", route):
                    risk.append("state-changing sensitive route: test privilege escalation / CSRF")
                eps.append({"framework": fw, "method": method, "route": route, "file": rel, "line": i + 1,
                            "has_id_param": has_id, "auth_hint": auth, "ownership_hint": owner, "leads": risk})
                break
    return eps


# ---- Meteor DDP method inventory (added by patch_meteor.py)
METEOR_BLOCK_START = re.compile(r"Meteor\.methods(<[^>]*>)?\(\s*\{")
METEOR_METHOD = re.compile(r"""^\t(?:async\s+)?(?:'([^']+)'|"([^"]+)"|([A-Za-z_$][\w$]*))\s*\((.*)\)\s*(?::[^{]+)?\{\s*$""")
METEOR_END = re.compile(r"^\t\},?\s*$")
ID_LIKE = re.compile(r"(?i)^(rid|roomid|tmid|mid|msgid|messageid|_id|id|uid|userid|fileid|teamid|drid|discussionid|token|\w+id)$")
VALIDATION = re.compile(r"check\(|typeof\s|Match\.test|ajv|isValid|\.parse\(|validate")
ACCESS = re.compile(r"canAccessRoom|canSendMessage|hasPermission|hasAtLeastOnePermission|hasAllPermission|hasRole|isOwner|canDelete|canEdit|u\._id\s*[!=]==?|\.uid\s*[!=]==?\s*userId")
LOGIN = re.compile(r"Meteor\.userId\(\)|this\.userId|Meteor\.userAsync\(\)|Meteor\.user\(\)|\buserId\b")


def _meteor_params(raw):
    raw = re.sub(r":\s*[^,=)}{]+", "", raw)          # strip TS type annotations
    raw = re.sub(r"=\s*[^,})]+", "", raw)              # strip default values
    return [p for p in re.findall(r"[A-Za-z_$][\w$]*", raw) if p not in ("async",)]


def _same_file_helpers(body, lines):
    extra = []
    called = set(re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(", body))
    for k, l in enumerate(lines):
        m = re.match(r"^(?:export\s+)?(?:const|let|function|async function)\s+([A-Za-z_$][\w$]*)", l)
        if m and m.group(1) in called and "Meteor.methods" not in l:
            end = k + 1
            while end < len(lines) and not re.match(r"^\}", lines[end]):
                end += 1
            extra.append("\n".join(lines[k:end + 1]))
    return "\n" + "\n".join(extra) if extra else ""


def map_meteor(ctx):
    eps = []
    for p in iter_files(ctx.root):
        if p.suffix not in (".ts", ".js"):
            continue
        rel = relpath(ctx.root, p)
        lines = read_lines(ctx.root, rel)
        if not any("Meteor.methods" in l for l in lines):
            continue
        inside, i = False, 0
        while i < len(lines):
            l = lines[i]
            if METEOR_BLOCK_START.search(l):
                inside = True
            elif inside and l.startswith("});"):
                inside = False
            m = METEOR_METHOD.match(l) if inside else None
            if m:
                name = m.group(1) or m.group(2) or m.group(3)
                params = _meteor_params(m.group(4))
                j = i + 1
                while j < len(lines) and not METEOR_END.match(lines[j]):
                    j += 1
                body = "\n".join(lines[i:j]) + _same_file_helpers("\n".join(lines[i:j]), lines)
                ids = [x for x in params if ID_LIKE.match(x)]
                leads = []
                if not LOGIN.search(body):
                    leads.append("NO LOGIN CHECK: may be callable unauthenticated")
                if params and not VALIDATION.search(body):
                    leads.append(f"args not validated ({', '.join(params)}): try object/operator payloads")
                if ids and not ACCESS.search(body):
                    leads.append(f"takes {', '.join(ids)} but no permission/room-access check: IDOR lead")
                if "methodDeprecationLogger" in body:
                    leads.append("deprecated but still callable - compare with its REST replacement")
                eps.append({"framework": "meteor-ddp", "method": "DDP", "route": name, "file": rel, "line": i + 1,
                            "has_id_param": bool(ids), "auth_hint": bool(LOGIN.search(body)),
                            "ownership_hint": bool(ACCESS.search(body)), "leads": leads})
                i = j
            i += 1
    return eps


# ---- JAX-RS endpoint inventory (added by patch_jaxrs.py)
JAXRS_CLASS_PATH = re.compile(r'^\s*@Path\(\s*"([^"]*)"')
JAXRS_VERB = re.compile(r'^\s*@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b')
JAXRS_METHOD_PATH = re.compile(r'^\s*@Path\(\s*"([^"]*)"')
JAXRS_SIG = re.compile(r'^\s*public\s+[\w<>\[\],.?\s]+\s+(\w+)\s*\(')
JAXRS_PARAM = re.compile(r'@(PathParam|QueryParam|FormParam|HeaderParam|CookieParam)\(\s*"([^"]+)"')
JX_ID = re.compile(r'(?i)^(.*(id|key|uuid|token|name|source|object|ref|user|org|mnt|handle)|.*\bpk\b)$')
JX_AUTH = re.compile(
    r'(?i)(getUser|SsoToken|ApiKey|OAuth|Authentication|authenticate|authoris|authoriz|'
    r'Credential|hasPermission|isTrusted|clientCert|Principal|SecurityContext|'
    r'accessControl|AccessControlList|isDenied|checkPermission|mntner|maintainer|'
    r'passwords|override|crowdToken|bearer)')
JX_WRITE = re.compile(r'^(POST|PUT|DELETE|PATCH)$')


def _jaxrs_norm(*parts):
    p = "/".join(x.strip("/") for x in parts if x)
    return "/" + p if p else "/"


def map_jaxrs(ctx):
    eps = []
    for p in iter_files(ctx.root):
        if p.suffix != ".java":
            continue
        rel = relpath(ctx.root, p)
        if re.search(r"(^|/)(test|tests|src/test)(/|$)", rel):
            continue
        lines = read_lines(ctx.root, rel)
        if not any("@Path(" in l for l in lines):
            continue
        base = ""
        for l in lines[:80]:
            m = JAXRS_CLASS_PATH.match(l)
            if m and not l.strip().startswith("//"):
                base = m.group(1)
                break
        i = 0
        while i < len(lines):
            if JAXRS_VERB.match(lines[i]):
                verb = JAXRS_VERB.match(lines[i]).group(1)
                sub, j, sig_line = "", i + 1, None
                while j < min(i + 25, len(lines)):
                    mp = JAXRS_METHOD_PATH.match(lines[j])
                    if mp:
                        sub = mp.group(1)
                    if JAXRS_SIG.match(lines[j]):
                        sig_line = j
                        break
                    j += 1
                if sig_line is None:
                    i += 1
                    continue
                end = sig_line
                depth, started = 0, False
                while end < len(lines) and end < sig_line + 400:
                    depth += lines[end].count("{") - lines[end].count("}")
                    if "{" in lines[end]:
                        started = True
                    if started and depth <= 0:
                        break
                    end += 1
                body = "\n".join(lines[sig_line:end + 1])
                sig = "\n".join(lines[i:sig_line + 25])
                params = JAXRS_PARAM.findall(sig)
                ids = [n for kind, n in params if JX_ID.match(n)]
                route = _jaxrs_norm(base, sub)
                leads = []
                if not JX_AUTH.search(body):
                    leads.append("no auth/authorization reference in handler body")
                if ids and not JX_AUTH.search(body):
                    leads.append(f"takes {', '.join(sorted(set(ids))[:4])} with no visible authorization: IDOR/BAC lead")
                if JX_WRITE.match(verb) and not JX_AUTH.search(body):
                    leads.append(f"{verb} state-changing with no visible auth check")
                eps.append({"framework": "jax-rs", "method": verb, "route": route, "file": rel,
                            "line": i + 1, "has_id_param": bool(ids),
                            "auth_hint": bool(JX_AUTH.search(body)),
                            "ownership_hint": bool(JX_AUTH.search(body)), "leads": leads})
                i = end
            i += 1
    return eps


# ----------------------------------------------------------------------------- dedupe / filter
def dedupe(findings):
    merged = {}
    for f in findings:
        f.category = categorize(f)
        key = (f.file, f.line, f.category) if f.line else (f.file, f.rule_id, f.title[:60])
        if key in merged:
            m = merged[key]
            if f.tool not in m.tools:
                m.tools.append(f.tool)
            m.rules.append(f"{f.tool}:{f.rule_id}")
            if SEV_RANK[f.severity] > SEV_RANK[m.severity]:
                m.severity = f.severity
            if not m.cwe and f.cwe:
                m.cwe = f.cwe
        else:
            f.tools = [f.tool]
            f.rules = [f"{f.tool}:{f.rule_id}"]
            merged[key] = f
    out = list(merged.values())
    # A no-shell exec (argument injection) overrides other tools calling the same line full command injection
    arg_lines = {(f.file, f.line) for f in out if f.category == "argument-injection"}
    shell_lines = {(f.file, f.line) for f in out if any("ts-java-cmdi-shell" in r for r in f.rules)}
    for f in out:
        if f.category == "cmdi" and (f.file, f.line) in arg_lines and (f.file, f.line) not in shell_lines:
            f.severity = "medium"
            f.title = "[downgraded: no shell, argument injection only] " + f.title
    for f in out:
        # corroborated by 2+ independent tools on a dangerous class -> bump
        if len(f.tools) >= 2 and f.severity == "high" and f.category in CRITICAL_CATS:
            f.severity = "critical"
    return out


def changed_files(root, diff):
    rc, so, se = run(["git", "-C", str(root), "diff", "--name-only", diff])
    if rc != 0:
        log(f"[!] git diff failed: {se.strip()}", "r")
        return None
    return {l.strip() for l in so.splitlines() if l.strip()}


# ----------------------------------------------------------------------------- AI triage
TRIAGE_SYSTEM = """You are a senior application security engineer triaging static-analysis findings for a bug bounty hunter.
For the finding and code you are given, decide if it is a real, exploitable vulnerability.
Check: (1) is the source actually attacker-controlled? (2) is it sanitized/validated/parameterized/authorized on the path?
(3) is the code reachable from an external entry point (route, handler, public function)? (4) is this test/example/dead code?
Be skeptical: most SAST findings are false positives. Respond with ONLY a JSON object, no markdown:
{"verdict":"true_positive|false_positive|needs_review","confidence":"high|medium|low","severity":"critical|high|medium|low|info",
"reasoning":"2-4 sentences","exploit_idea":"how to verify safely on a local instance (request shape / payload idea), or empty",
"missed_issues":"any other security issue visible in this code that the scanner did not flag (e.g. missing authz/IDOR), or empty"}"""


def call_claude(prompt, model, api_key, max_tokens=900):
    body = json.dumps({"model": model, "max_tokens": max_tokens, "system": TRIAGE_SYSTEM,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, method="POST", headers={
        "content-type": "application/json", "x-api-key": api_key, "anthropic-version": "2023-06-01"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read())
            text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
            text = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.M).strip()
            return json.loads(text[text.find("{"): text.rfind("}") + 1])
        except urllib.error.HTTPError as e:
            if e.code in (429, 529, 500, 503) and attempt < 3:
                time.sleep(5 * (attempt + 1))
                continue
            return {"verdict": "error", "reasoning": f"API error {e.code}: {e.read()[:200]!r}"}
        except Exception as e:  # noqa
            if attempt < 3:
                time.sleep(3)
                continue
            return {"verdict": "error", "reasoning": str(e)[:200]}


def triage(ctx, findings):
    kf = Path.home() / ".anthropic_key"
    key = os.environ.get("ANTHROPIC_API_KEY") or (kf.read_text().strip() if kf.exists() else "")
    if not key:
        log("[!] --triage needs ANTHROPIC_API_KEY in the environment; skipping triage", "r")
        return
    todo = [f for f in findings if f.line and f.category not in ("vulnerable-dependency", "misconfig", "code-smell")
            and SEV_RANK[f.severity] >= SEV_RANK[ctx.triage_min]]
    todo.sort(key=lambda f: -SEV_RANK[f.severity])
    todo = todo[: ctx.triage_max]
    log(f"[*] AI triage of {len(todo)} findings with {ctx.model} ...", "c")
    for i, f in enumerate(todo, 1):
        code = snippet(ctx.root, f.file, f.line, before=40, after=30)
        prompt = (f"Finding: {f.title}\nRule(s): {', '.join(f.rules)}\nCategory: {f.category} {f.cwe}\n"
                  f"Scanner severity: {f.severity}\nFile: {f.file}:{f.line}\n\nCode (> marks the flagged line):\n{code}")
        f.triage = call_claude(prompt, ctx.model, key) or {}
        v = f.triage.get("verdict", "?")
        log(f"    [{i}/{len(todo)}] {v:15s} {f.file}:{f.line} {f.category}", "g" if v == "true_positive" else None)


# ----------------------------------------------------------------------------- reports
def write_reports(ctx, findings, endpoints, status):
    findings.sort(key=lambda f: (-SEV_RANK[f.severity], f.category, f.file, f.line))
    (ctx.out / "findings.json").write_text(json.dumps({
        "target": str(ctx.root), "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "languages": dict(ctx.langs),
        "scanners": status, "findings": [asdict(f) for f in findings], "endpoints": endpoints}, indent=2))

    # SARIF (import into VS Code SARIF Viewer / GitHub code scanning)
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "TrendSAST", "rules": []}},
        "results": [{"ruleId": f"{f.category}/{f.rules[0]}", "level": lvl[f.severity],
                     "message": {"text": f"[{f.severity}] {f.title} (tools: {', '.join(f.tools)})"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                                         "region": {"startLine": max(1, f.line)}}}]} for f in findings]}]}
    (ctx.out / "report.sarif").write_text(json.dumps(sarif, indent=1))

    sev_count = Counter(f.severity for f in findings)
    cat_count = Counter(f.category for f in findings)
    md = [f"# TrendSAST report\n", f"Target: `{ctx.root}`  ", f"Generated: {time.strftime('%Y-%m-%d %H:%M')}  ",
          f"Languages: {', '.join(f'{k} ({v})' for k, v in ctx.langs.most_common())}\n",
          "## Scanners\n", "| Scanner | Status | Raw findings |", "|---|---|---|"]
    for name, st in status.items():
        md.append(f"| {name} | {st['status']} | {st.get('count', '')} |")
    md += ["\n## Summary\n", "| Severity | Count |", "|---|---|"]
    for s in ("critical", "high", "medium", "low", "info"):
        md.append(f"| {s} | {sev_count.get(s, 0)} |")
    md += ["\n| Category | Count |", "|---|---|"] + [f"| {c} | {n} |" for c, n in cat_count.most_common()]

    tp = [f for f in findings if f.triage.get("verdict") == "true_positive"]
    if any(f.triage for f in findings):
        md += ["\n## AI-confirmed leads (verify manually before reporting!)\n"]
        for f in tp:
            md.append(f"- **[{f.triage.get('severity', f.severity)}] {f.category}** `{f.file}:{f.line}` - {f.triage.get('reasoning', '')}")

    leads = [e for e in endpoints if e["leads"]]
    md += [f"\n## Endpoint map ({len(endpoints)} routes, {len(leads)} with leads)\n",
           "Routes with object IDs and no nearby ownership check are your best IDOR/BAC candidates. "
           "Test with two accounts: request account B's object with account A's session.\n",
           "| Method | Route | File | Leads |", "|---|---|---|---|"]
    for e in sorted(leads, key=lambda e: (not e["has_id_param"], e["file"]))[:300]:
        md.append(f"| {e['method']} | `{e['route']}` | `{e['file']}:{e['line']}` | {'; '.join(e['leads'])} |")

    md.append("\n## Findings\n")
    for f in findings:
        if SEV_RANK[f.severity] < SEV_RANK[ctx.report_min]:
            continue
        loc = f"{f.file}:{f.line}" if f.line else f.file
        md.append(f"### [{f.severity.upper()}] {f.category} - `{loc}`\n")
        md.append(f"{f.title}  \n**Tools:** {', '.join(f.tools)} | **Rules:** {', '.join(f.rules[:5])}"
                  f"{' | **' + f.cwe + '**' if f.cwe else ''}\n")
        sn = snippet(ctx.root, f.file, f.line)
        if sn:
            md.append(f"```\n{sn}\n```")
        if f.triage:
            t = f.triage
            md.append(f"> **AI triage:** {t.get('verdict')} ({t.get('confidence', '')}) - {t.get('reasoning', '')}")
            if t.get("exploit_idea"):
                md.append(f">\n> **Verify:** {t['exploit_idea']}")
            if t.get("missed_issues"):
                md.append(f">\n> **Also check:** {t['missed_issues']}")
        md.append("")
    (ctx.out / "report.md").write_text("\n".join(md))


# ----------------------------------------------------------------------------- main
SCANNERS = [
    # name, binary, applies(langs, extra) -> bool, function, install hint
    ("semgrep", "semgrep", lambda l, e: True, scan_semgrep, "pip install semgrep"),
    ("builtin", None, lambda l, e: True, scan_builtin, "(built in)"),
    ("bandit", "bandit", lambda l, e: "python" in l, scan_bandit, "pip install bandit"),
    ("njsscan", "njsscan", lambda l, e: "javascript" in l or "typescript" in l, scan_njsscan, "pip install njsscan"),
    ("gosec", "gosec", lambda l, e: "go" in l, scan_gosec, "go install github.com/securego/gosec/v2/cmd/gosec@latest"),
    ("brakeman", "brakeman", lambda l, e: "ruby" in l, scan_brakeman, "gem install brakeman"),
    ("mobsfscan", "mobsfscan", lambda l, e: "mobile" in e or bool({"kotlin", "swift", "objc", "dart"} & set(l)), scan_mobsfscan, "pip install mobsfscan"),
    ("gitleaks", "gitleaks", lambda l, e: True, scan_gitleaks, "https://github.com/gitleaks/gitleaks/releases"),
    ("trufflehog", "trufflehog", lambda l, e: True, scan_trufflehog, "https://github.com/trufflesecurity/trufflehog/releases"),
    ("trivy", "trivy", lambda l, e: True, scan_trivy, "https://github.com/aquasecurity/trivy/releases"),
    ("checkov", "checkov", lambda l, e: "iac" in e or "docker" in e or "terraform" in l, scan_checkov, "pip install checkov"),
    ("hadolint", "hadolint", lambda l, e: "docker" in e, scan_hadolint, "https://github.com/hadolint/hadolint/releases"),
    ("slither", "slither", lambda l, e: "solidity" in l, scan_slither, "pip install slither-analyzer solc-select"),
    ("aderyn", "aderyn", lambda l, e: "solidity" in l, scan_aderyn, "cargo install aderyn (or cyfrinup)"),
    ("codeql", "codeql", lambda l, e: bool(set(l) & set(CODEQL_LANGS)), scan_codeql, "https://github.com/github/codeql-action/releases"),
]


class Ctx:
    pass


def cmd_doctor(_args):
    log("TrendSAST scanner check\n", "b")
    for name, binary, _, _, hint in SCANNERS:
        ok = binary is None or which(binary)
        log(f"  {'[OK]     ' if ok else '[MISSING]'} {name:11s} {'' if ok else '-> ' + hint}", "g" if ok else "y")
    log(f"\n  Custom rules: {RULES_DIR} ({len(list(RULES_DIR.glob('*.yaml')))} packs)")
    log(f"  ANTHROPIC_API_KEY set: {'yes' if os.environ.get('ANTHROPIC_API_KEY') else 'no (needed only for --triage)'}")


def cmd_scan(args):
    ctx = Ctx()
    ctx.root = Path(args.path).resolve()
    if not ctx.root.is_dir():
        sys.exit(f"not a directory: {ctx.root}")
    ctx.out = Path(args.out or f"trendsast-out/{ctx.root.name}-{time.strftime('%Y%m%d-%H%M%S')}").resolve()
    ctx.raw = ctx.out / "raw"
    ctx.raw.mkdir(parents=True, exist_ok=True)
    ctx.offline, ctx.timeout, ctx.model = args.offline, args.timeout, args.model
    ctx.triage_max, ctx.triage_min, ctx.report_min = args.triage_max, args.triage_min, args.min_severity
    ctx.langs, ctx.extra = detect_languages(ctx.root)
    log(f"[*] Target: {ctx.root}", "b")
    log(f"[*] Languages: {dict(ctx.langs.most_common())}  extras: {sorted(ctx.extra) or '-'}")

    wanted = set(args.scanners.split(",")) if args.scanners != "all" else None
    skip = set(args.skip.split(",")) if args.skip else set()
    status, findings = {}, []
    for name, binary, applies, fn, hint in SCANNERS:
        if (wanted and name not in wanted) or name in skip:
            continue
        if name == "codeql" and not args.codeql and not (wanted and "codeql" in wanted):
            status[name] = {"status": "off (use --codeql)"}
            continue
        if not applies(ctx.langs, ctx.extra):
            status[name] = {"status": "n/a for languages"}
            continue
        if binary and not which(binary):
            status[name] = {"status": f"not installed ({hint})"}
            log(f"[-] {name:11s} not installed", "y")
            continue
        log(f"[+] {name:11s} running ...", "c")
        t0 = time.time()
        try:
            res = fn(ctx)
        except Exception as e:  # never let one scanner kill the run
            log(f"    {name} crashed: {e}", "r")
            status[name] = {"status": f"error: {e}"[:80]}
            continue
        status[name] = {"status": f"ok ({time.time() - t0:.0f}s)", "count": len(res)}
        log(f"    {len(res)} raw findings in {time.time() - t0:.0f}s")
        findings += res

    if args.diff:
        ch = changed_files(ctx.root, args.diff)
        if ch is not None:
            before = len(findings)
            findings = [f for f in findings if f.file in ch]
            log(f"[*] --diff {args.diff}: kept {len(findings)}/{before} findings in {len(ch)} changed files")

    if not args.include_tests:
        rx = re.compile(r"(^|/)(tests?|spec|specs|__tests__|e2e|fixtures?|mocks?|examples?|samples?|docs?)(/|$)|\.(test|spec)\.\w+$", re.I)
        findings = [f for f in findings if not rx.search(f.file)]

    findings = dedupe(findings)
    log(f"[*] {len(findings)} unique findings after de-duplication", "b")
    endpoints = map_endpoints(ctx) + map_meteor(ctx) + map_jaxrs(ctx)
    log(f"[*] Mapped {len(endpoints)} endpoints, {sum(1 for e in endpoints if e['leads'])} with access-control leads")

    if args.triage:
        triage(ctx, findings)
        if args.drop_fp:
            findings = [f for f in findings if f.triage.get("verdict") != "false_positive"]

    write_reports(ctx, findings, endpoints, status)
    c = Counter(f.severity for f in findings)
    log(f"\n[✓] Done. critical={c['critical']} high={c['high']} medium={c['medium']} low={c['low']} info={c['info']}", "g")
    log(f"    Report:   {ctx.out / 'report.md'}\n    JSON:     {ctx.out / 'findings.json'}\n    SARIF:    {ctx.out / 'report.sarif'}\n    Raw tool output: {ctx.raw}")


def main():
    ap = argparse.ArgumentParser(description="TrendSAST - multi-scanner SAST + AI triage for bug bounty code review")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="check which scanners are installed")
    s = sub.add_parser("scan", help="scan a source directory")
    s.add_argument("path")
    s.add_argument("-o", "--out", help="output dir (default trendsast-out/<name>-<timestamp>)")
    s.add_argument("--scanners", default="all", help="comma list, e.g. semgrep,bandit,gitleaks (default: all)")
    s.add_argument("--skip", default="", help="comma list of scanners to skip")
    s.add_argument("--offline", action="store_true", help="semgrep: only local rules (no registry packs)")
    s.add_argument("--codeql", action="store_true", help="also run CodeQL (slow, most accurate taint tracking)")
    s.add_argument("--diff", help="only keep findings in files changed in a git range, e.g. v1.2.0..v1.3.0")
    s.add_argument("--include-tests", action="store_true", help="keep findings in tests/examples/docs")
    s.add_argument("--triage", action="store_true", help="AI-triage findings with Claude (needs ANTHROPIC_API_KEY)")
    s.add_argument("--triage-max", type=int, default=40, help="max findings to triage (cost control)")
    s.add_argument("--triage-min", default="medium", choices=list(SEV_RANK), help="min severity to triage")
    s.add_argument("--drop-fp", action="store_true", help="remove AI-confirmed false positives from the report")
    s.add_argument("--model", default=os.environ.get("TRENDSAST_MODEL", "claude-sonnet-5-5"))
    s.add_argument("--min-severity", default="low", choices=list(SEV_RANK), help="min severity in report.md")
    s.add_argument("--timeout", type=int, default=1800, help="per-scanner timeout seconds")
    args = ap.parse_args()
    {"doctor": cmd_doctor, "scan": cmd_scan}[args.cmd](args)


if __name__ == "__main__":
    main()
