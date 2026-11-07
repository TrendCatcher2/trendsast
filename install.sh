#!/usr/bin/env bash
# TrendSAST installer - Linux (Kali/Ubuntu/Debian) and macOS.
# Usage:  bash install.sh            # all scanners except CodeQL
#         bash install.sh --codeql   # also download CodeQL bundle (~1 GB)
set -u
BIN="$HOME/.local/bin"; mkdir -p "$BIN"
export PATH="$BIN:$HOME/go/bin:$PATH"
OS=$(uname -s | tr '[:upper:]' '[:lower:]'); ARCH=$(uname -m)
ok(){ printf "\033[32m[OK]\033[0m %s\n" "$1"; }; warn(){ printf "\033[33m[!!]\033[0m %s\n" "$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }

pipi(){ # install python CLI tools; prefer pipx (isolated), fall back to pip --user
  for p in "$@"; do
    if have pipx; then pipx install "$p" >/dev/null 2>&1 || pipx upgrade "$p" >/dev/null 2>&1
    else python3 -m pip install --user -q "$p" 2>/dev/null || python3 -m pip install --user -q --break-system-packages "$p"; fi
  done
}

echo "== Python-based scanners"
pipi semgrep bandit njsscan mobsfscan checkov slither-analyzer solc-select
for t in semgrep bandit njsscan mobsfscan checkov slither; do have $t && ok $t || warn "$t failed"; done

echo "== Binary scanners (to $BIN)"
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$BIN" >/dev/null 2>&1 && ok trivy || warn trivy
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$BIN" >/dev/null 2>&1 && ok trufflehog || warn trufflehog
curl -sSfL https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b "$BIN" >/dev/null 2>&1 && ok gosec || warn gosec

# gitleaks
case "$ARCH" in x86_64|amd64) GA=x64;; aarch64|arm64) GA=arm64;; *) GA=x64;; esac
GV=$(curl -sI https://github.com/gitleaks/gitleaks/releases/latest | grep -i '^location:' | sed 's#.*/tag/##' | tr -d '\r\n')
if [ -n "$GV" ]; then
  curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/${GV}/gitleaks_${GV#v}_${OS}_${GA}.tar.gz" | tar -xz -C "$BIN" gitleaks && ok gitleaks || warn gitleaks
else warn "gitleaks (GitHub API rate-limited? retry later)"; fi

# hadolint
HA=$( [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ] && echo arm64 || echo x86_64 )
HO=$( [ "$OS" = "darwin" ] && echo Darwin || echo Linux )
curl -sSfL -o "$BIN/hadolint" "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-${HO}-${HA}" && chmod +x "$BIN/hadolint" && ok hadolint || warn hadolint

# brakeman (Ruby) / aderyn (Solidity) - only if their toolchains exist
have gem && (gem install --user-install brakeman -N >/dev/null 2>&1 && ok brakeman || warn brakeman) || warn "brakeman skipped (install ruby first)"
have npm && (npm install -g @cyfrin/aderyn >/dev/null 2>&1 && ok aderyn || warn aderyn) || warn "aderyn skipped (install nodejs/npm first)"
have solc-select && (solc-select install 0.8.24 >/dev/null 2>&1; solc-select use 0.8.24 >/dev/null 2>&1; ok "solc 0.8.24 for slither")

if [ "${1:-}" = "--codeql" ]; then
  echo "== CodeQL bundle (large download)"
  CB=$( [ "$OS" = "darwin" ] && echo osx64 || echo linux64 )
  mkdir -p "$HOME/.local/share" && curl -sSfL "https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-${CB}.tar.gz" \
    | tar -xz -C "$HOME/.local/share" && ln -sf "$HOME/.local/share/codeql/codeql" "$BIN/codeql" && ok codeql || warn codeql
fi

echo
echo "Add this to ~/.bashrc or ~/.zshrc if not already there:"
echo '  export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.gem/ruby/*/bin:$PATH"'
echo "Then run:  python3 trendsast.py doctor"
