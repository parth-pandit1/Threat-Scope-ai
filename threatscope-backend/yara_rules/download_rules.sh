#!/bin/bash
# ============================================================
# ThreatScope AI — Download Public YARA Rules
# ============================================================
# Fetches curated YARA rule sets from the Yara-Rules community
# repository for use in the ThreatScope scanning engine.
#
# Usage:
#   chmod +x yara_rules/download_rules.sh
#   ./yara_rules/download_rules.sh
#
# After downloading, restart the worker to reload rules:
#   docker compose restart worker
# ============================================================

set -euo pipefail

RULES_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_URL="https://raw.githubusercontent.com/Yara-Rules/rules/master"

echo "═══ ThreatScope AI — YARA Rule Downloader ═══"
echo "Target directory: $RULES_DIR"
echo ""

# Rule files to download (curated for malware analysis)
declare -a RULE_FILES=(
    # RATs
    "malware/RAT_RemcosRAT.yar"
    "malware/RAT_Ratankba.yar"
    # General malware
    "malware/MALW_Ransomware.yar"
    "malware/MALW_Trojan.yar"
    "malware/MALW_Backdoor.yar"
    # Packers
    "Packers/packer.yar"
    # Anti-debug / Anti-VM
    "antidebug_antivm/antidebug_antivm.yar"
    # CVE exploits
    "CVE_Rules/CVE-2017-11882.yar"
    # Webshells
    "webshells/webshell.yar"
)

SUCCESS=0
FAILED=0

for rule in "${RULE_FILES[@]}"; do
    target_path="$RULES_DIR/$rule"
    target_dir="$(dirname "$target_path")"

    mkdir -p "$target_dir"

    echo -n "  Downloading: $rule ... "
    if curl -sf --connect-timeout 10 "$BASE_URL/$rule" -o "$target_path" 2>/dev/null; then
        echo "✔"
        SUCCESS=$((SUCCESS + 1))
    else
        echo "✘ (not found or network error)"
        # Remove empty file if curl created one
        [ -f "$target_path" ] && [ ! -s "$target_path" ] && rm "$target_path"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "═══ Download complete ═══"
echo "  Downloaded: $SUCCESS"
echo "  Failed:     $FAILED"
echo ""
echo "Custom rules are in: $RULES_DIR/custom/"
echo "Run 'docker compose restart worker' to reload rules."
