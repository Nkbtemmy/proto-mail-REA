#!/usr/bin/env bash
# Turnkey runner: hand a prompt file to manzi-14b (Qwen) and save its output.
# Usage:  ./ask-manzi.sh prompts/A1-cli-extra-commands.md
set -euo pipefail
cd "$(dirname "$0")"
PROMPT="${1:?usage: ./ask-manzi.sh <prompt-file.md>}"
base="$(basename "$PROMPT" .md)"
OUT="outputs/${base}.out.txt"
echo ">> running manzi-14b on $PROMPT (14B model is slow, ~10 tok/s; be patient)"
python3 run_manzi.py "$PROMPT" "$OUT"
echo ">> saved: ai-collab/$OUT"
echo ">> GOLDEN RULE: review it, paste code into the right file, then:"
echo "     mvn -f ../reference-system/pom.xml test"
echo "   If the build goes RED, manzi hallucinated — fix or revert. Never keep a red build."
