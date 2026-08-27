#!/usr/bin/env bash
# Renders the real run to docs/hero.png. No mock terminal, no hand editing: the command below is
# the one in the Makefile and the output is whatever it printed, including the timings.
set -euo pipefail
cd "$(dirname "$0")/.."

RAW=$(mktemp)
OUT=$(mktemp)
FORCE_COLOR=1 make superset > "$RAW" 2>&1 || true

printf '\033[38;5;245m~/code/sparrow\033[0m $ make superset\n' > "$OUT"
sed -n '1,42p' "$RAW" >> "$OUT"

freeze "$OUT" --language ansi -o docs/hero.png --window --width 1180 --padding 20,30
rm -f "$RAW" "$OUT"
echo "wrote docs/hero.png"
