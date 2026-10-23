#!/usr/bin/env bash
# Runs every benchmark and writes a results file with the machine, the
# toolchain, the crate versions, and criterion's estimates.
# Usage: scripts/run.sh [label]
set -euo pipefail
cd "$(dirname "$0")/.."
label="${1:-run}"
stamp="$(date -u +%Y-%m-%d)"
commit="$(git rev-parse --short=12 HEAD 2>/dev/null || echo uncommitted)"
out="results/${stamp}-${commit}-${label}.md"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}"
cargo test --release --test equivalence
cargo bench --bench cookies -- --noplot 2>&1 | tee "results/${label}.tmp"
{
  echo "# cookie-net-bench results: ${label}"
  echo
  echo "- Date (UTC): ${stamp}; commit ${commit}"
  echo "- rustc: $(rustc --version)"
  echo "- CPU: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //' || echo unknown)"
  echo "- Crates: $(cargo tree --depth 1 --prefix none 2>/dev/null | grep -E '^(cookie-net|cookie|biscotti|cookie_store) ' | sort -u | tr '\n' ' ')"
  echo
  echo '```'
  grep -E '^c[0-9]+_|time:' "results/${label}.tmp"
  echo '```'
} > "$out"
rm -f "results/${label}.tmp"
echo "wrote $out"
