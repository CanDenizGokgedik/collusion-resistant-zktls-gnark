#!/usr/bin/env bash
# quicktest.sh — fast sanity check for tls-gnark (stub mode, no real Groth16).
#
# Usage:
#   ./quicktest.sh           # stub — all tests in <5s
#   ./quicktest.sh --prove   # real proving (bench_dctls Mode 1 + pipeline)
#   ./quicktest.sh --full    # real proving including Mode 2 (~15-30 min)

set -euo pipefail

PROVE=false
FULL=false
for arg in "$@"; do
  [[ "$arg" == "--prove" ]] && PROVE=true
  [[ "$arg" == "--full"  ]] && FULL=true
done

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
NC="\033[0m"

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; exit 1; }
info() { echo -e "  ${YELLOW}→${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  tls-gnark quick-test                                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── 1. Build ───────────────────────────────────────────────────────────────
info "Building..."
go build ./... && pass "go build ./..." || fail "build failed"

# ── 2. Unit tests ──────────────────────────────────────────────────────────
info "Running unit tests..."
go test ./... -timeout 60s -count=1 2>&1 | tail -5
pass "go test ./..."

# ── 3. bench_dctls stub ────────────────────────────────────────────────────
info "bench_dctls --stub --mode key"
go run ./cmd/bench_dctls --stub --mode key | grep -E "R1CS|prove_avg|JSON" | head -4
pass "bench_dctls Mode 1 stub"

# ── 4. bench_pipeline stub ────────────────────────────────────────────────
info "bench_pipeline --stub"
go run ./cmd/bench_pipeline --stub | grep -E "2-of-3|3-of-5|50-of-99"
pass "bench_pipeline stub (9 configs)"

# ── 5. Real proving (optional) ─────────────────────────────────────────────
if $PROVE || $FULL; then
  echo ""
  info "bench_dctls --mode key (real Groth16, ~3 iterations, ~5s total)..."
  go run ./cmd/bench_dctls --mode key
  pass "bench_dctls Mode 1 real proof"
fi

if $FULL; then
  echo ""
  info "bench_dctls --mode prf (real Groth16, ~1.5M R1CS — may take 15-30 min)..."
  go run ./cmd/bench_dctls --mode prf
  pass "bench_dctls Mode 2 real proof"
fi

echo ""
echo "  All checks passed."
echo ""
if ! $PROVE && ! $FULL; then
  echo "  Tip: run './quicktest.sh --prove' for real Groth16 timing."
  echo "       run './quicktest.sh --full'  for full Mode 2 (~30 min)."
fi
echo ""