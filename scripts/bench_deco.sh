#!/usr/bin/env bash
# bench_deco.sh — Build CanDenizGokgedik/decoTls12MtE and measure single DECO notary time.
#
# Outputs: DECO_SINGLE_MS=<ms>
#
# Usage:
#   ./scripts/bench_deco.sh              # 1 run
#   ./scripts/bench_deco.sh --runs 3     # average over 3 runs
#
# Requirements: docker, git
# First run: ~30-45 min (Docker build with emp-toolkit + jsnark compilation)
# Subsequent runs: ~2-3 min (image cached)

set -euo pipefail

REPO_URL="https://github.com/CanDenizGokgedik/decoTls12MtE.git"
IMAGE_NAME="tls-gnark-deco-baseline"
RUNS=1
CONTAINER_ID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs) RUNS="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

cleanup() {
  if [[ -n "$CONTAINER_ID" ]]; then
    docker stop "$CONTAINER_ID" >/dev/null 2>&1 || true
    docker rm   "$CONTAINER_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if ! command -v docker &>/dev/null; then
  echo "ERROR: docker not found." >&2; exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)/.deco-baseline"

# Clone repo (shallow, no submodules — Dockerfile handles gtest via HTTPS RUN step)
if [[ ! -d "$REPO_DIR/.git" ]]; then
  echo "[deco-bench] Cloning CanDenizGokgedik/decoTls12MtE..." >&2
  git clone --depth=1 "$REPO_URL" "$REPO_DIR" >&2
else
  echo "[deco-bench] Repo already at $REPO_DIR" >&2
  git -C "$REPO_DIR" pull --ff-only >&2 || true
fi

# Copy local install.sh fixes (limits make -j2, removes MULTICORE) into the cloned repo
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_DECO_DIR="$(cd "$SCRIPT_DIR/../../decoTls12MtE" 2>/dev/null && pwd)" || LOCAL_DECO_DIR=""
if [[ -n "$LOCAL_DECO_DIR" && -f "$LOCAL_DECO_DIR/install.sh" ]]; then
  echo "[deco-bench] Copying local install.sh fixes from $LOCAL_DECO_DIR..." >&2
  cp "$LOCAL_DECO_DIR/install.sh" "$REPO_DIR/install.sh"
else
  echo "[deco-bench] Local decoTls12MtE not found — patching install.sh in-place..." >&2
  # Fallback: patch directly in the cloned repo
  sed -i.bak 's/make -j\$(nproc)/make -j2/g' "$REPO_DIR/install.sh"
  sed -i.bak 's/-DMULTICORE=ON //g' "$REPO_DIR/install.sh"
fi

# Patch the cloned Dockerfile to install cmake>=3.25 from Kitware APT
# (Ubuntu 20.04 ships cmake 3.16 which is too old for emp-toolkit main)
echo "[deco-bench] Patching Dockerfile: cmake>=3.25 via Kitware APT..." >&2
cat > "$REPO_DIR/Dockerfile" <<'DOCKERFILE_EOF'
FROM --platform=linux/amd64 ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y wget git gcc

RUN wget -P /tmp https://dl.google.com/go/go1.17.7.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go1.17.7.linux-amd64.tar.gz
RUN rm /tmp/go1.17.7.linux-amd64.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

WORKDIR /root
RUN apt-get update && apt-get install -y \
  build-essential \
  git \
  libssl-dev \
  sudo \
  wget \
  python3 \
  vim \
  libgmp3-dev \
  libprocps-dev \
  python3-markdown \
  openjdk-17-jdk \
  junit4 \
  libboost-program-options-dev \
  pkg-config \
  gpg \
  lsb-release \
  ca-certificates

# Install cmake >= 3.25 from Kitware APT (Ubuntu 20.04 ships 3.16 which is too old for emp-toolkit main)
RUN wget -qO- https://apt.kitware.com/keys/kitware-archive-latest.asc \
      | gpg --dearmor - > /usr/share/keyrings/kitware-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ focal main" \
      > /etc/apt/sources.list.d/kitware.list && \
    apt-get update && apt-get install -y cmake

# Limit parallel compilation to 2 jobs to prevent Docker Desktop OOM on macOS
ENV MAKEFLAGS="-j2"

RUN mkdir -p ./deco-oracle
ADD jsnark/ ./deco-oracle/jsnark
ADD 2pc/ ./deco-oracle/2pc
ADD app/ ./deco-oracle/app
ADD src/ ./deco-oracle/src
ADD README.md ./deco-oracle/
ADD install.sh .
ADD config.yml ./deco-oracle

# Clone googletest via HTTPS (libsnark .gitmodules uses SSH which fails in Docker without keys)
RUN rm -rf ~/deco-oracle/jsnark/libsnark/depends/gtest && \
    git clone --depth=1 https://github.com/google/googletest.git \
        ~/deco-oracle/jsnark/libsnark/depends/gtest

RUN ["/bin/bash", "install.sh"]
CMD ["/bin/bash"]
DOCKERFILE_EOF

# Build Docker image
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "[deco-bench] Building Docker image (first run: ~30-45 min)..." >&2
  docker build --platform=linux/amd64 -t "$IMAGE_NAME" "$REPO_DIR" >&2
  echo "[deco-bench] Docker image built." >&2
else
  echo "[deco-bench] Docker image cached — skipping build." >&2
fi

echo "[deco-bench] Running DECO 3P-HS benchmark ($RUNS run(s))..." >&2

total_ms=0

for run in $(seq 1 "$RUNS"); do
  echo "[deco-bench] Run $run/$RUNS..." >&2

  CONTAINER_ID=$(docker run -d --platform=linux/amd64 "$IMAGE_NAME" sleep 300)
  echo "[deco-bench]   Container: $CONTAINER_ID" >&2

  # Generate TLS certs (needed by server + prover)
  docker exec "$CONTAINER_ID" bash -c \
    "cd ~/deco-oracle/app && bash cert.sh >/dev/null 2>&1" || true

  # Start server (TLS server the prover connects to)
  docker exec -d "$CONTAINER_ID" bash -c \
    "cd ~/deco-oracle/app/server && go run server.go >/tmp/server.log 2>&1"
  sleep 3

  # Start verifier (participates in 3P-HS)
  docker exec -d "$CONTAINER_ID" bash -c \
    "cd ~/deco-oracle/app/verifier && go run verifier.go >/tmp/verifier.log 2>&1"
  sleep 3

  # Run prover — captures "prover: total andshake took Xs" timing
  PROVER_OUT=$(docker exec "$CONTAINER_ID" bash -c \
    "cd ~/deco-oracle/app/prover && go run prover.go 2>&1") || true
  echo "[deco-bench]   Prover output:" >&2
  echo "$PROVER_OUT" >&2

  # Parse timing from "total andshake took Xs" (note: typo in original code)
  run_ms=0
  if echo "$PROVER_OUT" | grep -q "took"; then
    TIME_STR=$(echo "$PROVER_OUT" | grep "took" | grep -oE '[0-9]+(\.[0-9]+)?(ms|s|µs|m[0-9])' | head -1)
    echo "[deco-bench]   Parsed time: '$TIME_STR'" >&2
    if echo "$TIME_STR" | grep -qE 'ms$'; then
      run_ms=$(echo "$TIME_STR" | grep -oE '^[0-9]+' | head -1)
    elif echo "$TIME_STR" | grep -qE 'µs$'; then
      us=$(echo "$TIME_STR" | grep -oE '^[0-9]+' | head -1)
      run_ms=$(( us / 1000 ))
    elif echo "$TIME_STR" | grep -qE 's$'; then
      sec=$(echo "$TIME_STR" | grep -oE '^[0-9]+(\.[0-9]+)?' | head -1)
      run_ms=$(printf "%.0f" "$(echo "$sec * 1000" | bc)")
    fi
  else
    # Fallback: measure wall-clock around the prover invocation
    echo "[deco-bench]   No timing in output — using wall-clock." >&2
    t0=$(date +%s%3N)
    docker exec "$CONTAINER_ID" bash -c \
      "cd ~/deco-oracle/app/prover && go run prover.go >/dev/null 2>&1" || true
    t1=$(date +%s%3N)
    run_ms=$(( t1 - t0 ))
  fi

  echo "[deco-bench]   Run $run: ${run_ms} ms" >&2
  total_ms=$(( total_ms + run_ms ))

  docker stop "$CONTAINER_ID" >/dev/null 2>&1 || true
  docker rm   "$CONTAINER_ID" >/dev/null 2>&1 || true
  CONTAINER_ID=""
done

avg_ms=$(( total_ms / RUNS ))
echo "[deco-bench] Average over $RUNS run(s): ${avg_ms} ms" >&2
echo "DECO_SINGLE_MS=${avg_ms}"