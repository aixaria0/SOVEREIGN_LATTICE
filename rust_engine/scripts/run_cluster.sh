#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/.."

cd "${ROOT_DIR}"

echo "🔨 Building Sovereign-Lattice binaries..."
cargo build --release

PIDS=()

cleanup() {
    echo -e "\n🛑 Tearing down cluster nodes..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo "✅ Cluster shut down cleanly."
}

trap cleanup SIGINT SIGTERM EXIT

echo "🚀 Bootstrapping 4-node Sovereign-Lattice cluster..."

for id in {0..3}; do
    PORT=$((8000 + id))
    echo "   -> Spawning Validator Node ${id} on 127.0.0.1:${PORT}..."
    
    NODE_ID="${id}" \
    TOTAL_NODES=4 \
    THRESHOLD=3 \
    BIND_ADDR="127.0.0.1:${PORT}" \
    ./target/release/sovereign_lattice > "node_${id}.log" 2>&1 &
    
    PIDS+=($!)
done

echo "⏳ Giving nodes 2 seconds to initialize DKG and lock PBFT..."
sleep 2

echo "📡 Checking active sockets..."
for id in {0..3}; do
    PORT=$((8000 + id))
    if nc -z 127.0.0.1 "${PORT}" 2>/dev/null; then
        echo "   [ONLINE] Node ${id} listening on port ${PORT}."
    else
        echo "   [WARNING] Node ${id} socket not detected on port ${PORT} yet."
    fi
done

echo ""
echo "🎉 Cluster is live! Press Ctrl+C to terminate all nodes."
echo "Tail logs using: tail -f node_*.log"

wait

