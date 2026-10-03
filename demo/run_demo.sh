#!/usr/bin/env bash
set -euo pipefail

echo "================================================================================"
echo "Starting Nasiko Veil Demo..."
echo "================================================================================"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-E:/cargo_target}"

cargo run --release -p nasiko-llm-router --example mock_pipeline_demo
