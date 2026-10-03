# PowerShell script to execute the unified demo runner
$ErrorActionPreference = "Stop"

Write-Host "================================================================================"
Write-Host "Starting Nasiko Veil Demo..."
Write-Host "================================================================================"

$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
if (-not $env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = "E:\cargo_target"
}

cargo run --release -p nasiko-llm-router --example mock_pipeline_demo
