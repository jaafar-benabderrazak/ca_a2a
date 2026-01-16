# CA-A2A Attack Scenario Test Runner for AWS Environment (PowerShell)
# =====================================================================
#
# Runs attack scenario tests against AWS ECS deployment
#
# Usage:
#   .\Run-AttackTests-AWS.ps1 [OPTIONS]
#
# Examples:
#   .\Run-AttackTests-AWS.ps1 -Token "eyJhbGc..."
#   .\Run-AttackTests-AWS.ps1 -Username admin -Password secret
#   .\Run-AttackTests-AWS.ps1 -Token "..." -GenerateHTML

param(
    [string]$Token = "",
    [string]$Username = "test-user",
    [string]$Password = "",
    [string]$AlbDns = "",
    [switch]$Verbose,
    [switch]$GenerateHTML,
    [switch]$SkipOnError
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "CA-A2A ATTACK SCENARIO TESTS - AWS ENVIRONMENT" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Load AWS configuration
if (Test-Path "ca-a2a-config.env") {
    Write-Host "[✓] Loading AWS configuration from ca-a2a-config.env" -ForegroundColor Green
    
    Get-Content "ca-a2a-config.env" | ForEach-Object {
        if ($_ -match '^export\s+([^=]+)=(.*)$') {
            $name = $matches[1]
            $value = $matches[2] -replace '"', ''
            Set-Item -Path "env:$name" -Value $value
        }
    }
    
    if ([string]::IsNullOrEmpty($AlbDns) -and $env:ALB_DNS) {
        $AlbDns = $env:ALB_DNS
    }
} else {
    Write-Host "[⚠] ca-a2a-config.env not found" -ForegroundColor Yellow
}

# Verify ALB DNS
if ([string]::IsNullOrEmpty($AlbDns)) {
    Write-Host "[✗] ALB DNS not configured" -ForegroundColor Red
    Write-Host "   Please provide -AlbDns or set ALB_DNS in ca-a2a-config.env" -ForegroundColor Red
    exit 1
}

Write-Host "[✓] ALB DNS: $AlbDns" -ForegroundColor Green

# Step 2: Set environment variables for tests
$env:TEST_ENV = "aws"
$env:ORCHESTRATOR_URL = "http://$AlbDns"
$env:KEYCLOAK_URL = "http://keycloak.ca-a2a.local:8080"
$env:KEYCLOAK_REALM = "ca-a2a"
$env:KEYCLOAK_CLIENT_ID = "ca-a2a-agents"
$env:TEST_USERNAME = $Username
$env:TEST_VERBOSE = if ($Verbose) { "true" } else { "false" }
$env:SKIP_ON_CONNECTION_ERROR = if ($SkipOnError) { "true" } else { "false" }

if (-not [string]::IsNullOrEmpty($Password)) {
    $env:TEST_PASSWORD = $Password
}

if (-not [string]::IsNullOrEmpty($Token)) {
    $env:TEST_JWT_TOKEN = $Token
}

# Step 3: Check Python dependencies
Write-Host ""
Write-Host "Checking Python dependencies..."
try {
    python -c "import pytest, requests, jwt" 2>$null
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Host "[✓] Dependencies installed" -ForegroundColor Green
} catch {
    Write-Host "[✗] Missing dependencies" -ForegroundColor Red
    Write-Host "   Installing required packages..." -ForegroundColor Yellow
    pip install pytest requests "PyJWT[crypto]" pytest-html
}

# Step 4: Run environment setup
Write-Host ""
Write-Host "Running environment setup..."
Write-Host "================================================================================" -ForegroundColor Cyan
python setup_test_environment.py

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[✗] Environment setup failed" -ForegroundColor Red
    
    if (-not $SkipOnError) {
        Write-Host "   Use -SkipOnError to continue anyway" -ForegroundColor Yellow
        exit 1
    } else {
        Write-Host "   Continuing anyway (-SkipOnError enabled)" -ForegroundColor Yellow
    }
}

# Step 5: Run tests
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "RUNNING ATTACK SCENARIO TESTS" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

$pytestArgs = @("-v", "--tb=short")

if ($Verbose) {
    $pytestArgs += "-s"
}

if ($GenerateHTML) {
    $reportFile = "attack_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $pytestArgs += "--html=$reportFile"
    $pytestArgs += "--self-contained-html"
    Write-Host "HTML report will be saved to: $reportFile"
    Write-Host ""
}

# Run pytest
python -m pytest test_attack_scenarios.py @pytestArgs

$testExitCode = $LASTEXITCODE

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "TEST EXECUTION COMPLETE" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

switch ($testExitCode) {
    0 {
        Write-Host "[✓] All tests passed" -ForegroundColor Green
    }
    1 {
        Write-Host "[✗] Some tests failed - Security vulnerabilities detected" -ForegroundColor Red
    }
    5 {
        Write-Host "[⚠] No tests collected" -ForegroundColor Yellow
    }
    default {
        Write-Host "[✗] Test execution error (exit code: $testExitCode)" -ForegroundColor Red
    }
}

if ($GenerateHTML -and (Test-Path $reportFile)) {
    Write-Host ""
    Write-Host "View HTML report: $reportFile"
}

Write-Host "================================================================================" -ForegroundColor Cyan

exit $testExitCode

