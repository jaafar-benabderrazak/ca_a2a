# CA-A2A v5.1 Database Migration Script
# Executes migration from Windows PowerShell

Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "CA-A2A DATABASE MIGRATION v5.1" -ForegroundColor Yellow
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan

# Step 1: Retrieve DB password from Secrets Manager
Write-Host "[1/4] Retrieving database password from Secrets Manager..." -ForegroundColor Cyan
try {
    $DB_PASSWORD = aws secretsmanager get-secret-value --secret-id ca-a2a/db-password --region eu-west-3 --query SecretString --output text
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to retrieve password from Secrets Manager" -ForegroundColor Red
        exit 1
    }
    Write-Host "[SUCCESS] Password retrieved (length: $($DB_PASSWORD.Length))" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to retrieve password: $_" -ForegroundColor Red
    exit 1
}

# Step 2: Set environment variable
Write-Host "[2/4] Setting environment variable..." -ForegroundColor Cyan
$env:DB_PASSWORD = $DB_PASSWORD
Write-Host "[SUCCESS] Environment variable set" -ForegroundColor Green

# Step 3: Check if asyncpg is installed
Write-Host "[3/4] Checking Python dependencies..." -ForegroundColor Cyan
$asyncpgCheck = python -c "import asyncpg; print('OK')" 2>$null
if ($asyncpgCheck -ne "OK") {
    Write-Host "[WARN] asyncpg not found, installing..." -ForegroundColor Yellow
    pip install asyncpg --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to install asyncpg" -ForegroundColor Red
        exit 1
    }
    Write-Host "[SUCCESS] asyncpg installed" -ForegroundColor Green
} else {
    Write-Host "[SUCCESS] asyncpg is installed" -ForegroundColor Green
}

# Step 4: Execute migration
Write-Host "[4/4] Executing database migration..." -ForegroundColor Cyan
Write-Host ""

$migrationPath = Join-Path $PSScriptRoot "run_migration_python.py"
python $migrationPath

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "=" -NoNewline -ForegroundColor Cyan
    Write-Host ("=" * 59) -ForegroundColor Cyan
    Write-Host "✅ MIGRATION COMPLETED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "=" -NoNewline -ForegroundColor Cyan
    Write-Host ("=" * 59) -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "=" -NoNewline -ForegroundColor Red
    Write-Host ("=" * 59) -ForegroundColor Red
    Write-Host "❌ MIGRATION FAILED" -ForegroundColor Red
    Write-Host "=" -NoNewline -ForegroundColor Red
    Write-Host ("=" * 59) -ForegroundColor Red
    Write-Host ""
    Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
    Write-Host "1. Check if RDS is accessible from your network" -ForegroundColor Yellow
    Write-Host "2. Verify security group allows inbound 5432 from your IP" -ForegroundColor Yellow
    Write-Host "3. Try running from an EC2 instance in the VPC" -ForegroundColor Yellow
    Write-Host "4. Use RDS Query Editor in AWS Console as alternative" -ForegroundColor Yellow
    exit 1
}

