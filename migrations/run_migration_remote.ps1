#!/usr/bin/env pwsh
# CA-A2A v5.1 - Execute Migration from ECS Container
# This script copies the migration to an ECS task and executes it from within the VPC

param(
    [string]$Region = "eu-west-3",
    [string]$Cluster = "ca-a2a-cluster",
    [string]$Service = "orchestrator"
)

Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "CA-A2A v5.1 - Remote Migration Executor" -ForegroundColor Yellow
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan

# Step 1: Get running task
Write-Host "[1/6] Finding running $Service task..." -ForegroundColor Cyan
$taskArn = (aws ecs list-tasks --cluster $Cluster --service-name $Service --region $Region --query 'taskArns[0]' --output text)

if ([string]::IsNullOrEmpty($taskArn) -or $taskArn -eq "None") {
    Write-Host "[ERROR] No running tasks found for service $Service" -ForegroundColor Red
    exit 1
}

$taskId = $taskArn.Split('/')[-1]
Write-Host "[SUCCESS] Found task: $taskId" -ForegroundColor Green

# Step 2: Check if ECS Exec is enabled
Write-Host "[2/6] Checking if ECS Exec is enabled..." -ForegroundColor Cyan
$execEnabled = (aws ecs describe-tasks --cluster $Cluster --tasks $taskArn --region $Region --query 'tasks[0].enableExecuteCommand' --output text)

if ($execEnabled -ne "True") {
    Write-Host "[WARN] ECS Exec is not enabled on this task" -ForegroundColor Yellow
    Write-Host "[INFO] Enabling ECS Exec on service..." -ForegroundColor Cyan
    
    aws ecs update-service --cluster $Cluster --service $Service --enable-execute-command --region $Region --query 'service.serviceName' --output text | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to enable ECS Exec" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "[INFO] ECS Exec enabled. Waiting for new task to start..." -ForegroundColor Cyan
    Start-Sleep -Seconds 30
    
    # Get new task
    $taskArn = (aws ecs list-tasks --cluster $Cluster --service-name $Service --region $Region --query 'taskArns[0]' --output text)
    $taskId = $taskArn.Split('/')[-1]
    Write-Host "[SUCCESS] New task: $taskId" -ForegroundColor Green
} else {
    Write-Host "[SUCCESS] ECS Exec is enabled" -ForegroundColor Green
}

# Step 3: Create migration package
Write-Host "[3/6] Creating migration package..." -ForegroundColor Cyan
$tempDir = Join-Path $env:TEMP "ca-a2a-migration"
if (Test-Path $tempDir) {
    Remove-Item $tempDir -Recurse -Force
}
New-Item -ItemType Directory -Path $tempDir | Out-Null

# Copy migration files
Copy-Item -Path "001_create_revoked_tokens_table.sql" -Destination $tempDir
Copy-Item -Path "run_migration_python.py" -Destination $tempDir

# Create a simple runner script for the container
$runnerScript = @"
#!/bin/bash
set -e

echo "====================================================="
echo "CA-A2A v5.1 - Database Migration"
echo "====================================================="

# Install asyncpg if not present
pip install asyncpg --quiet 2>/dev/null || true

# Get DB password from Secrets Manager
export DB_PASSWORD=\`aws secretsmanager get-secret-value --secret-id ca-a2a/db-password --region eu-west-3 --query SecretString --output text\`

# Run migration
cd /tmp/migration
python run_migration_python.py

echo ""
echo "✅ Migration completed successfully"
"@

Set-Content -Path (Join-Path $tempDir "run_migration.sh") -Value $runnerScript
Write-Host "[SUCCESS] Migration package created" -ForegroundColor Green

# Step 4: Copy files to container
Write-Host "[4/6] Uploading migration files to container..." -ForegroundColor Cyan
Write-Host "[INFO] This requires ECS Exec to be properly configured..." -ForegroundColor Yellow

# Create migration directory in container
aws ecs execute-command --cluster $Cluster --task $taskArn --container $Service --interactive --command "/bin/sh -c 'mkdir -p /tmp/migration'" --region $Region 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to create directory in container" -ForegroundColor Red
    Write-Host "[INFO] ECS Exec may not be fully configured. See AWS documentation:" -ForegroundColor Yellow
    Write-Host "       https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html" -ForegroundColor Yellow
    exit 1
}

Write-Host "[SUCCESS] Directory created in container" -ForegroundColor Green

# Step 5: Upload files (Note: This is a placeholder - actual file copy requires additional tools)
Write-Host "[5/6] Note: File upload to ECS container requires AWS Session Manager Plugin" -ForegroundColor Yellow
Write-Host "[INFO] Alternative: Use AWS Console RDS Query Editor" -ForegroundColor Cyan
Write-Host ""
Write-Host "MANUAL STEPS:" -ForegroundColor Yellow
Write-Host "1. Go to AWS Console > RDS > Query Editor" -ForegroundColor White
Write-Host "2. Select database: documents-db" -ForegroundColor White
Write-Host "3. Use secret: ca-a2a/db-password" -ForegroundColor White
Write-Host "4. Execute this SQL:" -ForegroundColor White
Write-Host ""
Get-Content "001_create_revoked_tokens_table.sql" | Write-Host -ForegroundColor Gray
Write-Host ""

Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "⚠️  MIGRATION REQUIRES MANUAL EXECUTION" -ForegroundColor Yellow
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 59) -ForegroundColor Cyan

# Cleanup
Remove-Item $tempDir -Recurse -Force

