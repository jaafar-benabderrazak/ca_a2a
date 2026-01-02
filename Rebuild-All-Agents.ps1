# Rebuild and Redeploy ALL Agents
# Fixes MCP SDK import error across all services

$ErrorActionPreference = "Stop"

# Configuration
$AWS_REGION = "eu-west-3"
$AWS_ACCOUNT_ID = "555043101106"
$PROJECT_NAME = "ca-a2a"
$CLUSTER = "${PROJECT_NAME}-cluster"

$AGENTS = @("orchestrator", "extractor", "validator", "archivist")

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Rebuild and Redeploy ALL Agents"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Agents to rebuild:" -ForegroundColor Yellow
foreach ($agent in $AGENTS) {
    Write-Host "  - $agent" -ForegroundColor White
}
Write-Host ""
Write-Host "This will:" -ForegroundColor Yellow
Write-Host "  - Build images with Python 3.11" -ForegroundColor White
Write-Host "  - Fix MCP SDK import errors" -ForegroundColor White
Write-Host "  - Push to ECR" -ForegroundColor White
Write-Host "  - Update ECS services" -ForegroundColor White
Write-Host ""

# Auto-confirm in non-interactive mode
if ([Environment]::UserInteractive) {
    $confirm = Read-Host "Continue? (y/n)"
    if ($confirm -ne "y" -and $confirm -ne "Y") {
        Write-Host "Aborted by user" -ForegroundColor Yellow
        exit 0
    }
} else {
    Write-Host "Auto-confirming (non-interactive mode)" -ForegroundColor Cyan
}
Write-Host ""

# Step 1: Login to ECR
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Step 1/4: Login to ECR"
Write-Host "==========================================" -ForegroundColor Cyan
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [ERROR] ECR login failed" -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] ECR login successful" -ForegroundColor Green
Write-Host ""

# Step 2: Build all images
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Step 2/4: Build Docker Images"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$buildResults = @{}

foreach ($agent in $AGENTS) {
    Write-Host "Building ${agent}..." -ForegroundColor Yellow
    $IMAGE_URI = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/${agent}:latest"
    
    $startTime = Get-Date
    docker build -f "Dockerfile.${agent}" -t $IMAGE_URI . 2>&1 | Out-Null
    $buildTime = ((Get-Date) - $startTime).TotalSeconds
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Built ${agent} in ${buildTime}s" -ForegroundColor Green
        $buildResults[$agent] = "success"
    } else {
        Write-Host "  [ERROR] Failed to build ${agent}" -ForegroundColor Red
        $buildResults[$agent] = "failed"
    }
}

Write-Host ""
Write-Host "Build Summary:" -ForegroundColor Cyan
foreach ($agent in $AGENTS) {
    $status = $buildResults[$agent]
    if ($status -eq "success") {
        Write-Host "  [OK] $agent" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $agent" -ForegroundColor Red
    }
}

# Check if any builds failed
$failedBuilds = $buildResults.Values | Where-Object { $_ -eq "failed" }
if ($failedBuilds.Count -gt 0) {
    Write-Host ""
    Write-Host "[ERROR] Some builds failed. Aborting deployment." -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 3: Push all images
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Step 3/4: Push Images to ECR"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$pushResults = @{}

foreach ($agent in $AGENTS) {
    Write-Host "Pushing ${agent}..." -ForegroundColor Yellow
    $IMAGE_URI = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/${agent}:latest"
    
    docker push $IMAGE_URI 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Pushed ${agent}" -ForegroundColor Green
        $pushResults[$agent] = "success"
    } else {
        Write-Host "  [ERROR] Failed to push ${agent}" -ForegroundColor Red
        $pushResults[$agent] = "failed"
    }
}

Write-Host ""
Write-Host "Push Summary:" -ForegroundColor Cyan
foreach ($agent in $AGENTS) {
    $status = $pushResults[$agent]
    if ($status -eq "success") {
        Write-Host "  [OK] $agent" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $agent" -ForegroundColor Red
    }
}

# Check if any pushes failed
$failedPushes = $pushResults.Values | Where-Object { $_ -eq "failed" }
if ($failedPushes.Count -gt 0) {
    Write-Host ""
    Write-Host "[ERROR] Some pushes failed. Aborting deployment." -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 4: Update ECS services
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Step 4/4: Update ECS Services"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$updateResults = @{}

foreach ($agent in $AGENTS) {
    Write-Host "Updating ${agent} service..." -ForegroundColor Yellow
    
    aws ecs update-service `
        --cluster $CLUSTER `
        --service $agent `
        --force-new-deployment `
        --region $AWS_REGION `
        --output json 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Update initiated for ${agent}" -ForegroundColor Green
        $updateResults[$agent] = "success"
    } else {
        Write-Host "  [WARN] Failed to update ${agent} (may not exist yet)" -ForegroundColor Yellow
        $updateResults[$agent] = "warning"
    }
}

Write-Host ""
Write-Host "Update Summary:" -ForegroundColor Cyan
foreach ($agent in $AGENTS) {
    $status = $updateResults[$agent]
    if ($status -eq "success") {
        Write-Host "  [OK] $agent" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] $agent" -ForegroundColor Yellow
    }
}
Write-Host ""

# Step 5: Wait for deployments
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Waiting for Deployments"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "ECS is deploying new tasks (2-4 minutes)..." -ForegroundColor Cyan
Write-Host "Process: stop old tasks → start new tasks → health checks" -ForegroundColor DarkGray
Write-Host ""

$maxWait = 240  # 4 minutes
$elapsed = 0
$interval = 15

while ($elapsed -lt $maxWait) {
    Start-Sleep -Seconds $interval
    $elapsed += $interval
    
    $progress = [math]::Round(($elapsed / $maxWait) * 100)
    Write-Host "[$progress%] Elapsed: ${elapsed}s / ${maxWait}s" -ForegroundColor Cyan
    
    # Check if all services are stable
    $allStable = $true
    foreach ($agent in $AGENTS) {
        $status = aws ecs describe-services `
            --cluster $CLUSTER `
            --services $agent `
            --region $AWS_REGION `
            --query 'services[0].{running:runningCount,desired:desiredCount,state:deployments[0].rolloutState}' `
            --output json 2>$null | ConvertFrom-Json
        
        if ($status -and $status.state -ne "COMPLETED") {
            $allStable = $false
        }
    }
    
    if ($allStable) {
        Write-Host ""
        Write-Host "  [OK] All deployments completed!" -ForegroundColor Green
        break
    }
}

if ($elapsed -ge $maxWait) {
    Write-Host ""
    Write-Host "  [WARN] Deployments taking longer than expected" -ForegroundColor Yellow
    Write-Host "  Services may still be deploying. Check status manually." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Deployment Status for All Agents"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

foreach ($agent in $AGENTS) {
    Write-Host "${agent}:" -ForegroundColor Yellow
    aws ecs describe-services `
        --cluster $CLUSTER `
        --services $agent `
        --region $AWS_REGION `
        --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount,Pending:pendingCount}' `
        --output table 2>$null
    Write-Host ""
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Recent Events"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

foreach ($agent in $AGENTS) {
    Write-Host "${agent} - Latest Event:" -ForegroundColor Yellow
    aws ecs describe-services `
        --cluster $CLUSTER `
        --services $agent `
        --region $AWS_REGION `
        --query 'services[0].events[0].message' `
        --output text 2>$null
    Write-Host ""
}

Write-Host "==========================================" -ForegroundColor Green
Write-Host "Verification"
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

$ALB_URL = "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

Write-Host "Waiting 30s for ALB to detect new tasks..." -ForegroundColor Cyan
Start-Sleep -Seconds 30
Write-Host ""

Write-Host "Testing orchestrator health..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$ALB_URL/health" -Method Get -TimeoutSec 10
    Write-Host "  [OK] Orchestrator is healthy" -ForegroundColor Green
    Write-Host "    Status: $($response.status)" -ForegroundColor White
    Write-Host "    Agent: $($response.agent)" -ForegroundColor White
    Write-Host "    Version: $($response.version)" -ForegroundColor White
} catch {
    Write-Host "  [ERROR] Orchestrator health check failed: $_" -ForegroundColor Red
}
Write-Host ""

Write-Host "Testing upload endpoint..." -ForegroundColor Yellow
try {
    $testResponse = Invoke-WebRequest -Uri "$ALB_URL/upload" -Method Get -TimeoutSec 10 -SkipHttpErrorCheck
    if ($testResponse.StatusCode -eq 405) {
        Write-Host "  [OK] Upload endpoint exists (405 = Method Not Allowed for GET)" -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Upload endpoint response: $($testResponse.StatusCode)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "  [WARN] Could not verify upload endpoint: $_" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Green
Write-Host "Deployment Complete!"
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "All agents rebuilt with:" -ForegroundColor Cyan
Write-Host "  - Python 3.11" -ForegroundColor White
Write-Host "  - Fixed MCP imports" -ForegroundColor White
Write-Host "  - Upload handler (orchestrator)" -ForegroundColor White
Write-Host ""
Write-Host "ALB URL:" -ForegroundColor Yellow
Write-Host "  $ALB_URL" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Test file upload:" -ForegroundColor White
Write-Host "     .\Test-UploadViaALB.ps1" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  2. Monitor logs:" -ForegroundColor White
Write-Host "     aws logs tail /ecs/ca-a2a/orchestrator --follow --region $AWS_REGION" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  3. Check all services:" -ForegroundColor White
Write-Host "     aws ecs list-services --cluster $CLUSTER --region $AWS_REGION" -ForegroundColor DarkGray
Write-Host ""

