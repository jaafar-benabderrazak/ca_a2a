# Rebuild and Redeploy Orchestrator Agent
# Fixes MCP SDK import error by using HTTP mode exclusively in AWS

$ErrorActionPreference = "Stop"

# Configuration
$AWS_REGION = "eu-west-3"
$AWS_ACCOUNT_ID = "555043101106"
$PROJECT_NAME = "ca-a2a"
$CLUSTER = "${PROJECT_NAME}-cluster"
$IMAGE_URI = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/orchestrator:latest"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Rebuild and Redeploy Orchestrator"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Login to ECR
Write-Host "[1/5] Login to ECR..." -ForegroundColor Yellow
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [ERROR] ECR login failed" -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] ECR login successful" -ForegroundColor Green
Write-Host ""

# Step 2: Build image
Write-Host "[2/5] Building orchestrator image..." -ForegroundColor Yellow
Write-Host "  Using: Dockerfile.orchestrator (Python 3.11)" -ForegroundColor Cyan
docker build -f Dockerfile.orchestrator -t $IMAGE_URI .
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [ERROR] Docker build failed" -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] Image built successfully" -ForegroundColor Green
Write-Host ""

# Step 3: Push to ECR
Write-Host "[3/5] Pushing image to ECR..." -ForegroundColor Yellow
docker push $IMAGE_URI
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [ERROR] Docker push failed" -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] Image pushed to ECR" -ForegroundColor Green
Write-Host ""

# Step 4: Update ECS service
Write-Host "[4/5] Updating ECS service..." -ForegroundColor Yellow
Write-Host "  Forcing new deployment to pull latest image..." -ForegroundColor Cyan
aws ecs update-service `
    --cluster $CLUSTER `
    --service orchestrator `
    --force-new-deployment `
    --region $AWS_REGION `
    --output json | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Host "  [ERROR] Service update failed" -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] Service update initiated" -ForegroundColor Green
Write-Host ""

# Step 5: Wait for deployment
Write-Host "[5/5] Waiting for deployment..." -ForegroundColor Yellow
Write-Host "  This may take 2-3 minutes..." -ForegroundColor Cyan
Write-Host "  ECS needs to: stop old tasks → start new tasks → health checks" -ForegroundColor DarkGray
Write-Host ""

$maxWait = 180  # 3 minutes
$elapsed = 0
$interval = 10

while ($elapsed -lt $maxWait) {
    Start-Sleep -Seconds $interval
    $elapsed += $interval
    
    # Check running count
    $status = aws ecs describe-services `
        --cluster $CLUSTER `
        --services orchestrator `
        --region $AWS_REGION `
        --query 'services[0].{running:runningCount,desired:desiredCount,deployment:deployments[0].rolloutState}' `
        --output json | ConvertFrom-Json
    
    $progress = [math]::Round(($elapsed / $maxWait) * 100)
    Write-Host "  [$progress%] Running: $($status.running)/$($status.desired) | State: $($status.deployment)" -ForegroundColor Cyan
    
    # Check if deployment is complete
    if ($status.deployment -eq "COMPLETED" -and $status.running -eq $status.desired) {
        Write-Host ""
        Write-Host "  [OK] Deployment completed successfully!" -ForegroundColor Green
        break
    }
}

if ($elapsed -ge $maxWait) {
    Write-Host ""
    Write-Host "  [WARN] Deployment taking longer than expected" -ForegroundColor Yellow
    Write-Host "  Check logs and status manually:" -ForegroundColor Yellow
    Write-Host "    aws ecs describe-services --cluster $CLUSTER --services orchestrator --region $AWS_REGION" -ForegroundColor White
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Deployment Status"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Show current service status
aws ecs describe-services `
    --cluster $CLUSTER `
    --services orchestrator `
    --region $AWS_REGION `
    --query 'services[0].{Name:serviceName,Status:status,Running:runningCount,Desired:desiredCount,Pending:pendingCount}' `
    --output table

Write-Host ""
Write-Host "Recent Events:" -ForegroundColor Yellow
aws ecs describe-services `
    --cluster $CLUSTER `
    --services orchestrator `
    --region $AWS_REGION `
    --query 'services[0].events[0:5].[createdAt,message]' `
    --output table

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Testing Deployment"
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

$ALB_URL = "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

Write-Host "Waiting 30s for ALB to detect new tasks..." -ForegroundColor Cyan
Start-Sleep -Seconds 30

Write-Host ""
Write-Host "Testing health endpoint..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$ALB_URL/health" -Method Get -TimeoutSec 10
    Write-Host "  [OK] Health check passed:" -ForegroundColor Green
    Write-Host "    Status: $($response.status)" -ForegroundColor White
    Write-Host "    Agent: $($response.agent)" -ForegroundColor White
} catch {
    Write-Host "  [ERROR] Health check failed: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Check task logs:" -ForegroundColor White
    Write-Host "     aws logs tail /ecs/ca-a2a/orchestrator --follow --region $AWS_REGION" -ForegroundColor DarkGray
    Write-Host "  2. Check task status:" -ForegroundColor White
    Write-Host "     aws ecs list-tasks --cluster $CLUSTER --service-name orchestrator --region $AWS_REGION" -ForegroundColor DarkGray
    exit 1
}

Write-Host ""
Write-Host "Testing upload endpoint..." -ForegroundColor Yellow
try {
    $testResponse = Invoke-WebRequest -Uri "$ALB_URL/upload" -Method Get -TimeoutSec 10 -SkipHttpErrorCheck
    if ($testResponse.StatusCode -eq 405) {
        Write-Host "  [OK] Upload endpoint exists (GET returns 405 Method Not Allowed - expected)" -ForegroundColor Green
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
Write-Host "Orchestrator ALB URL:" -ForegroundColor Cyan
Write-Host "  $ALB_URL" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Test file upload:" -ForegroundColor White
Write-Host "     .\Test-UploadViaALB.ps1" -ForegroundColor DarkGray
Write-Host "  2. Monitor logs:" -ForegroundColor White
Write-Host "     aws logs tail /ecs/ca-a2a/orchestrator --follow --region $AWS_REGION" -ForegroundColor DarkGray
Write-Host ""

