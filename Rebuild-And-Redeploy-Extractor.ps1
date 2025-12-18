# Rebuild and Redeploy Extractor Service
# Adds pandas dependency and pushes new image to ECR

$env:AWS_PROFILE = "reply-sso"
$AWS_REGION = "eu-west-3"
$ACCOUNT_ID = "555043101106"
$PROJECT_NAME = "ca-a2a"
$ECR_REPO = "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$PROJECT_NAME-agents"
$CLUSTER = "$PROJECT_NAME-cluster"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Rebuild and Redeploy Extractor"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Login to ECR
Write-Host "[1/5] Logging in to ECR..." -ForegroundColor Yellow
$ECR_PASSWORD = aws ecr get-login-password --region $AWS_REGION --profile reply-sso
$ECR_PASSWORD | docker login --username AWS --password-stdin $ECR_REPO 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Logged in to ECR" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] ECR login failed" -ForegroundColor Red
    exit 1
}

# Step 2: Build Docker image with pandas
Write-Host ""
Write-Host "[2/5] Building Docker image with updated requirements..." -ForegroundColor Yellow
docker build -t "${PROJECT_NAME}-agents:latest" .
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Image built" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Image build failed" -ForegroundColor Red
    exit 1
}

# Step 3: Tag image
Write-Host ""
Write-Host "[3/5] Tagging image for ECR..." -ForegroundColor Yellow
docker tag "${PROJECT_NAME}-agents:latest" "${ECR_REPO}:latest"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
docker tag "${PROJECT_NAME}-agents:latest" "${ECR_REPO}:${timestamp}"
Write-Host "  [OK] Image tagged" -ForegroundColor Green

# Step 4: Push to ECR
Write-Host ""
Write-Host "[4/5] Pushing image to ECR..." -ForegroundColor Yellow
docker push "${ECR_REPO}:latest" | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Image pushed" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Image push failed" -ForegroundColor Red
    exit 1
}

# Step 5: Force redeploy extractor service
Write-Host ""
Write-Host "[5/5] Forcing extractor service redeployment..." -ForegroundColor Yellow
aws ecs update-service --cluster $CLUSTER --service extractor --force-new-deployment --region $AWS_REGION --profile reply-sso --output json | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Redeployment triggered" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Redeployment failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Waiting 90 seconds for new tasks to start..."
Write-Host "==========================================" -ForegroundColor Cyan
Start-Sleep -Seconds 90

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Service Status"
Write-Host "==========================================" -ForegroundColor Cyan
aws ecs describe-services --cluster $CLUSTER --services extractor --region $AWS_REGION --query 'services[*].[serviceName,runningCount,desiredCount,deployments[0].status]' --output table --profile reply-sso

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Latest events:"
Write-Host "==========================================" -ForegroundColor Cyan
aws ecs describe-services --cluster $CLUSTER --services extractor --region $AWS_REGION --query 'services[0].events[0:3].[message]' --output text --profile reply-sso

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Check logs with:"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "aws logs tail /ecs/ca-a2a-extractor --since 5m --follow --region $AWS_REGION --profile reply-sso"
Write-Host ""
