# Rebuild and Redeploy ALL Services with SSL Fix
# Adds SSL support for RDS PostgreSQL connections

$env:AWS_PROFILE = "reply-sso"
$AWS_REGION = "eu-west-3"
$ACCOUNT_ID = "555043101106"
$PROJECT_NAME = "ca-a2a"
$CLUSTER = "$PROJECT_NAME-cluster"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Rebuild and Redeploy All Services (SSL Fix)"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Login to ECR
Write-Host "[1/4] Logging in to ECR..." -ForegroundColor Yellow
$ECR_PASSWORD = aws ecr get-login-password --region $AWS_REGION --profile reply-sso
$ECR_REPO_BASE = "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$PROJECT_NAME"
$ECR_PASSWORD | docker login --username AWS --password-stdin $ECR_REPO_BASE 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Logged in to ECR" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] ECR login failed" -ForegroundColor Red
    exit 1
}

# Step 2: Build Docker image
Write-Host ""
Write-Host "[2/4] Building Docker image with SSL support..." -ForegroundColor Yellow
docker build -t "${PROJECT_NAME}-agents:latest" .
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Image built" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Image build failed" -ForegroundColor Red
    exit 1
}

# Step 3: Tag and push to all agent repositories
Write-Host ""
Write-Host "[3/4] Tagging and pushing images to ECR..." -ForegroundColor Yellow
$services = @("extractor", "validator", "archivist")
foreach ($service in $services) {
    Write-Host "  Processing $service..." -ForegroundColor Cyan
    $ECR_REPO = "$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$PROJECT_NAME/$service"
    
    docker tag "${PROJECT_NAME}-agents:latest" "${ECR_REPO}:latest"
    docker push "${ECR_REPO}:latest" | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    [OK] $service image pushed" -ForegroundColor Green
    } else {
        Write-Host "    [FAIL] $service image push failed" -ForegroundColor Red
        exit 1
    }
}

# Step 4: Force redeploy all services
Write-Host ""
Write-Host "[4/4] Forcing service redeployments..." -ForegroundColor Yellow
foreach ($service in $services) {
    Write-Host "  Redeploying $service..." -ForegroundColor Cyan
    aws ecs update-service --cluster $CLUSTER --service $service --force-new-deployment --region $AWS_REGION --profile reply-sso --output json | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    [OK] $service redeployment triggered" -ForegroundColor Green
    } else {
        Write-Host "    [FAIL] $service redeployment failed" -ForegroundColor Red
    }
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
aws ecs describe-services --cluster $CLUSTER --services extractor validator archivist --region $AWS_REGION --query 'services[*].[serviceName,runningCount,desiredCount]' --output table --profile reply-sso

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Latest events for each service:"
Write-Host "==========================================" -ForegroundColor Cyan
foreach ($service in $services) {
    Write-Host ""
    Write-Host "=== $service ===" -ForegroundColor Yellow
    aws ecs describe-services --cluster $CLUSTER --services $service --region $AWS_REGION --query 'services[0].events[0:2].[message]' --output text --profile reply-sso
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Check logs with:"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "aws logs tail /ecs/ca-a2a-extractor --since 5m --follow --region $AWS_REGION --profile reply-sso"
Write-Host ""

