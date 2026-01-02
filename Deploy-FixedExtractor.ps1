# Deploy Fixed Extractor to AWS ECS
# Run this on your local Windows machine with Docker Desktop running

$ErrorActionPreference = "Stop"

$REGION = "eu-west-3"
$CLUSTER = "ca-a2a-cluster"
$SERVICE = "extractor"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "DEPLOY FIXED EXTRACTOR TO ECS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check Docker is running
Write-Host "1. Checking Docker..." -ForegroundColor Yellow
try {
    docker ps | Out-Null
    Write-Host "   ✓ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Docker is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Get AWS account
Write-Host ""
Write-Host "2. Getting AWS account info..." -ForegroundColor Yellow
$AWS_ACCOUNT = aws sts get-caller-identity --query Account --output text
$ECR_REPO = "${AWS_ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a-extractor"
Write-Host "   Account: $AWS_ACCOUNT" -ForegroundColor Green
Write-Host "   ECR Repo: $ECR_REPO" -ForegroundColor Green

# Build Docker image
Write-Host ""
Write-Host "3. Building extractor Docker image..." -ForegroundColor Yellow
Write-Host "   (This may take 2-3 minutes)" -ForegroundColor Gray

docker build -t ca-a2a-extractor:fixed -f Dockerfile.extractor .

if ($LASTEXITCODE -ne 0) {
    Write-Host "   ✗ Docker build failed" -ForegroundColor Red
    exit 1
}
Write-Host "   ✓ Image built successfully" -ForegroundColor Green

# Login to ECR
Write-Host ""
Write-Host "4. Logging in to ECR..." -ForegroundColor Yellow
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR_REPO

if ($LASTEXITCODE -ne 0) {
    Write-Host "   ✗ ECR login failed" -ForegroundColor Red
    exit 1
}
Write-Host "   ✓ Logged in to ECR" -ForegroundColor Green

# Tag and push
Write-Host ""
Write-Host "5. Pushing image to ECR..." -ForegroundColor Yellow
Write-Host "   (This may take 3-5 minutes depending on your connection)" -ForegroundColor Gray

docker tag ca-a2a-extractor:fixed "${ECR_REPO}:fixed"
docker push "${ECR_REPO}:fixed"

if ($LASTEXITCODE -ne 0) {
    Write-Host "   ✗ Push failed" -ForegroundColor Red
    exit 1
}
Write-Host "   ✓ Image pushed to ECR" -ForegroundColor Green

# Get current task definition
Write-Host ""
Write-Host "6. Updating ECS task definition..." -ForegroundColor Yellow

$TASK_DEF_ARN = aws ecs describe-services `
    --cluster $CLUSTER `
    --services $SERVICE `
    --region $REGION `
    --query 'services[0].taskDefinition' `
    --output text

Write-Host "   Current: $TASK_DEF_ARN" -ForegroundColor Gray

# Download current task definition
aws ecs describe-task-definition `
    --task-definition $TASK_DEF_ARN `
    --region $REGION `
    --query 'taskDefinition' | Out-File -Encoding utf8 extractor_taskdef.json

# Update image in task definition
$taskDef = Get-Content extractor_taskdef.json | ConvertFrom-Json
$taskDef.containerDefinitions[0].image = "${ECR_REPO}:fixed"

# Remove fields that can't be in registration
$taskDef.PSObject.Properties.Remove('taskDefinitionArn')
$taskDef.PSObject.Properties.Remove('revision')
$taskDef.PSObject.Properties.Remove('status')
$taskDef.PSObject.Properties.Remove('requiresAttributes')
$taskDef.PSObject.Properties.Remove('compatibilities')
$taskDef.PSObject.Properties.Remove('registeredAt')
$taskDef.PSObject.Properties.Remove('registeredBy')

$taskDef | ConvertTo-Json -Depth 10 | Out-File -Encoding utf8 extractor_taskdef_updated.json

# Register new task definition
Write-Host "   Registering new task definition..." -ForegroundColor Gray
$NEW_TASK_DEF = aws ecs register-task-definition `
    --cli-input-json file://extractor_taskdef_updated.json `
    --region $REGION `
    --query 'taskDefinition.taskDefinitionArn' `
    --output text

Write-Host "   New: $NEW_TASK_DEF" -ForegroundColor Green

# Update ECS service
Write-Host ""
Write-Host "7. Updating ECS service..." -ForegroundColor Yellow
aws ecs update-service `
    --cluster $CLUSTER `
    --service $SERVICE `
    --task-definition $NEW_TASK_DEF `
    --force-new-deployment `
    --region $REGION | Out-Null

Write-Host "   ✓ Service updated - new tasks will start deploying" -ForegroundColor Green

# Cleanup
Remove-Item extractor_taskdef.json -ErrorAction SilentlyContinue
Remove-Item extractor_taskdef_updated.json -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "DEPLOYMENT INITIATED" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "The fixed extractor is now deploying to ECS." -ForegroundColor Green
Write-Host ""
Write-Host "Wait 60-90 seconds for the new tasks to start, then run in CloudShell:" -ForegroundColor Yellow
Write-Host "  ./test-complete-pipeline-simple.sh" -ForegroundColor White
Write-Host ""
Write-Host "You should then see:" -ForegroundColor Yellow
Write-Host "  ✅ PDF extraction completed" -ForegroundColor Green
Write-Host "  ✅ Starting validation" -ForegroundColor Green
Write-Host "  ✅ Starting archiving" -ForegroundColor Green
Write-Host "  ✅ Pipeline completed successfully" -ForegroundColor Green
Write-Host ""
Write-Host "To monitor deployment:" -ForegroundColor Yellow
Write-Host "  aws ecs describe-services --cluster $CLUSTER --services $SERVICE --region $REGION --query 'services[0].deployments'" -ForegroundColor White
Write-Host ""

