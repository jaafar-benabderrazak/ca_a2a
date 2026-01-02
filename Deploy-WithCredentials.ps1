#!/usr/bin/env pwsh
# Deploy Fixed Extractor with Provided Credentials
# Run this in PowerShell on Windows

$ErrorActionPreference = "Stop"

# Set AWS credentials from provided session
$env:AWS_ACCESS_KEY_ID = "ASIAYCOZFTGZCVR5FLMC"
$env:AWS_SECRET_ACCESS_KEY = "M5l32OkqF+11kVennXYsPrJFxDcAyIgkzuqJ/Uhz"
$env:AWS_SESSION_TOKEN = "IQoJb3JpZ2luX2VjED4aCXVzLWVhc3QtMSJIMEYCIQC0PRr0CWTxs8NPP5y/aNmowrEBWGlb9mfzLqe8J0B4zgIhAPrw0UA2PVPqTWyrpGw/w4R9sHSa/AGJL9tgqoRUG2KJKpMDCAYQARoMNTU1MDQzMTAxMTA2IgzbipW4tJDi3rNWpVgq8ALNEhuyQoDayjW1Y9q8lSZVNwy3TjLUFpTaRtxGd576yhImk4rsFK3bX2ak6Oc3Fe3RrTBv9N6fB1XlkLqtRJQtJGpu30YuZlJZC+JPi9lKXUlPhNwUIwvEd102D14m5VZrR6mS+9J0haBQYEPFzEciyBv3cT+vWjO1IxsBgRddaRCkEEoobapnPvd+SF5d+Ji9+Jujzc17vxJYPBStuuxUvWE7dGY8GCd6G/Q4fVskWj/86dgcfQDFiZEdojXKKQ3udVNqn/GsbQwIXb3y4Tuz0v/nCHnwX8nV32Qzj6kNrsuaHoxKZARsvr5gYLjLMVhYsjeAjcaf2yxH3kHDujVK/og9Rr/Xiq/g1WjHQQ9B0vorbZ2kvwPUmG9dDRHVcEKDAIpLHhXGAKpgDDLo3q4Wk29RAton9W6wbSMensPONwUl0iby18LQv228oXxB8s4wjTd+dobKJrhKiCZ1LrA6NANjO6BdIbg68oleAb808DCE6eDKBjqjAWHO53prjhOjdJb+g18pkILqLDYFkqXrOnZh4wWbzQZnX8GD2UGHxzTRY8cOdJhCnQPUN4+DhTklWYHdhr1+uQY4IyWnz6zMyg+7BHVrTHr1BlR07HMUG/sCa4WCVedIpFnKLmaSOe9SP5j9sncW8WBobNz0HWH9YDexT+G+EpcnoLAfPPU91Oo4NlPY8zbzyC85i5iJybPj1jqx4D1I7qEa38Y="
$env:AWS_DEFAULT_REGION = "eu-west-3"

$REGION = "eu-west-3"
$CLUSTER = "ca-a2a-cluster"
$SERVICE = "extractor"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "DEPLOY FIXED EXTRACTOR TO ECS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Verify credentials work
Write-Host "1. Verifying AWS credentials..." -ForegroundColor Yellow
try {
    $AWS_ACCOUNT = (aws sts get-caller-identity --query Account --output text)
    Write-Host "   ✓ Credentials valid - Account: $AWS_ACCOUNT" -ForegroundColor Green
} catch {
    Write-Host "   ✗ AWS credentials invalid or expired" -ForegroundColor Red
    exit 1
}

# Check Docker
Write-Host ""
Write-Host "2. Checking Docker..." -ForegroundColor Yellow
try {
    docker ps | Out-Null
    Write-Host "   ✓ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Docker is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# ECR repository
$ECR_REPO = "$AWS_ACCOUNT.dkr.ecr.$REGION.amazonaws.com/ca-a2a-extractor"
Write-Host "   ECR Repo: $ECR_REPO"

# Build Docker image
Write-Host ""
Write-Host "3. Building extractor Docker image..." -ForegroundColor Yellow
Write-Host "   (This may take 2-3 minutes)" -ForegroundColor Gray
Write-Host ""

docker build -t ca-a2a-extractor:fixed -f Dockerfile.extractor .
if ($LASTEXITCODE -ne 0) {
    Write-Host "   ✗ Docker build failed" -ForegroundColor Red
    exit 1
}
Write-Host ""
Write-Host "   ✓ Image built successfully" -ForegroundColor Green

# Login to ECR
Write-Host ""
Write-Host "4. Logging in to ECR..." -ForegroundColor Yellow
$loginCmd = aws ecr get-login-password --region $REGION
$loginCmd | docker login --username AWS --password-stdin $ECR_REPO 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "   ✗ ECR login failed" -ForegroundColor Red
    exit 1
}
Write-Host "   ✓ Logged in to ECR" -ForegroundColor Green

# Tag and push
Write-Host ""
Write-Host "5. Pushing image to ECR..." -ForegroundColor Yellow
Write-Host "   (This may take 3-5 minutes depending on your connection)" -ForegroundColor Gray
Write-Host ""

$targetImage = "${ECR_REPO}:fixed"
docker tag ca-a2a-extractor:fixed $targetImage
docker push $targetImage
if ($LASTEXITCODE -ne 0) {
    Write-Host "   ✗ Push failed" -ForegroundColor Red
    exit 1
}
Write-Host ""
Write-Host "   ✓ Image pushed to ECR" -ForegroundColor Green

# Get current task definition
Write-Host ""
Write-Host "6. Updating ECS task definition..." -ForegroundColor Yellow

$TASK_DEF_ARN = (aws ecs describe-services `
    --cluster $CLUSTER `
    --services $SERVICE `
    --region $REGION `
    --query 'services[0].taskDefinition' `
    --output text)

Write-Host "   Current: $TASK_DEF_ARN"

# Download current task definition
aws ecs describe-task-definition `
    --task-definition $TASK_DEF_ARN `
    --region $REGION `
    --query 'taskDefinition' | Out-File -Encoding utf8 extractor_taskdef.json

# Update image in task definition using PowerShell JSON manipulation
$taskDef = Get-Content extractor_taskdef.json -Raw | ConvertFrom-Json
$newImage = "${ECR_REPO}:fixed"
$taskDef.containerDefinitions[0].image = $newImage

# Remove fields that can't be in register call
$taskDef.PSObject.Properties.Remove('taskDefinitionArn')
$taskDef.PSObject.Properties.Remove('revision')
$taskDef.PSObject.Properties.Remove('status')
$taskDef.PSObject.Properties.Remove('requiresAttributes')
$taskDef.PSObject.Properties.Remove('compatibilities')
$taskDef.PSObject.Properties.Remove('registeredAt')
$taskDef.PSObject.Properties.Remove('registeredBy')

$taskDef | ConvertTo-Json -Depth 10 | Out-File -Encoding utf8 extractor_taskdef_updated.json

# Register new task definition
Write-Host "   Registering new task definition..."
$NEW_TASK_DEF = (aws ecs register-task-definition `
    --cli-input-json file://extractor_taskdef_updated.json `
    --region $REGION `
    --query 'taskDefinition.taskDefinitionArn' `
    --output text)

Write-Host "   New: $NEW_TASK_DEF"

# Update ECS service
Write-Host ""
Write-Host "7. Updating ECS service..." -ForegroundColor Yellow
aws ecs update-service `
    --cluster $CLUSTER `
    --service $SERVICE `
    --task-definition $NEW_TASK_DEF `
    --force-new-deployment `
    --region $REGION | Out-Null

Write-Host "   ✓ Service updated - new tasks deploying" -ForegroundColor Green

# Cleanup
Remove-Item extractor_taskdef.json -ErrorAction SilentlyContinue
Remove-Item extractor_taskdef_updated.json -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "DEPLOYMENT COMPLETE!" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "✅ Fixed extractor is deploying to ECS" -ForegroundColor Green
Write-Host ""
Write-Host "Wait 60-90 seconds, then test in CloudShell:"
Write-Host "  ./test-complete-pipeline-simple.sh"
Write-Host ""
Write-Host "Expected results:"
Write-Host "  ✅ PDF extraction completed"
Write-Host "  ✅ Starting validation"
Write-Host "  ✅ Starting archiving"  
Write-Host "  ✅ Pipeline completed successfully"
Write-Host ""

# Monitor deployment
Write-Host "Checking deployment status in 20 seconds..." -ForegroundColor Gray
Start-Sleep -Seconds 20

Write-Host ""
Write-Host "Deployment status:"
aws ecs describe-services `
    --cluster $CLUSTER `
    --services $SERVICE `
    --region $REGION `
    --query 'services[0].deployments[*].{Status: status, TaskDef: taskDefinition, Running: runningCount, Desired: desiredCount}' `
    --output table

Write-Host ""
Write-Host "🎉 Deployment initiated! Test in CloudShell in about 60 seconds." -ForegroundColor Green

