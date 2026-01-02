#!/usr/bin/env pwsh
# Push fixed extractor to CORRECT ECR repository

$ErrorActionPreference = "Stop"

# Set credentials
$env:AWS_ACCESS_KEY_ID = "ASIAYCOZFTGZCVR5FLMC"
$env:AWS_SECRET_ACCESS_KEY = "M5l32OkqF+11kVennXYsPrJFxDcAyIgkzuqJ/Uhz"
$env:AWS_SESSION_TOKEN = "IQoJb3JpZ2luX2VjED4aCXVzLWVhc3QtMSJIMEYCIQC0PRr0CWTxs8NPP5y/aNmowrEBWGlb9mfzLqe8J0B4zgIhAPrw0UA2PVPqTWyrpGw/w4R9sHSa/AGJL9tgqoRUG2KJKpMDCAYQARoMNTU1MDQzMTAxMTA2IgzbipW4tJDi3rNWpVgq8ALNEhuyQoDayjW1Y9q8lSZVNwy3TjLUFpTaRtxGd576yhImk4rsFK3bX2ak6Oc3Fe3RrTBv9N6fB1XlkLqtRJQtJGpu30YuZlJZC+JPi9lKXUlPhNwUIwvEd102D14m5VZrR6mS+9J0haBQYEPFzEciyBv3cT+vWjO1IxsBgRddaRCkEEoobapnPvd+SF5d+Ji9+Jujzc17vxJYPBStuuxUvWE7dGY8GCd6G/Q4fVskWj/86dgcfQDFiZEdojXKKQ3udVNqn/GsbQwIXb3y4Tuz0v/nCHnwX8nV32Qzj6kNrsuaHoxKZARsvr5gYLjLMVhYsjeAjcaf2yxH3kHDujVK/og9Rr/Xiq/g1WjHQQ9B0vorbZ2kvwPUmG9dDRHVcEKDAIpLHhXGAKpgDDLo3q4Wk29RAton9W6wbSMensPONwUl0iby18LQv228oXxB8s4wjTd+dobKJrhKiCZ1LrA6NANjO6BdIbg68oleAb808DCE6eDKBjqjAWHO53prjhOjdJb+g18pkILqLDYFkqXrOnZh4wWbzQZnX8GD2UGHxzTRY8cOdJhCnQPUN4+DhTklWYHdhr1+uQY4IyWnz6zMyg+7BHVrTHr1BlR07HMUG/sCa4WCVedIpFnKLmaSOe9SP5j9sncW8WBobNz0HWH9YDexT+G+EpcnoLAfPPU91Oo4NlPY8zbzyC85i5iJybPj1jqx4D1I7qEa38Y="
$env:AWS_DEFAULT_REGION = "eu-west-3"

$REGION = "eu-west-3"
$CLUSTER = "ca-a2a-cluster"
$SERVICE = "extractor"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "PUSH TO CORRECT ECR REPOSITORY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Get account ID
$AWS_ACCOUNT = (aws sts get-caller-identity --query Account --output text)
Write-Host "Account: $AWS_ACCOUNT"

# CORRECT repository path (with slash)
$CORRECT_ECR_REPO = "$AWS_ACCOUNT.dkr.ecr.$REGION.amazonaws.com/ca-a2a/extractor"
Write-Host "Target Repo: $CORRECT_ECR_REPO"
Write-Host ""

# Check if local image exists
Write-Host "1. Checking for local image..."
$localImage = docker images -q ca-a2a-extractor:fixed
if ([string]::IsNullOrEmpty($localImage)) {
    Write-Host "   Local image not found. Rebuilding..." -ForegroundColor Yellow
    Write-Host ""
    docker build -t ca-a2a-extractor:fixed -f Dockerfile.extractor .
    if ($LASTEXITCODE -ne 0) {
        Write-Host "   ✗ Build failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "   ✓ Local image found" -ForegroundColor Green
}

Write-Host ""
Write-Host "2. Logging in to ECR..."
$loginCmd = aws ecr get-login-password --region $REGION
$loginCmd | docker login --username AWS --password-stdin "$AWS_ACCOUNT.dkr.ecr.$REGION.amazonaws.com" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "   ✗ ECR login failed" -ForegroundColor Red
    exit 1
}
Write-Host "   ✓ Logged in" -ForegroundColor Green

Write-Host ""
Write-Host "3. Tagging image for CORRECT repository..."
Write-Host "   From: ca-a2a-extractor:fixed"
Write-Host "   To:   $CORRECT_ECR_REPO:latest"
docker tag ca-a2a-extractor:fixed "$CORRECT_ECR_REPO:latest"
if ($LASTEXITCODE -ne 0) {
    Write-Host "   ✗ Tag failed" -ForegroundColor Red
    exit 1
}
Write-Host "   ✓ Tagged" -ForegroundColor Green

Write-Host ""
Write-Host "4. Pushing to CORRECT ECR repository..."
Write-Host "   (This may take 2-3 minutes)"
Write-Host ""
docker push "$CORRECT_ECR_REPO:latest"
if ($LASTEXITCODE -ne 0) {
    Write-Host "   ✗ Push failed" -ForegroundColor Red
    exit 1
}
Write-Host ""
Write-Host "   ✓ Pushed successfully!" -ForegroundColor Green

Write-Host ""
Write-Host "5. Forcing service update..."
aws ecs update-service `
    --cluster $CLUSTER `
    --service $SERVICE `
    --force-new-deployment `
    --region $REGION | Out-Null

Write-Host "   ✓ Service update initiated" -ForegroundColor Green

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "SUCCESS!" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "The fixed extractor is now in the CORRECT repository!" -ForegroundColor Green
Write-Host "Repository: $CORRECT_ECR_REPO:latest" -ForegroundColor Green
Write-Host ""
Write-Host "Service is redeploying. Wait 60 seconds, then test in CloudShell." -ForegroundColor Yellow
Write-Host ""

