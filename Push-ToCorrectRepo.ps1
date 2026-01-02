#!/usr/bin/env pwsh
# Push fixed extractor to CORRECT ECR repository
# Run this in PowerShell with AWS credentials

param(
    [Parameter(Mandatory=$true)]
    [string]$AWS_ACCESS_KEY_ID,
    
    [Parameter(Mandatory=$true)]
    [string]$AWS_SECRET_ACCESS_KEY,
    
    [Parameter(Mandatory=$true)]
    [string]$AWS_SESSION_TOKEN
)

$ErrorActionPreference = "Stop"

# Set credentials
$env:AWS_ACCESS_KEY_ID = $AWS_ACCESS_KEY_ID
$env:AWS_SECRET_ACCESS_KEY = $AWS_SECRET_ACCESS_KEY
$env:AWS_SESSION_TOKEN = $AWS_SESSION_TOKEN
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
    Write-Host "   Local image not found. Need to rebuild..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Building image..."
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
Write-Host "The fixed extractor is now in the CORRECT repository:" -ForegroundColor Green
Write-Host "  $CORRECT_ECR_REPO:latest" -ForegroundColor Green
Write-Host ""
Write-Host "Service is redeploying with the fixed image." -ForegroundColor Green
Write-Host ""
Write-Host "Next: Go to CloudShell and run (wait 60 seconds first):" -ForegroundColor Yellow
Write-Host ""
Write-Host "  TIMESTAMP=`$(date +%s)" -ForegroundColor Gray
Write-Host "  aws s3 cp facture_acme_dec2025.pdf \"  -ForegroundColor Gray
Write-Host "    s3://ca-a2a-documents-555043101106/invoices/2026/01/test_`${TIMESTAMP}.pdf \"  -ForegroundColor Gray
Write-Host "    --region eu-west-3" -ForegroundColor Gray
Write-Host ""
Write-Host "  sleep 40" -ForegroundColor Gray
Write-Host ""  
Write-Host "  aws logs tail /ecs/ca-a2a-extractor --since 2m --region eu-west-3" -ForegroundColor Gray
Write-Host ""

