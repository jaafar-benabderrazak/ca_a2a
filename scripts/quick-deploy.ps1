# CA A2A - Quick Deployment Script (Simplified)
# Use this for step-by-step deployment with confirmations

$region = if ($env:AWS_REGION) { $env:AWS_REGION } else { "us-east-1" }
$projectName = "ca-a2a"
$accountId = "555043101106"

Write-Host "CA A2A Quick Deployment" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host ""

# Step 1: DB Subnet Group
Write-Host "[1] Creating DB Subnet Group..." -ForegroundColor Green
$continue = Read-Host "Create DB Subnet Group? (Y/N)"
if ($continue -eq "Y") {
    aws rds create-db-subnet-group `
        --db-subnet-group-name ca-a2a-db-subnet `
        --db-subnet-group-description "CA A2A DB Subnet" `
        --subnet-ids subnet-020c68e784c2c9354 subnet-0deca2d494c9ba33f `
        --tags "Key=Project,Value=CA-A2A" "Key=Component,Value=Database" `
        --region $region
    Write-Host "  Done!" -ForegroundColor Green
}

# Step 2: RDS PostgreSQL
Write-Host ""
Write-Host "[2] Creating RDS PostgreSQL..." -ForegroundColor Green
$continue = Read-Host "Create RDS instance? This takes 10 minutes (Y/N)"
if ($continue -eq "Y") {
    $password = Read-Host "Enter database password (min 8 chars)" -AsSecureString
    $passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    
    aws rds create-db-instance `
        --db-instance-identifier ca-a2a-postgres `
        --db-instance-class db.t3.medium `
        --engine postgres `
        --engine-version 16.3 `
        --master-username postgres `
        --master-user-password $passwordPlain `
        --allocated-storage 20 `
        --vpc-security-group-ids sg-0dfffbf7f98f77a4c `
        --db-subnet-group-name ca-a2a-db-subnet `
        --backup-retention-period 7 `
        --storage-encrypted `
        --enable-cloudwatch-logs-exports postgresql `
        --no-publicly-accessible `
        --no-multi-az `
        --tags "Key=Project,Value=CA-A2A" "Key=Component,Value=Database" `
        --region $region
    Write-Host "  RDS creation started!" -ForegroundColor Green
    $passwordPlain = $null
}

# Step 3: S3 Bucket
Write-Host ""
Write-Host "[3] Creating S3 Bucket..." -ForegroundColor Green
$continue = Read-Host "Create S3 bucket? (Y/N)"
if ($continue -eq "Y") {
    $bucket = "ca-a2a-documents-$accountId"
    
    # Create bucket
    aws s3api create-bucket --bucket $bucket --region $region --create-bucket-configuration LocationConstraint=$region
    
    # Enable encryption
    aws s3api put-bucket-encryption --bucket $bucket --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'
    
    # Enable versioning
    aws s3api put-bucket-versioning --bucket $bucket --versioning-configuration Status=Enabled
    
    # Block public access
    aws s3api put-public-access-block --bucket $bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
    
    Write-Host "  S3 bucket created: $bucket" -ForegroundColor Green
}

# Step 4: ECS Cluster
Write-Host ""
Write-Host "[4] Creating ECS Cluster..." -ForegroundColor Green
$continue = Read-Host "Create ECS cluster? (Y/N)"
if ($continue -eq "Y") {
    aws ecs create-cluster --cluster-name ca-a2a-cluster --tags "Key=Project,Value=CA-A2A" --region $region
    Write-Host "  ECS cluster created!" -ForegroundColor Green
}

# Step 5: ECR Repositories
Write-Host ""
Write-Host "[5] Creating ECR Repositories..." -ForegroundColor Green
$continue = Read-Host "Create ECR repositories for agents? (Y/N)"
if ($continue -eq "Y") {
    $agents = @("orchestrator", "extractor", "validator", "archivist", "keycloak", "mcp-server")
    foreach ($agent in $agents) {
        aws ecr create-repository --repository-name "ca-a2a-$agent" --region $region --tags "Key=Project,Value=CA-A2A" "Key=AgentName,Value=$agent"
        Write-Host "  Created: ca-a2a-$agent" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Quick deployment complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Check RDS status:" -ForegroundColor Cyan
Write-Host "aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --query 'DBInstances[0].DBInstanceStatus'" -ForegroundColor White

