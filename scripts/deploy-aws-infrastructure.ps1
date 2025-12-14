# CA A2A - Complete AWS Infrastructure Deployment Script
# Region: eu-west-3
# Account: 555043101106

$ErrorActionPreference = "Stop"

# Configuration
$region = "eu-west-3"
$projectName = "ca-a2a"
$environment = "Production"
$owner = "j.benabderrazak@reply.com"
$accountId = "555043101106"

# Tags
$tags = @(
    "Key=Project,Value=CA-A2A"
    "Key=Environment,Value=$environment"
    "Key=Owner,Value=$owner"
    "Key=ManagedBy,Value=Script"
    "Key=CostCenter,Value=CA-Reply"
    "Key=Application,Value=Agent-Based-Architecture"
)
$tagsString = $tags -join " "

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CA A2A Infrastructure Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Region: $region" -ForegroundColor Yellow
Write-Host "Account: $accountId" -ForegroundColor Yellow
Write-Host ""

# Function to check if resource exists
function Test-ResourceExists {
    param($Command)
    try {
        Invoke-Expression $Command | Out-Null
        return $true
    } catch {
        return $false
    }
}

# 1. Create VPC (if not exists)
Write-Host "[1/10] Setting up VPC..." -ForegroundColor Green
$vpcId = "vpc-086392a3eed899f72"  # Your existing VPC
Write-Host "  Using existing VPC: $vpcId" -ForegroundColor Yellow

# Tag existing VPC
try {
    aws ec2 create-tags --resources $vpcId --tags $tagsString --region $region
    Write-Host "  VPC tagged successfully" -ForegroundColor Green
} catch {
    Write-Host "  Warning: Could not tag VPC" -ForegroundColor Yellow
}

# 2. Create Subnets (if needed)
Write-Host "[2/10] Setting up Subnets..." -ForegroundColor Green
$subnet1 = "subnet-020c68e784c2c9354"
$subnet2 = "subnet-0deca2d494c9ba33f"
Write-Host "  Using existing subnets: $subnet1, $subnet2" -ForegroundColor Yellow

# Tag subnets
try {
    aws ec2 create-tags --resources $subnet1 $subnet2 --tags $tagsString --region $region
    Write-Host "  Subnets tagged successfully" -ForegroundColor Green
} catch {
    Write-Host "  Warning: Could not tag subnets" -ForegroundColor Yellow
}

# 3. Create Security Group
Write-Host "[3/10] Setting up Security Groups..." -ForegroundColor Green
$sgId = "sg-0dfffbf7f98f77a4c"
Write-Host "  Using existing security group: $sgId" -ForegroundColor Yellow

# Tag security group
try {
    aws ec2 create-tags --resources $sgId --tags $tagsString --region $region
    Write-Host "  Security group tagged successfully" -ForegroundColor Green
} catch {
    Write-Host "  Warning: Could not tag security group" -ForegroundColor Yellow
}

# 4. Create DB Subnet Group
Write-Host "[4/10] Creating RDS DB Subnet Group..." -ForegroundColor Green
try {
    $dbSubnetCheck = aws rds describe-db-subnet-groups --db-subnet-group-name "$projectName-db-subnet" --region $region 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  DB Subnet Group already exists" -ForegroundColor Yellow
    }
} catch {
    aws rds create-db-subnet-group `
        --db-subnet-group-name "$projectName-db-subnet" `
        --db-subnet-group-description "Subnet group for $projectName PostgreSQL" `
        --subnet-ids $subnet1 $subnet2 `
        --tags $tagsString "Key=Component,Value=Database" `
        --region $region
    Write-Host "  DB Subnet Group created successfully" -ForegroundColor Green
}

# 5. Create RDS PostgreSQL
Write-Host "[5/10] Creating RDS PostgreSQL Instance..." -ForegroundColor Green
Write-Host "  Note: You'll be prompted for a database password" -ForegroundColor Cyan

$dbPassword = Read-Host "Enter database master password (min 8 chars, mix of letters/numbers)" -AsSecureString
$dbPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($dbPassword))

if ($dbPasswordPlain.Length -lt 8) {
    Write-Host "  Error: Password must be at least 8 characters" -ForegroundColor Red
    exit 1
}

try {
    $rdsCheck = aws rds describe-db-instances --db-instance-identifier "$projectName-postgres" --region $region 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  RDS instance already exists" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Creating RDS instance (this takes 5-10 minutes)..." -ForegroundColor Cyan
    aws rds create-db-instance `
        --db-instance-identifier "$projectName-postgres" `
        --db-instance-class db.t3.medium `
        --engine postgres `
        --engine-version 16.3 `
        --master-username postgres `
        --master-user-password $dbPasswordPlain `
        --allocated-storage 20 `
        --vpc-security-group-ids $sgId `
        --db-subnet-group-name "$projectName-db-subnet" `
        --backup-retention-period 7 `
        --storage-encrypted `
        --enable-cloudwatch-logs-exports postgresql `
        --no-publicly-accessible `
        --no-multi-az `
        --tags $tagsString "Key=Component,Value=Database" `
        --region $region
    Write-Host "  RDS instance creation initiated" -ForegroundColor Green
}

# Clear password from memory
$dbPasswordPlain = $null

# 6. Create S3 Buckets
Write-Host "[6/10] Creating S3 Buckets..." -ForegroundColor Green

# Documents bucket
$documentsBucket = "$projectName-documents-$accountId"
try {
    $bucketCheck = aws s3api head-bucket --bucket $documentsBucket --region $region 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Documents bucket already exists" -ForegroundColor Yellow
    }
} catch {
    aws s3api create-bucket `
        --bucket $documentsBucket `
        --region $region `
        --create-bucket-configuration LocationConstraint=$region
    
    # Enable versioning
    aws s3api put-bucket-versioning `
        --bucket $documentsBucket `
        --versioning-configuration Status=Enabled `
        --region $region
    
    # Enable encryption
    aws s3api put-bucket-encryption `
        --bucket $documentsBucket `
        --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}' `
        --region $region
    
    # Block public access
    aws s3api put-public-access-block `
        --bucket $documentsBucket `
        --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true `
        --region $region
    
    # Add tags
    $s3Tags = '{"TagSet":[{"Key":"Project","Value":"CA-A2A"},{"Key":"Environment","Value":"Production"},{"Key":"Component","Value":"Storage"},{"Key":"Owner","Value":"j.benabderrazak@reply.com"}]}'
    aws s3api put-bucket-tagging --bucket $documentsBucket --tagging $s3Tags --region $region
    
    Write-Host "  Documents bucket created successfully" -ForegroundColor Green
}

# 7. Create ECR Repositories
Write-Host "[7/10] Creating ECR Repositories..." -ForegroundColor Green
$agents = @("orchestrator", "extractor", "classifier", "qa-agent")

foreach ($agent in $agents) {
    $repoName = "$projectName-$agent"
    try {
        $ecrCheck = aws ecr describe-repositories --repository-names $repoName --region $region 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ECR repo $repoName already exists" -ForegroundColor Yellow
        }
    } catch {
        aws ecr create-repository `
            --repository-name $repoName `
            --image-scanning-configuration scanOnPush=true `
            --region $region `
            --tags $tagsString "Key=Component,Value=Container-Registry" "Key=AgentName,Value=$agent"
        Write-Host "  ECR repository $repoName created" -ForegroundColor Green
    }
}

# 8. Create ECS Cluster
Write-Host "[8/10] Creating ECS Cluster..." -ForegroundColor Green
try {
    $ecsCheck = aws ecs describe-clusters --clusters "$projectName-cluster" --region $region 2>&1
    $clusterData = $ecsCheck | ConvertFrom-Json
    if ($clusterData.clusters.Count -gt 0 -and $clusterData.clusters[0].status -eq "ACTIVE") {
        Write-Host "  ECS cluster already exists" -ForegroundColor Yellow
    } else {
        throw "Cluster not found"
    }
} catch {
    aws ecs create-cluster `
        --cluster-name "$projectName-cluster" `
        --capacity-providers FARGATE FARGATE_SPOT `
        --tags $tagsString "Key=Component,Value=Compute" `
        --region $region
    Write-Host "  ECS cluster created successfully" -ForegroundColor Green
}

# 9. Create CloudWatch Log Groups
Write-Host "[9/10] Creating CloudWatch Log Groups..." -ForegroundColor Green
foreach ($agent in $agents) {
    $logGroup = "/ecs/$projectName-$agent"
    try {
        $logCheck = aws logs describe-log-groups --log-group-name-prefix $logGroup --region $region 2>&1
        $logData = $logCheck | ConvertFrom-Json
        if ($logData.logGroups.Count -gt 0) {
            Write-Host "  Log group $logGroup already exists" -ForegroundColor Yellow
        } else {
            throw "Log group not found"
        }
    } catch {
        aws logs create-log-group --log-group-name $logGroup --region $region
        aws logs put-retention-policy --log-group-name $logGroup --retention-in-days 30 --region $region
        Write-Host "  Log group $logGroup created" -ForegroundColor Green
    }
}

# 10. Create IAM Roles
Write-Host "[10/10] Creating IAM Roles..." -ForegroundColor Green

# ECS Task Execution Role
$executionRoleName = "$projectName-ecs-task-execution-role"
try {
    $roleCheck = aws iam get-role --role-name $executionRoleName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  IAM execution role already exists" -ForegroundColor Yellow
    }
} catch {
    $trustPolicy = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
"@
    $trustPolicy | Out-File -FilePath "trust-policy-temp.json" -Encoding utf8
    
    aws iam create-role `
        --role-name $executionRoleName `
        --assume-role-policy-document file://trust-policy-temp.json `
        --tags $tagsString "Key=Component,Value=Security"
    
    aws iam attach-role-policy `
        --role-name $executionRoleName `
        --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
    
    Remove-Item "trust-policy-temp.json" -ErrorAction SilentlyContinue
    Write-Host "  IAM execution role created" -ForegroundColor Green
}

# ECS Task Role (for S3 access)
$taskRoleName = "$projectName-ecs-task-role"
try {
    $taskRoleCheck = aws iam get-role --role-name $taskRoleName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  IAM task role already exists" -ForegroundColor Yellow
    }
} catch {
    $trustPolicy = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
"@
    $trustPolicy | Out-File -FilePath "trust-policy-temp.json" -Encoding utf8
    
    aws iam create-role `
        --role-name $taskRoleName `
        --assume-role-policy-document file://trust-policy-temp.json `
        --tags $tagsString "Key=Component,Value=Security"
    
    # Create inline policy for S3 access
    $s3Policy = @"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::$documentsBucket",
        "arn:aws:s3:::$documentsBucket/*"
      ]
    }
  ]
}
"@
    $s3Policy | Out-File -FilePath "s3-policy-temp.json" -Encoding utf8
    
    aws iam put-role-policy `
        --role-name $taskRoleName `
        --policy-name S3AccessPolicy `
        --policy-document file://s3-policy-temp.json
    
    Remove-Item "trust-policy-temp.json" -ErrorAction SilentlyContinue
    Remove-Item "s3-policy-temp.json" -ErrorAction SilentlyContinue
    Write-Host "  IAM task role created" -ForegroundColor Green
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Deployment Summary" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "VPC ID: $vpcId" -ForegroundColor White
Write-Host "Subnets: $subnet1, $subnet2" -ForegroundColor White
Write-Host "Security Group: $sgId" -ForegroundColor White
Write-Host "RDS Instance: $projectName-postgres" -ForegroundColor White
Write-Host "S3 Bucket: $documentsBucket" -ForegroundColor White
Write-Host "ECS Cluster: $projectName-cluster" -ForegroundColor White
Write-Host "ECR Repos: $($agents.Count) repositories" -ForegroundColor White
Write-Host "CloudWatch Log Groups: $($agents.Count) log groups" -ForegroundColor White
Write-Host "IAM Roles: Execution and Task roles" -ForegroundColor White
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "1. Wait for RDS instance to become available (~10 minutes)" -ForegroundColor Yellow
Write-Host "   Check status: aws rds describe-db-instances --db-instance-identifier $projectName-postgres --region $region --query 'DBInstances[0].DBInstanceStatus'" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Build and push Docker images to ECR" -ForegroundColor Yellow
Write-Host "   Use: .\scripts\build-and-push-images.ps1" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Create ECS task definitions and services" -ForegroundColor Yellow
Write-Host "   Use: .\scripts\deploy-ecs-services.ps1" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Configure Application Load Balancer (optional)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Deployment completed successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

