# CA A2A - Fix Missing Resources
# This script creates the IAM roles and ECR repos that failed due to tag issues

$region = "eu-west-3"
$projectName = "ca-a2a"
$accountId = "555043101106"
$documentsBucket = "$projectName-documents-$accountId"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CA A2A - Fix Missing Resources" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Create IAM Execution Role
Write-Host "[1/3] Creating IAM ECS Task Execution Role..." -ForegroundColor Green
$executionRoleName = "$projectName-ecs-task-execution-role"
try {
    $roleCheck = aws iam get-role --role-name $executionRoleName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Role already exists" -ForegroundColor Yellow
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
    $trustPolicy | Out-File -FilePath "trust-policy.json" -Encoding utf8
    
    aws iam create-role `
        --role-name $executionRoleName `
        --assume-role-policy-document file://trust-policy.json `
        --tags Key=Project,Value=CA-A2A Key=Component,Value=Security Key=Owner,Value=j.benabderrazak@reply.com
    
    Start-Sleep -Seconds 2
    
    aws iam attach-role-policy `
        --role-name $executionRoleName `
        --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
    
    Remove-Item "trust-policy.json" -ErrorAction SilentlyContinue
    Write-Host "  Execution role created successfully" -ForegroundColor Green
}

# 2. Create IAM Task Role
Write-Host ""
Write-Host "[2/3] Creating IAM ECS Task Role..." -ForegroundColor Green
$taskRoleName = "$projectName-ecs-task-role"
try {
    $roleCheck = aws iam get-role --role-name $taskRoleName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Role already exists" -ForegroundColor Yellow
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
    $trustPolicy | Out-File -FilePath "trust-policy.json" -Encoding utf8
    
    aws iam create-role `
        --role-name $taskRoleName `
        --assume-role-policy-document file://trust-policy.json `
        --tags Key=Project,Value=CA-A2A Key=Component,Value=Security Key=Owner,Value=j.benabderrazak@reply.com
    
    Start-Sleep -Seconds 2
    
    # Create S3 access policy
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
    $s3Policy | Out-File -FilePath "s3-policy.json" -Encoding utf8
    
    aws iam put-role-policy `
        --role-name $taskRoleName `
        --policy-name S3AccessPolicy `
        --policy-document file://s3-policy.json
    
    Remove-Item "trust-policy.json" -ErrorAction SilentlyContinue
    Remove-Item "s3-policy.json" -ErrorAction SilentlyContinue
    Write-Host "  Task role created successfully" -ForegroundColor Green
}

# 3. Verify/Tag ECR Repositories
Write-Host ""
Write-Host "[3/3] Verifying ECR Repositories..." -ForegroundColor Green
$agents = @("orchestrator", "extractor", "classifier", "qa-agent")

foreach ($agent in $agents) {
    $repoName = "$projectName-$agent"
    try {
        $ecrCheck = aws ecr describe-repositories --repository-names $repoName --region $region 2>&1 | ConvertFrom-Json
        if ($ecrCheck.repositories.Count -gt 0) {
            Write-Host "  ECR repo $repoName exists" -ForegroundColor Green
            # Try to add tags
            try {
                $repoArn = $ecrCheck.repositories[0].repositoryArn
                aws ecr tag-resource --resource-arn $repoArn --tags Key=Project,Value=CA-A2A Key=AgentName,Value=$agent --region $region
                Write-Host "    Tagged successfully" -ForegroundColor Gray
            } catch {
                Write-Host "    Already tagged" -ForegroundColor Gray
            }
        }
    } catch {
        Write-Host "  Creating ECR repo $repoName..." -ForegroundColor Yellow
        aws ecr create-repository `
            --repository-name $repoName `
            --image-scanning-configuration scanOnPush=true `
            --region $region `
            --tags Key=Project,Value=CA-A2A Key=AgentName,Value=$agent Key=Component,Value=Container-Registry
        Write-Host "  ECR repository $repoName created" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Fix Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Run status check to verify:" -ForegroundColor Cyan
Write-Host ".\scripts\check-deployment-status.ps1" -ForegroundColor White

