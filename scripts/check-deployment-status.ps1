# CA A2A - Check Deployment Status

$region = "eu-west-3"
$projectName = "ca-a2a"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CA A2A Deployment Status Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# RDS Status
Write-Host "[1] RDS PostgreSQL Instance" -ForegroundColor Green
try {
    $rdsStatus = aws rds describe-db-instances --db-instance-identifier "$projectName-postgres" --region $region --query 'DBInstances[0].[DBInstanceStatus,Endpoint.Address]' --output text 2>&1
    if ($LASTEXITCODE -eq 0) {
        $statusParts = $rdsStatus -split "`t"
        Write-Host "  Status: $($statusParts[0])" -ForegroundColor $(if ($statusParts[0] -eq "available") { "Green" } else { "Yellow" })
        if ($statusParts[1]) {
            Write-Host "  Endpoint: $($statusParts[1])" -ForegroundColor White
        }
    } else {
        Write-Host "  Not found" -ForegroundColor Red
    }
} catch {
    Write-Host "  Not found" -ForegroundColor Red
}

# S3 Bucket
Write-Host ""
Write-Host "[2] S3 Buckets" -ForegroundColor Green
try {
    $buckets = aws s3 ls | Select-String "ca-a2a"
    if ($buckets) {
        Write-Host "  Found:" -ForegroundColor White
        $buckets | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
    } else {
        Write-Host "  No CA-A2A buckets found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Error checking buckets" -ForegroundColor Red
}

# ECS Cluster
Write-Host ""
Write-Host "[3] ECS Cluster" -ForegroundColor Green
try {
    $ecsStatus = aws ecs describe-clusters --clusters "$projectName-cluster" --region $region --query 'clusters[0].[status,runningTasksCount,pendingTasksCount]' --output text 2>&1
    if ($LASTEXITCODE -eq 0) {
        $statusParts = $ecsStatus -split "`t"
        Write-Host "  Status: $($statusParts[0])" -ForegroundColor $(if ($statusParts[0] -eq "ACTIVE") { "Green" } else { "Yellow" })
        Write-Host "  Running Tasks: $($statusParts[1])" -ForegroundColor White
        Write-Host "  Pending Tasks: $($statusParts[2])" -ForegroundColor White
    } else {
        Write-Host "  Not found" -ForegroundColor Red
    }
} catch {
    Write-Host "  Not found" -ForegroundColor Red
}

# ECR Repositories
Write-Host ""
Write-Host "[4] ECR Repositories" -ForegroundColor Green
try {
    $repos = aws ecr describe-repositories --region $region --query 'repositories[?contains(repositoryName,`ca-a2a`)].repositoryName' --output text 2>&1
    if ($LASTEXITCODE -eq 0 -and $repos) {
        Write-Host "  Found:" -ForegroundColor White
        $repos -split "`t" | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
    } else {
        Write-Host "  No repositories found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Error checking repositories" -ForegroundColor Red
}

# DB Subnet Group
Write-Host ""
Write-Host "[5] RDS DB Subnet Group" -ForegroundColor Green
try {
    $subnetGroup = aws rds describe-db-subnet-groups --db-subnet-group-name "$projectName-db-subnet" --region $region --query 'DBSubnetGroups[0].DBSubnetGroupName' --output text 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Status: Exists" -ForegroundColor Green
        Write-Host "  Name: $subnetGroup" -ForegroundColor White
    } else {
        Write-Host "  Not found" -ForegroundColor Red
    }
} catch {
    Write-Host "  Not found" -ForegroundColor Red
}

# CloudWatch Log Groups
Write-Host ""
Write-Host "[6] CloudWatch Log Groups" -ForegroundColor Green
try {
    $logGroups = aws logs describe-log-groups --region $region --log-group-name-prefix "/ecs/ca-a2a" --query 'logGroups[*].logGroupName' --output text 2>&1
    if ($LASTEXITCODE -eq 0 -and $logGroups) {
        Write-Host "  Found:" -ForegroundColor White
        $logGroups -split "`t" | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
    } else {
        Write-Host "  No log groups found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Error checking log groups" -ForegroundColor Red
}

# IAM Roles
Write-Host ""
Write-Host "[7] IAM Roles" -ForegroundColor Green
try {
    $roles = aws iam list-roles --query 'Roles[?contains(RoleName,`ca-a2a`)].RoleName' --output text 2>&1
    if ($LASTEXITCODE -eq 0 -and $roles) {
        Write-Host "  Found:" -ForegroundColor White
        $roles -split "`t" | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
    } else {
        Write-Host "  No IAM roles found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Error checking IAM roles" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Status check complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

