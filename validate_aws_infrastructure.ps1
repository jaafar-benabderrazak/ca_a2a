# AWS Infrastructure Validation Script
# Validates that all required AWS resources are properly configured

param(
    [Parameter(Mandatory=$false)]
    [string]$AwsRegion = "us-east-1"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "AWS Infrastructure Validation" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$env:AWS_DEFAULT_REGION = $AwsRegion

# Validation results
$results = @()

function Add-ValidationResult {
    param(
        [string]$Category,
        [string]$Resource,
        [bool]$Passed,
        [string]$Message
    )
    
    $results += [PSCustomObject]@{
        Category = $Category
        Resource = $Resource
        Passed = $Passed
        Message = $Message
    }
    
    $icon = if ($Passed) { "✓" } else { "✗" }
    $color = if ($Passed) { "Green" } else { "Red" }
    
    Write-Host "  $icon $Resource : $Message" -ForegroundColor $color
}

# 1. AWS Credentials
Write-Host "`n[1] AWS Credentials" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Yellow

try {
    $identity = aws sts get-caller-identity --query '[Account,Arn]' --output text 2>&1
    if ($LASTEXITCODE -eq 0) {
        Add-ValidationResult -Category "Credentials" -Resource "AWS Identity" -Passed $true -Message $identity
    } else {
        Add-ValidationResult -Category "Credentials" -Resource "AWS Identity" -Passed $false -Message "Not authenticated"
    }
}
catch {
    Add-ValidationResult -Category "Credentials" -Resource "AWS Identity" -Passed $false -Message $_.Exception.Message
}

# 2. VPC and Networking
Write-Host "`n[2] VPC and Networking" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Yellow

try {
    $vpcs = aws ec2 describe-vpcs --filters "Name=tag:Application,Values=ca-a2a" --query 'Vpcs[*].VpcId' --output text 2>&1
    if ($LASTEXITCODE -eq 0 -and $vpcs) {
        Add-ValidationResult -Category "Networking" -Resource "VPC" -Passed $true -Message "Found: $vpcs"
        
        # Check subnets
        $subnets = aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpcs" --query 'Subnets[*].[SubnetId,AvailabilityZone]' --output text 2>&1
        $subnetCount = ($subnets -split "`n").Count
        Add-ValidationResult -Category "Networking" -Resource "Subnets" -Passed ($subnetCount -ge 2) -Message "Found $subnetCount subnets"
        
        # Check internet gateway
        $igw = aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$vpcs" --query 'InternetGateways[0].InternetGatewayId' --output text 2>&1
        Add-ValidationResult -Category "Networking" -Resource "Internet Gateway" -Passed ($igw -ne $null) -Message $(if ($igw) { "Found: $igw" } else { "Not found" })
    } else {
        Add-ValidationResult -Category "Networking" -Resource "VPC" -Passed $false -Message "No VPC found with tag Application=ca-a2a"
    }
}
catch {
    Add-ValidationResult -Category "Networking" -Resource "VPC" -Passed $false -Message $_.Exception.Message
}

# Check security groups
try {
    $sgs = aws ec2 describe-security-groups --filters "Name=tag:Application,Values=ca-a2a" --query 'SecurityGroups[*].[GroupId,GroupName]' --output text 2>&1
    $sgCount = ($sgs -split "`n" | Where-Object { $_ }).Count
    Add-ValidationResult -Category "Networking" -Resource "Security Groups" -Passed ($sgCount -gt 0) -Message "Found $sgCount security groups"
}
catch {
    Add-ValidationResult -Category "Networking" -Resource "Security Groups" -Passed $false -Message $_.Exception.Message
}

# 3. RDS Database
Write-Host "`n[3] RDS Database" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Yellow

try {
    $dbInstances = aws rds describe-db-instances --query 'DBInstances[?contains(DBInstanceIdentifier, `ca-a2a`)].{ID:DBInstanceIdentifier,Status:DBInstanceStatus,Endpoint:Endpoint.Address}' --output json 2>&1 | ConvertFrom-Json
    
    if ($dbInstances) {
        foreach ($db in $dbInstances) {
            $passed = $db.Status -eq "available"
            Add-ValidationResult -Category "Database" -Resource $db.ID -Passed $passed -Message "Status: $($db.Status), Endpoint: $($db.Endpoint)"
        }
    } else {
        Add-ValidationResult -Category "Database" -Resource "RDS Instance" -Passed $false -Message "No RDS instances found"
    }
}
catch {
    Add-ValidationResult -Category "Database" -Resource "RDS Instance" -Passed $false -Message $_.Exception.Message
}

# 4. S3 Bucket
Write-Host "`n[4] S3 Bucket" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Yellow

try {
    $accountId = aws sts get-caller-identity --query Account --output text
    $bucketName = "ca-a2a-documents-$accountId"
    
    $bucketExists = aws s3 ls "s3://$bucketName" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Add-ValidationResult -Category "Storage" -Resource "S3 Bucket" -Passed $true -Message "Found: $bucketName"
        
        # Check versioning
        $versioning = aws s3api get-bucket-versioning --bucket $bucketName --query 'Status' --output text 2>&1
        Add-ValidationResult -Category "Storage" -Resource "S3 Versioning" -Passed ($versioning -eq "Enabled") -Message "Status: $versioning"
        
        # Check encryption
        $encryption = aws s3api get-bucket-encryption --bucket $bucketName --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>&1
        Add-ValidationResult -Category "Storage" -Resource "S3 Encryption" -Passed ($encryption -eq "AES256" -or $encryption -eq "aws:kms") -Message "Algorithm: $encryption"
    } else {
        Add-ValidationResult -Category "Storage" -Resource "S3 Bucket" -Passed $false -Message "Bucket not found: $bucketName"
    }
}
catch {
    Add-ValidationResult -Category "Storage" -Resource "S3 Bucket" -Passed $false -Message $_.Exception.Message
}

# 5. ECR Repositories
Write-Host "`n[5] ECR Repositories" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Yellow

$expectedRepos = @("orchestrator", "extractor", "validator", "archivist")

foreach ($repo in $expectedRepos) {
    try {
        $repoUri = aws ecr describe-repositories --repository-names "ca-a2a/$repo" --query 'repositories[0].repositoryUri' --output text 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $repoUri) {
            # Check if images exist
            $images = aws ecr list-images --repository-name "ca-a2a/$repo" --query 'imageIds[*].imageTag' --output text 2>&1
            $imageCount = ($images -split "`s+" | Where-Object { $_ }).Count
            
            Add-ValidationResult -Category "Container Registry" -Resource "ca-a2a/$repo" -Passed ($imageCount -gt 0) -Message "Found $imageCount images"
        } else {
            Add-ValidationResult -Category "Container Registry" -Resource "ca-a2a/$repo" -Passed $false -Message "Repository not found"
        }
    }
    catch {
        Add-ValidationResult -Category "Container Registry" -Resource "ca-a2a/$repo" -Passed $false -Message $_.Exception.Message
    }
}

# 6. ECS Cluster and Services
Write-Host "`n[6] ECS Cluster and Services" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Yellow

try {
    $cluster = aws ecs describe-clusters --clusters ca-a2a-cluster --query 'clusters[0].{Name:clusterName,Status:status,Running:runningTasksCount,Pending:pendingTasksCount}' --output json 2>&1 | ConvertFrom-Json
    
    if ($cluster) {
        $passed = $cluster.Status -eq "ACTIVE" -and $cluster.Running -gt 0
        Add-ValidationResult -Category "ECS" -Resource "Cluster" -Passed $passed -Message "Status: $($cluster.Status), Running: $($cluster.Running), Pending: $($cluster.Pending)"
    } else {
        Add-ValidationResult -Category "ECS" -Resource "Cluster" -Passed $false -Message "Cluster 'ca-a2a-cluster' not found"
    }
}
catch {
    Add-ValidationResult -Category "ECS" -Resource "Cluster" -Passed $false -Message $_.Exception.Message
}

# Check services
$expectedServices = @("orchestrator", "extractor", "validator", "archivist")

foreach ($service in $expectedServices) {
    try {
        $svcInfo = aws ecs describe-services --cluster ca-a2a-cluster --services $service --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount}' --output json 2>&1 | ConvertFrom-Json
        
        if ($svcInfo) {
            $passed = $svcInfo.Status -eq "ACTIVE" -and $svcInfo.Running -eq $svcInfo.Desired
            Add-ValidationResult -Category "ECS" -Resource "Service: $service" -Passed $passed -Message "Running: $($svcInfo.Running)/$($svcInfo.Desired)"
        } else {
            Add-ValidationResult -Category "ECS" -Resource "Service: $service" -Passed $false -Message "Service not found"
        }
    }
    catch {
        Add-ValidationResult -Category "ECS" -Resource "Service: $service" -Passed $false -Message $_.Exception.Message
    }
}

# 7. Load Balancer
Write-Host "`n[7] Load Balancer" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Yellow

try {
    $alb = aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].{Name:LoadBalancerName,DNS:DNSName,State:State.Code}' --output json 2>&1 | ConvertFrom-Json
    
    if ($alb) {
        $passed = $alb.State -eq "active"
        Add-ValidationResult -Category "Load Balancer" -Resource "ALB" -Passed $passed -Message "State: $($alb.State), DNS: $($alb.DNS)"
        
        # Check target groups
        $tgs = aws elbv2 describe-target-groups --query 'TargetGroups[?contains(TargetGroupName, `ca-a2a`)].TargetGroupName' --output text 2>&1
        $tgCount = ($tgs -split "`s+" | Where-Object { $_ }).Count
        Add-ValidationResult -Category "Load Balancer" -Resource "Target Groups" -Passed ($tgCount -gt 0) -Message "Found $tgCount target groups"
        
        # Check target health
        $tgArn = aws elbv2 describe-target-groups --names ca-a2a-orchestrator-tg --query 'TargetGroups[0].TargetGroupArn' --output text 2>$null
        if ($tgArn) {
            $health = aws elbv2 describe-target-health --target-group-arn $tgArn --query 'TargetHealthDescriptions[*].TargetHealth.State' --output text 2>&1
            $healthyCount = ($health -split "`s+" | Where-Object { $_ -eq "healthy" }).Count
            Add-ValidationResult -Category "Load Balancer" -Resource "Target Health" -Passed ($healthyCount -gt 0) -Message "$healthyCount healthy targets"
        }
    } else {
        Add-ValidationResult -Category "Load Balancer" -Resource "ALB" -Passed $false -Message "Load balancer 'ca-a2a-alb' not found"
    }
}
catch {
    Add-ValidationResult -Category "Load Balancer" -Resource "ALB" -Passed $false -Message $_.Exception.Message
}

# 8. Service Discovery (Cloud Map)
Write-Host "`n[8] Service Discovery" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Yellow

try {
    $namespace = aws servicediscovery list-namespaces --query 'Namespaces[?Name==`local`].{Name:Name,Id:Id,Type:Type}' --output json 2>&1 | ConvertFrom-Json
    
    if ($namespace) {
        Add-ValidationResult -Category "Service Discovery" -Resource "Namespace" -Passed $true -Message "Found: local ($($namespace.Id))"
        
        # Check services
        $services = aws servicediscovery list-services --filters Name=NAMESPACE_ID,Values=$($namespace.Id) --query 'Services[*].Name' --output text 2>&1
        $serviceCount = ($services -split "`s+" | Where-Object { $_ }).Count
        Add-ValidationResult -Category "Service Discovery" -Resource "Registered Services" -Passed ($serviceCount -ge 3) -Message "Found $serviceCount services"
    } else {
        Add-ValidationResult -Category "Service Discovery" -Resource "Namespace" -Passed $false -Message "Namespace 'local' not found"
    }
}
catch {
    Add-ValidationResult -Category "Service Discovery" -Resource "Cloud Map" -Passed $false -Message $_.Exception.Message
}

# 9. CloudWatch Logs
Write-Host "`n[9] CloudWatch Logs" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Yellow

$logGroups = @("/ecs/ca-a2a-orchestrator", "/ecs/ca-a2a-extractor", "/ecs/ca-a2a-validator", "/ecs/ca-a2a-archivist")

foreach ($logGroup in $logGroups) {
    try {
        $streams = aws logs describe-log-streams --log-group-name $logGroup --max-items 1 --order-by LastEventTime --descending --query 'logStreams[0].lastEventTimestamp' --output text 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $streams) {
            $lastEvent = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$streams).DateTime
            $minutesAgo = ([DateTime]::Now - $lastEvent).TotalMinutes
            
            $passed = $minutesAgo -lt 10  # Recent logs within 10 minutes
            Add-ValidationResult -Category "Logging" -Resource $logGroup -Passed $passed -Message "Last event: $([math]::Round($minutesAgo, 1)) minutes ago"
        } else {
            Add-ValidationResult -Category "Logging" -Resource $logGroup -Passed $false -Message "No log streams found"
        }
    }
    catch {
        Add-ValidationResult -Category "Logging" -Resource $logGroup -Passed $false -Message $_.Exception.Message
    }
}

# 10. IAM Roles
Write-Host "`n[10] IAM Roles" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Yellow

$expectedRoles = @("ecsTaskExecutionRole", "ca-a2a-task-role")

foreach ($role in $expectedRoles) {
    try {
        $roleInfo = aws iam get-role --role-name $role --query 'Role.RoleName' --output text 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Add-ValidationResult -Category "IAM" -Resource $role -Passed $true -Message "Found"
        } else {
            Add-ValidationResult -Category "IAM" -Resource $role -Passed $false -Message "Not found"
        }
    }
    catch {
        Add-ValidationResult -Category "IAM" -Resource $role -Passed $false -Message $_.Exception.Message
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Validation Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$totalChecks = $results.Count
$passedChecks = ($results | Where-Object { $_.Passed }).Count
$failedChecks = $totalChecks - $passedChecks

Write-Host "Total Checks: $totalChecks" -ForegroundColor Cyan
Write-Host "Passed: $passedChecks" -ForegroundColor Green
Write-Host "Failed: $failedChecks" -ForegroundColor $(if ($failedChecks -eq 0) { "Gray" } else { "Red" })

$passPercentage = [math]::Round(($passedChecks / $totalChecks) * 100, 1)
Write-Host "Success Rate: $passPercentage%" -ForegroundColor $(if ($passPercentage -eq 100) { "Green" } elseif ($passPercentage -ge 80) { "Yellow" } else { "Red" })

# Group by category
Write-Host "`nResults by Category:" -ForegroundColor Cyan
$results | Group-Object -Property Category | ForEach-Object {
    $categoryPassed = ($_.Group | Where-Object { $_.Passed }).Count
    $categoryTotal = $_.Count
    $categoryIcon = if ($categoryPassed -eq $categoryTotal) { "✓" } elseif ($categoryPassed -eq 0) { "✗" } else { "⚠" }
    
    Write-Host "  $categoryIcon $($_.Name): $categoryPassed/$categoryTotal" -ForegroundColor $(if ($categoryPassed -eq $categoryTotal) { "Green" } elseif ($categoryPassed -gt 0) { "Yellow" } else { "Red" })
}

if ($failedChecks -gt 0) {
    Write-Host "`nFailed Checks:" -ForegroundColor Red
    $results | Where-Object { -not $_.Passed } | ForEach-Object {
        Write-Host "  ✗ [$($_.Category)] $($_.Resource): $($_.Message)" -ForegroundColor Red
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Recommendations" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($passPercentage -eq 100) {
    Write-Host "✓ All infrastructure checks passed!" -ForegroundColor Green
    Write-Host "  Your AWS infrastructure is properly configured." -ForegroundColor Gray
    Write-Host "  Ready for deployment testing!" -ForegroundColor Gray
} elseif ($passPercentage -ge 80) {
    Write-Host "⚠ Most infrastructure checks passed." -ForegroundColor Yellow
    Write-Host "  Review and fix the failed checks above." -ForegroundColor Gray
    Write-Host "  Some features may not work until all checks pass." -ForegroundColor Gray
} else {
    Write-Host "✗ Multiple infrastructure issues detected." -ForegroundColor Red
    Write-Host "  Please review the AWS deployment guide and fix issues." -ForegroundColor Gray
    Write-Host "  See: AWS_DEPLOYMENT.md" -ForegroundColor Gray
}

Write-Host "`nValidation complete!`n" -ForegroundColor Cyan
