# Specific Resource Tagging Script for CA A2A Infrastructure
# Tags specific AWS resources by type (ECS, RDS, S3, ALB, etc.)

$region = "eu-west-3"
$projectName = "CA-A2A"
$environment = "Production"
$owner = "j.benabderrazak@reply.com"

# Common tags for all resources
$commonTags = @{
    "Project" = $projectName
    "Environment" = $environment
    "Owner" = $owner
    "ManagedBy" = "Terraform"
    "CostCenter" = "CA-Reply"
    "Application" = "Agent-Based-Architecture"
    "Version" = "1.0.0"
    "DeploymentDate" = (Get-Date -Format 'yyyy-MM-dd')
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CA A2A Resource Tagging Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Region: $region" -ForegroundColor Yellow
Write-Host ""

# Convert tags to AWS CLI format
function Get-TagsString {
    $tagList = @()
    foreach ($key in $commonTags.Keys) {
        $tagList += "Key=$key,Value=$($commonTags[$key])"
    }
    return $tagList -join " "
}

$tagsString = Get-TagsString

# 1. Tag ECS Resources
Write-Host "[1] Tagging ECS Resources..." -ForegroundColor Green
try {
    # List ECS Clusters
    $ecsClusters = aws ecs list-clusters --region $region | ConvertFrom-Json
    foreach ($clusterArn in $ecsClusters.clusterArns) {
        Write-Host "  - Tagging ECS Cluster: $clusterArn" -ForegroundColor Yellow
        aws ecs tag-resource --region $region --resource-arn $clusterArn --tags $tagsString
    }
    
    # List ECS Services
    foreach ($clusterArn in $ecsClusters.clusterArns) {
        $services = aws ecs list-services --region $region --cluster $clusterArn | ConvertFrom-Json
        foreach ($serviceArn in $services.serviceArns) {
            Write-Host "  - Tagging ECS Service: $serviceArn" -ForegroundColor Yellow
            aws ecs tag-resource --region $region --resource-arn $serviceArn --tags $tagsString
        }
    }
    
    # List ECS Task Definitions
    $taskDefs = aws ecs list-task-definitions --region $region --status ACTIVE | ConvertFrom-Json
    foreach ($taskDefArn in $taskDefs.taskDefinitionArns) {
        if ($taskDefArn -match "ca-a2a|orchestrator|extractor|classifier|qa") {
            Write-Host "  - Tagging Task Definition: $taskDefArn" -ForegroundColor Yellow
            aws ecs tag-resource --region $region --resource-arn $taskDefArn --tags $tagsString
        }
    }
    Write-Host "  ✓ ECS resources tagged" -ForegroundColor Green
} catch {
    Write-Host "  ✗ No ECS resources found or error: $_" -ForegroundColor Red
}

# 2. Tag RDS Resources
Write-Host "`n[2] Tagging RDS Resources..." -ForegroundColor Green
try {
    $rdsInstances = aws rds describe-db-instances --region $region | ConvertFrom-Json
    foreach ($instance in $rdsInstances.DBInstances) {
        $dbArn = $instance.DBInstanceArn
        Write-Host "  - Tagging RDS Instance: $($instance.DBInstanceIdentifier)" -ForegroundColor Yellow
        aws rds add-tags-to-resource --region $region --resource-name $dbArn --tags $tagsString
    }
    Write-Host "  ✓ RDS resources tagged" -ForegroundColor Green
} catch {
    Write-Host "  ✗ No RDS resources found or error: $_" -ForegroundColor Red
}

# 3. Tag S3 Buckets
Write-Host "`n[3] Tagging S3 Buckets..." -ForegroundColor Green
try {
    $s3Buckets = aws s3api list-buckets --region $region | ConvertFrom-Json
    foreach ($bucket in $s3Buckets.Buckets) {
        $bucketName = $bucket.Name
        if ($bucketName -match "ca-a2a|documents|agents") {
            Write-Host "  - Tagging S3 Bucket: $bucketName" -ForegroundColor Yellow
            
            # Create tag set for S3
            $s3TagSet = @{
                TagSet = @()
            }
            foreach ($key in $commonTags.Keys) {
                $s3TagSet.TagSet += @{
                    Key = $key
                    Value = $commonTags[$key]
                }
            }
            $s3TagJson = $s3TagSet | ConvertTo-Json -Depth 5
            
            $s3TagJson | Out-File -FilePath "temp_s3_tags.json" -Encoding UTF8
            aws s3api put-bucket-tagging --bucket $bucketName --tagging "file://temp_s3_tags.json"
            Remove-Item "temp_s3_tags.json" -ErrorAction SilentlyContinue
        }
    }
    Write-Host "  ✓ S3 buckets tagged" -ForegroundColor Green
} catch {
    Write-Host "  ✗ No S3 buckets found or error: $_" -ForegroundColor Red
}

# 4. Tag Application Load Balancers
Write-Host "`n[4] Tagging Application Load Balancers..." -ForegroundColor Green
try {
    $albs = aws elbv2 describe-load-balancers --region $region | ConvertFrom-Json
    foreach ($alb in $albs.LoadBalancers) {
        $albArn = $alb.LoadBalancerArn
        Write-Host "  - Tagging ALB: $($alb.LoadBalancerName)" -ForegroundColor Yellow
        aws elbv2 add-tags --region $region --resource-arns $albArn --tags $tagsString
        
        # Tag target groups
        $targetGroups = aws elbv2 describe-target-groups --region $region --load-balancer-arn $albArn | ConvertFrom-Json
        foreach ($tg in $targetGroups.TargetGroups) {
            Write-Host "  - Tagging Target Group: $($tg.TargetGroupName)" -ForegroundColor Yellow
            aws elbv2 add-tags --region $region --resource-arns $tg.TargetGroupArn --tags $tagsString
        }
    }
    Write-Host "  ✓ Load Balancer resources tagged" -ForegroundColor Green
} catch {
    Write-Host "  ✗ No ALB resources found or error: $_" -ForegroundColor Red
}

# 5. Tag VPC Resources
Write-Host "`n[5] Tagging VPC Resources..." -ForegroundColor Green
try {
    # Tag VPCs
    $vpcs = aws ec2 describe-vpcs --region $region | ConvertFrom-Json
    foreach ($vpc in $vpcs.Vpcs) {
        Write-Host "  - Tagging VPC: $($vpc.VpcId)" -ForegroundColor Yellow
        aws ec2 create-tags --region $region --resources $vpc.VpcId --tags $tagsString
    }
    
    # Tag Subnets
    $subnets = aws ec2 describe-subnets --region $region | ConvertFrom-Json
    foreach ($subnet in $subnets.Subnets) {
        Write-Host "  - Tagging Subnet: $($subnet.SubnetId)" -ForegroundColor Yellow
        aws ec2 create-tags --region $region --resources $subnet.SubnetId --tags $tagsString
    }
    
    # Tag Security Groups (filter for CA-A2A related)
    $securityGroups = aws ec2 describe-security-groups --region $region | ConvertFrom-Json
    foreach ($sg in $securityGroups.SecurityGroups) {
        if ($sg.GroupName -match "ca-a2a|agent|orchestrator") {
            Write-Host "  - Tagging Security Group: $($sg.GroupName)" -ForegroundColor Yellow
            aws ec2 create-tags --region $region --resources $sg.GroupId --tags $tagsString
        }
    }
    
    Write-Host "  ✓ VPC resources tagged" -ForegroundColor Green
} catch {
    Write-Host "  ✗ No VPC resources found or error: $_" -ForegroundColor Red
}

# 6. Tag CloudWatch Resources
Write-Host "`n[6] Tagging CloudWatch Log Groups..." -ForegroundColor Green
try {
    $logGroups = aws logs describe-log-groups --region $region | ConvertFrom-Json
    foreach ($logGroup in $logGroups.logGroups) {
        if ($logGroup.logGroupName -match "ca-a2a|/ecs/|agent") {
            Write-Host "  - Tagging Log Group: $($logGroup.logGroupName)" -ForegroundColor Yellow
            aws logs tag-log-group --region $region --log-group-name $logGroup.logGroupName --tags $($commonTags | ConvertTo-Json -Compress)
        }
    }
    Write-Host "  ✓ CloudWatch Log Groups tagged" -ForegroundColor Green
} catch {
    Write-Host "  ✗ No CloudWatch Log Groups found or error: $_" -ForegroundColor Red
}

# 7. Tag ECR Repositories
Write-Host "`n[7] Tagging ECR Repositories..." -ForegroundColor Green
try {
    $ecrRepos = aws ecr describe-repositories --region $region | ConvertFrom-Json
    foreach ($repo in $ecrRepos.repositories) {
        if ($repo.repositoryName -match "ca-a2a|orchestrator|extractor|classifier|qa") {
            Write-Host "  - Tagging ECR Repository: $($repo.repositoryName)" -ForegroundColor Yellow
            aws ecr tag-resource --region $region --resource-arn $repo.repositoryArn --tags $tagsString
        }
    }
    Write-Host "  ✓ ECR repositories tagged" -ForegroundColor Green
} catch {
    Write-Host "  ✗ No ECR repositories found or error: $_" -ForegroundColor Red
}

# 8. Tag IAM Roles (for ECS tasks)
Write-Host "`n[8] Tagging IAM Roles..." -ForegroundColor Green
try {
    $iamRoles = aws iam list-roles | ConvertFrom-Json
    foreach ($role in $iamRoles.Roles) {
        if ($role.RoleName -match "ca-a2a|ECSTask|agent") {
            Write-Host "  - Tagging IAM Role: $($role.RoleName)" -ForegroundColor Yellow
            aws iam tag-role --role-name $role.RoleName --tags $tagsString
        }
    }
    Write-Host "  ✓ IAM roles tagged" -ForegroundColor Green
} catch {
    Write-Host "  ✗ No IAM roles found or error: $_" -ForegroundColor Red
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Tagging Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Query resources by project tag
Write-Host "`nVerifying tagged resources..." -ForegroundColor Yellow
$taggedResources = aws resourcegroupstaggingapi get-resources `
    --region $region `
    --tag-filters "Key=Project,Values=$projectName" | ConvertFrom-Json

Write-Host "Total resources tagged with Project=$projectName : $($taggedResources.ResourceTagMappingList.Count)" -ForegroundColor Green

# Group by resource type
$resourceTypes = @{}
foreach ($resource in $taggedResources.ResourceTagMappingList) {
    if ($resource.ResourceARN -match "arn:aws:([^:]+):") {
        $type = $matches[1]
        if (-not $resourceTypes.ContainsKey($type)) {
            $resourceTypes[$type] = 0
        }
        $resourceTypes[$type]++
    }
}

Write-Host "`nResources by type:" -ForegroundColor Cyan
foreach ($type in $resourceTypes.Keys | Sort-Object) {
    Write-Host "  - $type : $($resourceTypes[$type])" -ForegroundColor White
}

Write-Host "`nTagging Complete!" -ForegroundColor Green
Write-Host "All CA A2A resources have been tagged consistently." -ForegroundColor Green

