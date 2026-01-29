###############################################################################
# CA-A2A eu-west-3 Deployment Deletion Script
# This script removes ALL CA-A2A resources deployed in eu-west-3
# Date: January 29, 2026
# WARNING: This is a destructive operation and cannot be undone
###############################################################################

param(
    [string]$Region = "eu-west-3",
    [string]$ProjectName = "ca-a2a",
    [string]$AccountId = "555043101106"
)

$ErrorActionPreference = "Continue"

function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }
function Write-Header { param([string]$Message) Write-Host $Message -ForegroundColor Cyan }

Write-Host ""
Write-Header "==================================================================="
Write-Header "CA-A2A EU-WEST-3 DEPLOYMENT DELETION"
Write-Header "==================================================================="
Write-Host "Region: $Region"
Write-Host "Account: $AccountId"
Write-Host ""

###############################################################################
# PHASE 1: AUDIT CURRENT RESOURCES
###############################################################################

Write-Header "=== PHASE 1: AUDITING CURRENT RESOURCES ==="
Write-Host ""

$resourceCount = 0
$resourcesList = @()

Write-Info "[1/15] Checking ECS Cluster..."
try {
    $ecsCluster = aws ecs describe-clusters --clusters "$ProjectName-cluster" --region $Region --query 'clusters[0].clusterArn' --output text 2>&1
    if ($ecsCluster -and $ecsCluster -ne "None" -and -not $ecsCluster.ToString().Contains("Error")) {
        Write-Host "  ✓ Found: $ecsCluster"
        $resourceCount++
        $resourcesList += "  - ECS Cluster"
    }
} catch { }

Write-Info "[2/15] Checking ECS Services..."
$ecsServices = @()
if ($ecsCluster -and $ecsCluster -ne "None") {
    try {
        $servicesJson = aws ecs list-services --cluster "$ProjectName-cluster" --region $Region --query 'serviceArns' --output json 2>&1 | ConvertFrom-Json
        if ($servicesJson -and $servicesJson.Count -gt 0) {
            $ecsServices = $servicesJson
            Write-Host "  ✓ Found $($ecsServices.Count) services:"
            foreach ($svc in $ecsServices) {
                $svcName = $svc.Split('/')[-1]
                Write-Host "    - $svcName"
            }
            $resourceCount += $ecsServices.Count
            $resourcesList += "  - $($ecsServices.Count) ECS Services"
        }
    } catch { }
}

Write-Info "[3/15] Checking RDS Clusters..."
$rdsClusters = @()
try {
    $rdsOutput = aws rds describe-db-clusters --region $Region --query 'DBClusters[?contains(DBClusterIdentifier, `ca-a2a`) || contains(DBClusterIdentifier, `documents-db`) || contains(DBClusterIdentifier, `keycloak`)].DBClusterIdentifier' --output text 2>&1
    if ($rdsOutput -and $rdsOutput -ne "None" -and -not $rdsOutput.ToString().Contains("Error")) {
        $rdsClusters = $rdsOutput -split '\s+'
        Write-Host "  ✓ Found RDS clusters: $($rdsClusters -join ', ')"
        $resourceCount += $rdsClusters.Count
        $resourcesList += "  - $($rdsClusters.Count) RDS Clusters"
    }
} catch { }

Write-Info "[4/15] Checking S3 Buckets..."
$s3Buckets = @()
try {
    $s3Output = aws s3api list-buckets --query 'Buckets[?contains(Name, `ca-a2a`)].Name' --output text 2>&1
    if ($s3Output -and $s3Output -ne "None" -and -not $s3Output.ToString().Contains("Error")) {
        $s3Buckets = $s3Output -split '\s+'
        Write-Host "  ✓ Found S3 buckets: $($s3Buckets -join ', ')"
        $resourceCount += $s3Buckets.Count
        $resourcesList += "  - $($s3Buckets.Count) S3 Buckets"
    }
} catch { }

Write-Info "[5/15] Checking Load Balancers..."
$albs = @()
try {
    $albOutput = aws elbv2 describe-load-balancers --region $Region --query 'LoadBalancers[?contains(LoadBalancerName, `ca-a2a`)].LoadBalancerArn' --output text 2>&1
    if ($albOutput -and $albOutput -ne "None" -and -not $albOutput.ToString().Contains("Error")) {
        $albs = $albOutput -split '\s+'
        Write-Host "  ✓ Found $($albs.Count) ALB(s)"
        $resourceCount += $albs.Count
        $resourcesList += "  - $($albs.Count) Application Load Balancer(s)"
    }
} catch { }

Write-Info "[6/15] Checking Target Groups..."
$tgs = @()
try {
    $tgOutput = aws elbv2 describe-target-groups --region $Region --query 'TargetGroups[?contains(TargetGroupName, `ca-a2a`)].TargetGroupArn' --output text 2>&1
    if ($tgOutput -and $tgOutput -ne "None" -and -not $tgOutput.ToString().Contains("Error")) {
        $tgs = $tgOutput -split '\s+'
        Write-Host "  ✓ Found $($tgs.Count) Target Group(s)"
        $resourceCount += $tgs.Count
        $resourcesList += "  - $($tgs.Count) Target Groups"
    }
} catch { }

Write-Info "[7/15] Checking ECR Repositories..."
$ecrRepos = @()
try {
    $ecrOutput = aws ecr describe-repositories --region $Region --query 'repositories[?contains(repositoryName, `ca-a2a`)].repositoryName' --output text 2>&1
    if ($ecrOutput -and $ecrOutput -ne "None" -and -not $ecrOutput.ToString().Contains("Error")) {
        $ecrRepos = $ecrOutput -split '\s+'
        Write-Host "  ✓ Found ECR repositories: $($ecrRepos -join ', ')"
        $resourceCount += $ecrRepos.Count
        $resourcesList += "  - $($ecrRepos.Count) ECR Repositories"
    }
} catch { }

Write-Info "[8/15] Checking VPCs..."
$vpcs = @()
try {
    $vpcOutput = aws ec2 describe-vpcs --region $Region --filters "Name=tag:Name,Values=*ca-a2a*" --query 'Vpcs[].VpcId' --output text 2>&1
    if ($vpcOutput -and $vpcOutput -ne "None" -and -not $vpcOutput.ToString().Contains("Error")) {
        $vpcs = $vpcOutput -split '\s+'
        Write-Host "  ✓ Found VPCs: $($vpcs -join ', ')"
        $resourceCount += $vpcs.Count
        $resourcesList += "  - $($vpcs.Count) VPC(s)"
    }
} catch { }

Write-Info "[9/15] Checking CloudWatch Log Groups..."
$logGroups = @()
try {
    $logOutput = aws logs describe-log-groups --region $Region --log-group-name-prefix "/ecs/ca-a2a" --query 'logGroups[].logGroupName' --output text 2>&1
    if ($logOutput -and $logOutput -ne "None" -and -not $logOutput.ToString().Contains("Error")) {
        $logGroups = $logOutput -split '\s+'
        Write-Host "  ✓ Found $($logGroups.Count) log group(s)"
        $resourceCount += $logGroups.Count
        $resourcesList += "  - $($logGroups.Count) CloudWatch Log Groups"
    }
} catch { }

Write-Info "[10/15] Checking Secrets Manager..."
$secrets = @()
try {
    $secretOutput = aws secretsmanager list-secrets --region $Region --query 'SecretList[?contains(Name, `ca-a2a`)].Name' --output text 2>&1
    if ($secretOutput -and $secretOutput -ne "None" -and -not $secretOutput.ToString().Contains("Error")) {
        $secrets = $secretOutput -split '\s+'
        Write-Host "  ✓ Found secrets: $($secrets -join ', ')"
        $resourceCount += $secrets.Count
        $resourcesList += "  - $($secrets.Count) Secrets"
    }
} catch { }

Write-Info "[11/15] Checking IAM Roles..."
$iamRoles = @()
try {
    $iamOutput = aws iam list-roles --query 'Roles[?contains(RoleName, `ca-a2a`)].RoleName' --output text 2>&1
    if ($iamOutput -and $iamOutput -ne "None" -and -not $iamOutput.ToString().Contains("Error")) {
        $iamRoles = $iamOutput -split '\s+'
        Write-Host "  ✓ Found IAM roles: $($iamRoles -join ', ')"
        $resourceCount += $iamRoles.Count
        $resourcesList += "  - $($iamRoles.Count) IAM Roles"
    }
} catch { }

Write-Info "[12/15] Checking Service Discovery Namespace..."
$namespaces = @()
try {
    $nsOutput = aws servicediscovery list-namespaces --query 'Namespaces[?Name==`ca-a2a.local`].Id' --output text --region $Region 2>&1
    if ($nsOutput -and $nsOutput -ne "None" -and -not $nsOutput.ToString().Contains("Error")) {
        $namespaces = $nsOutput -split '\s+'
        Write-Host "  ✓ Found service discovery namespace"
        $resourceCount++
        $resourcesList += "  - Service Discovery Namespace"
    }
} catch { }

Write-Info "[13/15] Checking SQS Queues..."
$sqsQueues = @()
try {
    $sqsOutput = aws sqs list-queues --region $Region --queue-name-prefix "ca-a2a" --query 'QueueUrls' --output text 2>&1
    if ($sqsOutput -and $sqsOutput -ne "None" -and -not $sqsOutput.ToString().Contains("Error")) {
        $sqsQueues = $sqsOutput -split '\s+'
        Write-Host "  ✓ Found $($sqsQueues.Count) SQS queue(s)"
        $resourceCount += $sqsQueues.Count
        $resourcesList += "  - $($sqsQueues.Count) SQS Queues"
    }
} catch { }

Write-Info "[14/15] Checking VPC Endpoints..."
$vpcEndpoints = @()
if ($vpcs.Count -gt 0) {
    try {
        $vpcIdFilter = $vpcs -join ','
        $endpointOutput = aws ec2 describe-vpc-endpoints --region $Region --filters "Name=vpc-id,Values=$vpcIdFilter" --query 'VpcEndpoints[].VpcEndpointId' --output text 2>&1
        if ($endpointOutput -and $endpointOutput -ne "None" -and -not $endpointOutput.ToString().Contains("Error")) {
            $vpcEndpoints = $endpointOutput -split '\s+'
            Write-Host "  ✓ Found $($vpcEndpoints.Count) VPC endpoint(s)"
            $resourceCount += $vpcEndpoints.Count
            $resourcesList += "  - $($vpcEndpoints.Count) VPC Endpoints"
        }
    } catch { }
}

Write-Info "[15/15] Checking Security Groups..."
if ($vpcs.Count -gt 0) {
    try {
        $vpcIdFilter = $vpcs -join ','
        $sgOutput = aws ec2 describe-security-groups --region $Region --filters "Name=vpc-id,Values=$vpcIdFilter" "Name=group-name,Values=*ca-a2a*" --query 'SecurityGroups[].GroupId' --output text 2>&1
        if ($sgOutput -and $sgOutput -ne "None" -and -not $sgOutput.ToString().Contains("Error")) {
            $securityGroups = $sgOutput -split '\s+'
            Write-Host "  ✓ Found $($securityGroups.Count) security group(s)"
            $resourceCount += $securityGroups.Count
            $resourcesList += "  - $($securityGroups.Count) Security Groups"
        }
    } catch { }
}

Write-Host ""
Write-Header "=== AUDIT SUMMARY ==="
Write-Host "Total resource groups found: $resourceCount"
Write-Host ""

if ($resourceCount -eq 0) {
    Write-Info "No CA-A2A resources found in eu-west-3. Nothing to delete."
    exit 0
}

Write-Host ""
Write-Host "⚠️  WARNING: The following resources will be PERMANENTLY DELETED:" -ForegroundColor Red
foreach ($res in $resourcesList) {
    Write-Host $res
}
Write-Host ""
Write-Host "This operation is IRREVERSIBLE and will delete:" -ForegroundColor Red
Write-Host "  - All running services and containers"
Write-Host "  - All databases and their data"
Write-Host "  - All documents in S3 buckets"
Write-Host "  - All Docker images in ECR"
Write-Host "  - All networking infrastructure"
Write-Host "  - All logs and secrets"
Write-Host ""
Write-Host "Type 'DELETE-EU-WEST-3' to confirm deletion, or Ctrl+C to cancel:" -ForegroundColor Yellow
$confirmation = Read-Host

if ($confirmation -ne "DELETE-EU-WEST-3") {
    Write-Error "Deletion cancelled by user."
    exit 1
}

###############################################################################
# PHASE 2: DELETION
###############################################################################

Write-Host ""
Write-Header "=== PHASE 2: DELETING RESOURCES ==="
Write-Host ""

# Step 1: Delete ECS Services
if ($ecsServices.Count -gt 0) {
    Write-Info "[Step 1/16] Scaling down and deleting ECS Services..."
    foreach ($service in $ecsServices) {
        $serviceName = $service.Split('/')[-1]
        Write-Host "  Scaling down $serviceName to 0..."
        aws ecs update-service --cluster "$ProjectName-cluster" --service $serviceName --desired-count 0 --region $Region 2>&1 | Out-Null
    }
    
    Write-Host "  Waiting 45 seconds for tasks to drain..."
    Start-Sleep -Seconds 45
    
    foreach ($service in $ecsServices) {
        $serviceName = $service.Split('/')[-1]
        Write-Host "  Deleting service $serviceName..."
        aws ecs delete-service --cluster "$ProjectName-cluster" --service $serviceName --force --region $Region 2>&1 | Out-Null
    }
    Write-Info "  ✓ All ECS services deleted"
    Start-Sleep -Seconds 20
}

# Step 2: Delete ECS Cluster
if ($ecsCluster -and $ecsCluster -ne "None") {
    Write-Info "[Step 2/16] Deleting ECS Cluster..."
    aws ecs delete-cluster --cluster "$ProjectName-cluster" --region $Region 2>&1 | Out-Null
    Write-Info "  ✓ ECS cluster deleted"
}

# Step 3: Delete Load Balancers
if ($albs.Count -gt 0) {
    Write-Info "[Step 3/16] Deleting Load Balancers..."
    foreach ($alb in $albs) {
        $albName = aws elbv2 describe-load-balancers --load-balancer-arns $alb --region $Region --query 'LoadBalancers[0].LoadBalancerName' --output text 2>&1
        Write-Host "  Deleting ALB: $albName..."
        aws elbv2 delete-load-balancer --load-balancer-arn $alb --region $Region 2>&1 | Out-Null
    }
    Write-Info "  Waiting 75 seconds for ALBs to be deleted..."
    Start-Sleep -Seconds 75
    Write-Info "  ✓ Load balancers deleted"
}

# Step 4: Delete Target Groups
if ($tgs.Count -gt 0) {
    Write-Info "[Step 4/16] Deleting Target Groups..."
    foreach ($tg in $tgs) {
        aws elbv2 delete-target-group --target-group-arn $tg --region $Region 2>&1 | Out-Null
    }
    Write-Info "  ✓ Target groups deleted"
}

# Step 5: Delete SQS Queues
if ($sqsQueues.Count -gt 0) {
    Write-Info "[Step 5/16] Deleting SQS Queues..."
    foreach ($queueUrl in $sqsQueues) {
        Write-Host "  Deleting queue: $queueUrl..."
        aws sqs delete-queue --queue-url $queueUrl --region $Region 2>&1 | Out-Null
    }
    Write-Info "  ✓ SQS queues deleted"
}

# Step 6: Delete RDS Clusters
if ($rdsClusters.Count -gt 0) {
    Write-Info "[Step 6/16] Deleting RDS Clusters (this may take several minutes)..."
    foreach ($cluster in $rdsClusters) {
        Write-Host "  Processing cluster: $cluster..."
        
        # Delete instances first
        $instancesOutput = aws rds describe-db-clusters --region $Region --db-cluster-identifier $cluster --query 'DBClusters[0].DBClusterMembers[].DBInstanceIdentifier' --output text 2>&1
        if ($instancesOutput -and $instancesOutput -ne "None") {
            $instances = $instancesOutput -split '\s+'
            foreach ($instance in $instances) {
                Write-Host "    Deleting instance: $instance..."
                aws rds delete-db-instance --db-instance-identifier $instance --skip-final-snapshot --region $Region 2>&1 | Out-Null
            }
        }
        Start-Sleep -Seconds 15
        
        # Delete cluster
        Write-Host "  Deleting cluster: $cluster..."
        aws rds delete-db-cluster --db-cluster-identifier $cluster --skip-final-snapshot --region $Region 2>&1 | Out-Null
    }
    Write-Info "  ✓ RDS clusters deletion initiated"
}

# Step 7: Empty and Delete S3 Buckets
if ($s3Buckets.Count -gt 0) {
    Write-Info "[Step 7/16] Emptying and deleting S3 Buckets..."
    foreach ($bucket in $s3Buckets) {
        Write-Host "  Emptying bucket: $bucket..."
        aws s3 rm "s3://$bucket" --recursive --region $Region 2>&1 | Out-Null
        Write-Host "  Deleting bucket: $bucket..."
        aws s3 rb "s3://$bucket" --region $Region 2>&1 | Out-Null
    }
    Write-Info "  ✓ S3 buckets deleted"
}

# Step 8: Delete ECR Repositories
if ($ecrRepos.Count -gt 0) {
    Write-Info "[Step 8/16] Deleting ECR Repositories..."
    foreach ($repo in $ecrRepos) {
        Write-Host "  Deleting repository: $repo..."
        aws ecr delete-repository --repository-name $repo --force --region $Region 2>&1 | Out-Null
    }
    Write-Info "  ✓ ECR repositories deleted"
}

# Step 9: Delete CloudWatch Log Groups
if ($logGroups.Count -gt 0) {
    Write-Info "[Step 9/16] Deleting CloudWatch Log Groups..."
    foreach ($logGroup in $logGroups) {
        aws logs delete-log-group --log-group-name $logGroup --region $Region 2>&1 | Out-Null
    }
    Write-Info "  ✓ Log groups deleted"
}

# Step 10: Delete Secrets
if ($secrets.Count -gt 0) {
    Write-Info "[Step 10/16] Deleting Secrets..."
    foreach ($secret in $secrets) {
        Write-Host "  Deleting secret: $secret..."
        aws secretsmanager delete-secret --secret-id $secret --force-delete-without-recovery --region $Region 2>&1 | Out-Null
    }
    Write-Info "  ✓ Secrets deleted"
}

# Step 11: Wait for RDS deletion
Write-Info "[Step 11/16] Waiting for RDS resources to finish deleting (150s)..."
Start-Sleep -Seconds 150
Write-Info "  ✓ RDS resources should be deleted or deleting"

# Step 12: Delete Service Discovery
if ($namespaces.Count -gt 0) {
    Write-Info "[Step 12/16] Deleting Service Discovery..."
    foreach ($namespaceId in $namespaces) {
        Write-Host "  Processing namespace: $namespaceId..."
        $servicesOutput = aws servicediscovery list-services --filters "Name=NAMESPACE_ID,Values=$namespaceId" --query 'Services[].Id' --output text --region $Region 2>&1
        if ($servicesOutput -and $servicesOutput -ne "None") {
            $services = $servicesOutput -split '\s+'
            foreach ($svc in $services) {
                Write-Host "    Deleting service: $svc..."
                aws servicediscovery delete-service --id $svc --region $Region 2>&1 | Out-Null
            }
        }
        Start-Sleep -Seconds 15
        Write-Host "  Deleting namespace: $namespaceId..."
        aws servicediscovery delete-namespace --id $namespaceId --region $Region 2>&1 | Out-Null
    }
    Write-Info "  ✓ Service discovery deleted"
}

# Step 13: Delete VPC Endpoints
if ($vpcEndpoints.Count -gt 0) {
    Write-Info "[Step 13/16] Deleting VPC Endpoints..."
    foreach ($endpoint in $vpcEndpoints) {
        Write-Host "  Deleting VPC endpoint: $endpoint..."
        aws ec2 delete-vpc-endpoints --vpc-endpoint-ids $endpoint --region $Region 2>&1 | Out-Null
    }
    Write-Info "  Waiting 30 seconds for endpoints to be deleted..."
    Start-Sleep -Seconds 30
    Write-Info "  ✓ VPC endpoints deleted"
}

# Step 14: Delete VPC Resources
if ($vpcs.Count -gt 0) {
    Write-Info "[Step 14/16] Deleting VPC Resources..."
    foreach ($vpcId in $vpcs) {
        Write-Host "  Processing VPC: $vpcId..."
        
        # Delete NAT Gateways
        $natGwOutput = aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$vpcId" "Name=state,Values=available" --query 'NatGateways[].NatGatewayId' --output text --region $Region 2>&1
        if ($natGwOutput -and $natGwOutput -ne "None") {
            $natGws = $natGwOutput -split '\s+'
            foreach ($natGw in $natGws) {
                Write-Host "    Deleting NAT Gateway: $natGw..."
                $eipOutput = aws ec2 describe-nat-gateways --nat-gateway-ids $natGw --query 'NatGateways[0].NatGatewayAddresses[0].AllocationId' --output text --region $Region 2>&1
                aws ec2 delete-nat-gateway --nat-gateway-id $natGw --region $Region 2>&1 | Out-Null
                if ($eipOutput -and $eipOutput -ne "None") {
                    Start-Sleep -Seconds 45
                    Write-Host "    Releasing EIP: $eipOutput..."
                    aws ec2 release-address --allocation-id $eipOutput --region $Region 2>&1 | Out-Null
                }
            }
        }
        
        # Delete Security Groups (except default)
        $sgOutput = aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpcId" --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text --region $Region 2>&1
        if ($sgOutput -and $sgOutput -ne "None") {
            Write-Host "    Deleting security groups..."
            $sgs = $sgOutput -split '\s+'
            foreach ($sg in $sgs) {
                aws ec2 delete-security-group --group-id $sg --region $Region 2>&1 | Out-Null
            }
        }
        
        # Delete Subnets
        $subnetOutput = aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpcId" --query 'Subnets[].SubnetId' --output text --region $Region 2>&1
        if ($subnetOutput -and $subnetOutput -ne "None") {
            Write-Host "    Deleting subnets..."
            $subnets = $subnetOutput -split '\s+'
            foreach ($subnet in $subnets) {
                aws ec2 delete-subnet --subnet-id $subnet --region $Region 2>&1 | Out-Null
            }
        }
        
        # Delete Route Tables (except main)
        $rtOutput = aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$vpcId" --query 'RouteTables[?Associations[0].Main!=`true`].RouteTableId' --output text --region $Region 2>&1
        if ($rtOutput -and $rtOutput -ne "None") {
            Write-Host "    Deleting route tables..."
            $rts = $rtOutput -split '\s+'
            foreach ($rt in $rts) {
                aws ec2 delete-route-table --route-table-id $rt --region $Region 2>&1 | Out-Null
            }
        }
        
        # Detach and Delete Internet Gateway
        $igwOutput = aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$vpcId" --query 'InternetGateways[].InternetGatewayId' --output text --region $Region 2>&1
        if ($igwOutput -and $igwOutput -ne "None") {
            $igws = $igwOutput -split '\s+'
            foreach ($igw in $igws) {
                Write-Host "    Detaching and deleting Internet Gateway: $igw..."
                aws ec2 detach-internet-gateway --internet-gateway-id $igw --vpc-id $vpcId --region $Region 2>&1 | Out-Null
                aws ec2 delete-internet-gateway --internet-gateway-id $igw --region $Region 2>&1 | Out-Null
            }
        }
        
        # Delete VPC
        Write-Host "  Deleting VPC: $vpcId..."
        aws ec2 delete-vpc --vpc-id $vpcId --region $Region 2>&1 | Out-Null
    }
    Write-Info "  ✓ VPC resources deleted"
}

# Step 15: Delete IAM Roles
if ($iamRoles.Count -gt 0) {
    Write-Info "[Step 15/16] Deleting IAM Roles..."
    foreach ($roleName in $iamRoles) {
        Write-Host "  Processing role: $roleName..."
        
        # Detach managed policies
        $policiesOutput = aws iam list-attached-role-policies --role-name $roleName --query 'AttachedPolicies[].PolicyArn' --output text 2>&1
        if ($policiesOutput -and $policiesOutput -ne "None") {
            $policies = $policiesOutput -split '\s+'
            foreach ($policy in $policies) {
                aws iam detach-role-policy --role-name $roleName --policy-arn $policy 2>&1 | Out-Null
            }
        }
        
        # Delete inline policies
        $inlinePoliciesOutput = aws iam list-role-policies --role-name $roleName --query 'PolicyNames' --output text 2>&1
        if ($inlinePoliciesOutput -and $inlinePoliciesOutput -ne "None") {
            $inlinePolicies = $inlinePoliciesOutput -split '\s+'
            foreach ($policy in $inlinePolicies) {
                aws iam delete-role-policy --role-name $roleName --policy-name $policy 2>&1 | Out-Null
            }
        }
        
        # Delete role
        aws iam delete-role --role-name $roleName 2>&1 | Out-Null
    }
    Write-Info "  ✓ IAM roles deleted"
}

# Step 16: Final verification
Write-Info "[Step 16/16] Final Verification..."
Start-Sleep -Seconds 10

$remainingClusters = aws ecs describe-clusters --clusters "$ProjectName-cluster" --region $Region --query 'clusters[0].status' --output text 2>&1
$remainingRds = aws rds describe-db-clusters --region $Region --query 'DBClusters[?contains(DBClusterIdentifier, `ca-a2a`)].Status' --output text 2>&1

if (-not $remainingClusters -or $remainingClusters -eq "INACTIVE" -or $remainingClusters -eq "None") {
    Write-Info "  ✓ ECS resources cleaned up"
} else {
    Write-Warn "  ⚠️  ECS cluster status: $remainingClusters"
}

if (-not $remainingRds -or $remainingRds -eq "None") {
    Write-Info "  ✓ RDS resources cleaned up"
} else {
    Write-Warn "  ⚠️  Some RDS clusters may still be deleting: $remainingRds"
}

Write-Host ""
Write-Header "==================================================================="
Write-Header "✅ DELETION COMPLETE"
Write-Header "==================================================================="
Write-Host ""
Write-Info "All CA-A2A resources in eu-west-3 have been deleted or are being deleted."
Write-Info "Some resources like RDS clusters may take additional time to fully delete."
Write-Host ""
Write-Info "You can verify deletion with:"
Write-Host "  aws ecs describe-clusters --clusters ca-a2a-cluster --region eu-west-3"
Write-Host "  aws rds describe-db-clusters --region eu-west-3"
Write-Host "  aws s3 ls | grep ca-a2a"
Write-Host ""
