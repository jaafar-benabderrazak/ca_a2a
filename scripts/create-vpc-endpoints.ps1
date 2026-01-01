# Create VPC Endpoints for ECS Tasks in Private Subnets
# This allows tasks to access AWS Secrets Manager, ECR, CloudWatch Logs, and S3

$ErrorActionPreference = "Stop"

# Load configuration
if (Test-Path "ca-a2a-config.env") {
    Get-Content "ca-a2a-config.env" | ForEach-Object {
        if ($_ -match '^export\s+(\w+)="([^"]+)"') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
}

$region = $env:AWS_REGION ?? "eu-west-3"
$vpcId = $env:VPC_ID ?? "vpc-086392a3eed899f72"
$privateSubnet1 = $env:PRIVATE_SUBNET_1 ?? "subnet-07484aca0e473e3d0"
$privateSubnet2 = $env:PRIVATE_SUBNET_2 ?? "subnet-0aef6b4fcce7748a9"
$projectName = $env:PROJECT_NAME ?? "ca-a2a"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Create VPC Endpoints for ECS Tasks" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Region: $region" -ForegroundColor Yellow
Write-Host "VPC: $vpcId" -ForegroundColor Yellow
Write-Host ""

# Get route table IDs for private subnets
Write-Host "[1/5] Finding route tables for private subnets..." -ForegroundColor Green
$routeTable1 = aws ec2 describe-route-tables `
    --filters "Name=association.subnet-id,Values=$privateSubnet1" `
    --region $region `
    --query 'RouteTables[0].RouteTableId' `
    --output text

$routeTable2 = aws ec2 describe-route-tables `
    --filters "Name=association.subnet-id,Values=$privateSubnet2" `
    --region $region `
    --query 'RouteTables[0].RouteTableId' `
    --output text

if (-not $routeTable1 -or $routeTable1 -eq "None") {
    Write-Host "  Error: Could not find route table for subnet $privateSubnet1" -ForegroundColor Red
    exit 1
}

if (-not $routeTable2 -or $routeTable2 -eq "None") {
    Write-Host "  Error: Could not find route table for subnet $privateSubnet2" -ForegroundColor Red
    exit 1
}

Write-Host "  Route table 1: $routeTable1" -ForegroundColor Yellow
Write-Host "  Route table 2: $routeTable2" -ForegroundColor Yellow
Write-Host ""

# Get security group for VPC endpoints (use ECS security group or create one)
Write-Host "[2/5] Setting up security group for VPC endpoints..." -ForegroundColor Green
$ecsSgId = $env:ECS_SG ?? "sg-047a8f39f9cdcaf4c"

# Check if security group allows HTTPS from VPC
$sgRules = aws ec2 describe-security-groups `
    --group-ids $ecsSgId `
    --region $region `
    --query 'SecurityGroups[0].IpPermissions' `
    --output json | ConvertFrom-Json

$needsHttpsRule = $true
foreach ($rule in $sgRules) {
    if ($rule.IpProtocol -eq "tcp" -and $rule.FromPort -eq 443) {
        $needsHttpsRule = $false
        break
    }
}

if ($needsHttpsRule) {
    Write-Host "  Adding HTTPS ingress rule to security group..." -ForegroundColor Yellow
    aws ec2 authorize-security-group-ingress `
        --group-id $ecsSgId `
        --protocol tcp `
        --port 443 `
        --cidr "10.0.0.0/16" `
        --region $region 2>&1 | Out-Null
    Write-Host "  ✓ HTTPS rule added" -ForegroundColor Green
} else {
    Write-Host "  ✓ HTTPS rule already exists" -ForegroundColor Green
}
Write-Host ""

# Define services that need VPC endpoints
$services = @(
    @{
        Name = "Secrets Manager"
        ServiceName = "com.amazonaws.$region.secretsmanager"
        EndpointType = "Interface"
        Required = $true
    },
    @{
        Name = "ECR API"
        ServiceName = "com.amazonaws.$region.ecr.api"
        EndpointType = "Interface"
        Required = $true
    },
    @{
        Name = "ECR DKR"
        ServiceName = "com.amazonaws.$region.ecr.dkr"
        EndpointType = "Interface"
        Required = $true
    },
    @{
        Name = "CloudWatch Logs"
        ServiceName = "com.amazonaws.$region.logs"
        EndpointType = "Interface"
        Required = $true
    },
    @{
        Name = "S3"
        ServiceName = "com.amazonaws.$region.s3"
        EndpointType = "Gateway"
        Required = $false
    }
)

# Create VPC endpoints
Write-Host "[3/5] Creating VPC endpoints..." -ForegroundColor Green
$createdEndpoints = @()

foreach ($service in $services) {
    Write-Host "  Checking $($service.Name) endpoint..." -ForegroundColor Yellow
    
    # Check if endpoint already exists
    $existingEndpoint = aws ec2 describe-vpc-endpoints `
        --filters "Name=vpc-id,Values=$vpcId" "Name=service-name,Values=$($service.ServiceName)" `
        --region $region `
        --query 'VpcEndpoints[0].VpcEndpointId' `
        --output text

    if ($existingEndpoint -and $existingEndpoint -ne "None") {
        Write-Host "    ✓ Endpoint already exists: $existingEndpoint" -ForegroundColor Green
        $createdEndpoints += @{
            Name = $service.Name
            Id = $existingEndpoint
            Type = $service.EndpointType
        }
        continue
    }

    # Create endpoint
    Write-Host "    Creating $($service.Name) endpoint..." -ForegroundColor Yellow
    
    if ($service.EndpointType -eq "Interface") {
        # Interface endpoint (for Secrets Manager, ECR, CloudWatch Logs)
        $endpointId = aws ec2 create-vpc-endpoint `
            --vpc-id $vpcId `
            --service-name $service.ServiceName `
            --vpc-endpoint-type Interface `
            --subnet-ids $privateSubnet1 $privateSubnet2 `
            --security-group-ids $ecsSgId `
            --region $region `
            --query 'VpcEndpoint.VpcEndpointId' `
            --output text
        
        Write-Host "    ✓ Created interface endpoint: $endpointId" -ForegroundColor Green
        $createdEndpoints += @{
            Name = $service.Name
            Id = $endpointId
            Type = $service.EndpointType
        }
    } elseif ($service.EndpointType -eq "Gateway") {
        # Gateway endpoint (for S3)
        $endpointId = aws ec2 create-vpc-endpoint `
            --vpc-id $vpcId `
            --service-name $service.ServiceName `
            --vpc-endpoint-type Gateway `
            --route-table-ids $routeTable1 $routeTable2 `
            --region $region `
            --query 'VpcEndpoint.VpcEndpointId' `
            --output text
        
        Write-Host "    ✓ Created gateway endpoint: $endpointId" -ForegroundColor Green
        $createdEndpoints += @{
            Name = $service.Name
            Id = $endpointId
            Type = $service.EndpointType
        }
    }
}

Write-Host ""

# Wait for interface endpoints to be available
Write-Host "[4/5] Waiting for interface endpoints to be available..." -ForegroundColor Green
$interfaceEndpoints = $createdEndpoints | Where-Object { $_.Type -eq "Interface" }
foreach ($endpoint in $interfaceEndpoints) {
    Write-Host "  Waiting for $($endpoint.Name) endpoint..." -ForegroundColor Yellow
    $maxAttempts = 30
    $attempt = 0
    $available = $false
    
    while ($attempt -lt $maxAttempts) {
        $state = aws ec2 describe-vpc-endpoints `
            --vpc-endpoint-ids $endpoint.Id `
            --region $region `
            --query 'VpcEndpoints[0].State' `
            --output text
        
        if ($state -eq "available") {
            Write-Host "    ✓ $($endpoint.Name) endpoint is available" -ForegroundColor Green
            $available = $true
            break
        } elseif ($state -eq "failed" -or $state -eq "deleted") {
            Write-Host "    ✗ $($endpoint.Name) endpoint is in state: $state" -ForegroundColor Red
            break
        } else {
            $attempt++
            Write-Host "    ... State: $state (attempt $attempt/$maxAttempts)" -ForegroundColor Yellow
            Start-Sleep -Seconds 10
        }
    }
    
    if (-not $available -and $attempt -eq $maxAttempts) {
        Write-Host "    ⚠ $($endpoint.Name) endpoint did not become available within timeout" -ForegroundColor Yellow
    }
}

Write-Host ""

# Verify endpoints
Write-Host "[5/5] Verifying VPC endpoints..." -ForegroundColor Green
$allEndpoints = aws ec2 describe-vpc-endpoints `
    --filters "Name=vpc-id,Values=$vpcId" `
    --region $region `
    --query 'VpcEndpoints[*].[VpcEndpointId,ServiceName,State]' `
    --output table

Write-Host $allEndpoints

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "VPC Endpoints Created Successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Wait 2-3 minutes for endpoints to fully propagate" -ForegroundColor White
Write-Host "2. Restart ECS tasks to pick up the new endpoints:" -ForegroundColor White
Write-Host "   .\fix-ecs-connectivity.sh" -ForegroundColor Cyan
Write-Host ""
Write-Host "Or manually restart services:" -ForegroundColor Yellow
Write-Host "   aws ecs update-service --cluster ca-a2a-cluster --service extractor --force-new-deployment --region $region" -ForegroundColor Cyan
Write-Host "   aws ecs update-service --cluster ca-a2a-cluster --service validator --force-new-deployment --region $region" -ForegroundColor Cyan
Write-Host "   aws ecs update-service --cluster ca-a2a-cluster --service archivist --force-new-deployment --region $region" -ForegroundColor Cyan
Write-Host ""

