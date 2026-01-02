# Deploy MCP Server to AWS ECS
# This script builds, pushes, and deploys the MCP server to ECS

param(
    [string]$Profile = "AWSAdministratorAccess-555043101106",
    [string]$Region = "eu-west-3",
    [switch]$SkipBuild,
    [switch]$SkipPush
)

$ErrorActionPreference = "Stop"

# Configuration
$ACCOUNT_ID = "555043101106"
$CLUSTER_NAME = "ca-a2a-cluster"
$SERVICE_NAME = "mcp-server"
$TASK_FAMILY = "ca-a2a-mcp-server"
$ECR_REPO = "ca-a2a-mcp-server"
$IMAGE_TAG = "latest"

# Set AWS profile
$env:AWS_PROFILE = $Profile
$env:AWS_DEFAULT_REGION = $Region

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  MCP SERVER DEPLOYMENT TO AWS ECS" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Account: $ACCOUNT_ID"
Write-Host "  Region: $Region"
Write-Host "  Cluster: $CLUSTER_NAME"
Write-Host "  Service: $SERVICE_NAME"
Write-Host "  ECR Repo: $ECR_REPO"
Write-Host ""

# Step 1: Create ECR repository if it doesn't exist
Write-Host "[1/8] Checking ECR repository..." -ForegroundColor Yellow
$repoExists = aws ecr describe-repositories --repository-names $ECR_REPO 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Creating ECR repository: $ECR_REPO" -ForegroundColor Cyan
    aws ecr create-repository `
        --repository-name $ECR_REPO `
        --image-scanning-configuration scanOnPush=true `
        --encryption-configuration encryptionType=AES256
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] ECR repository created" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Failed to create ECR repository" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  [OK] ECR repository exists" -ForegroundColor Green
}

# Step 2: Login to ECR
Write-Host "`n[2/8] Logging in to ECR..." -ForegroundColor Yellow
$loginCmd = aws ecr get-login-password | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$Region.amazonaws.com"
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Logged in to ECR" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] Failed to login to ECR" -ForegroundColor Red
    exit 1
}

# Step 3: Build Docker image
if (-not $SkipBuild) {
    Write-Host "`n[3/8] Building Docker image..." -ForegroundColor Yellow
    docker build -f Dockerfile.mcp -t ${ECR_REPO}:${IMAGE_TAG} .
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Docker image built" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Failed to build Docker image" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "`n[3/8] Skipping Docker build" -ForegroundColor Gray
}

# Step 4: Tag image
Write-Host "`n[4/8] Tagging Docker image..." -ForegroundColor Yellow
$ecrImageName = "${ACCOUNT_ID}.dkr.ecr.${Region}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}"
docker tag "${ECR_REPO}:${IMAGE_TAG}" $ecrImageName
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Image tagged" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] Failed to tag image" -ForegroundColor Red
    Write-Host "  Source: ${ECR_REPO}:${IMAGE_TAG}" -ForegroundColor Gray
    Write-Host "  Target: $ecrImageName" -ForegroundColor Gray
    exit 1
}

# Step 5: Push to ECR
if (-not $SkipPush) {
    Write-Host "`n[5/8] Pushing image to ECR..." -ForegroundColor Yellow
    $ecrImageName = "${ACCOUNT_ID}.dkr.ecr.${Region}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}"
    docker push $ecrImageName
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Image pushed to ECR" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Failed to push image" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "`n[5/8] Skipping image push" -ForegroundColor Gray
}

# Step 6: Get VPC and network configuration from existing services
Write-Host "`n[6/8] Getting network configuration..." -ForegroundColor Yellow
$orchService = aws ecs describe-services --cluster $CLUSTER_NAME --services orchestrator | ConvertFrom-Json
if ($orchService.services.Count -gt 0) {
    $networkConfig = $orchService.services[0].networkConfiguration.awsvpcConfiguration
    $subnets = $networkConfig.subnets -join ","
    $securityGroupId = $networkConfig.securityGroups[0]
    
    Write-Host "  Subnets: $subnets" -ForegroundColor Cyan
    Write-Host "  Security Group: $securityGroupId" -ForegroundColor Cyan
    Write-Host "  [OK] Network configuration retrieved" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] No orchestrator service found" -ForegroundColor Red
    exit 1
}

# Step 7: Register ECS task definition
Write-Host "`n[7/8] Registering ECS task definition..." -ForegroundColor Yellow

# Get DB password from Secrets Manager
$dbSecretArn = "arn:aws:secretsmanager:${Region}:${ACCOUNT_ID}:secret:ca-a2a/db-password"

$taskDefJson = @"
{
  "family": "$TASK_FAMILY",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::${ACCOUNT_ID}:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "mcp-server",
      "image": "${ACCOUNT_ID}.dkr.ecr.${Region}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "POSTGRES_HOST", "value": "ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com"},
        {"name": "POSTGRES_PORT", "value": "5432"},
        {"name": "POSTGRES_DB", "value": "documents_db"},
        {"name": "POSTGRES_USER", "value": "postgres"},
        {"name": "AWS_REGION", "value": "$Region"},
        {"name": "S3_BUCKET", "value": "ca-a2a-documents"}
      ],
      "secrets": [
        {
          "name": "POSTGRES_PASSWORD",
          "valueFrom": "$dbSecretArn"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/ca-a2a-mcp-server",
          "awslogs-region": "$Region",
          "awslogs-stream-prefix": "mcp-server"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8000/health')\" || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
"@

# Create CloudWatch log group (ignore error if already exists)
$ErrorActionPreference = "SilentlyContinue"
aws logs create-log-group --log-group-name "/ecs/ca-a2a-mcp-server" 2>&1 | Out-Null
$ErrorActionPreference = "Stop"

# Register task definition
$taskDefJson | Out-File -FilePath "mcp-taskdef.json" -Encoding ASCII
$taskDef = aws ecs register-task-definition --cli-input-json file://mcp-taskdef.json | ConvertFrom-Json

if ($LASTEXITCODE -eq 0) {
    $taskDefArn = $taskDef.taskDefinition.taskDefinitionArn
    Write-Host "  [OK] Task definition registered: $taskDefArn" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] Failed to register task definition" -ForegroundColor Red
    exit 1
}

# Clean up temp file
Remove-Item "mcp-taskdef.json" -ErrorAction SilentlyContinue

# Step 8: Create or update ECS service
Write-Host "`n[8/8] Creating/updating ECS service..." -ForegroundColor Yellow

# Check if service exists
$serviceExists = aws ecs describe-services --cluster $CLUSTER_NAME --services $SERVICE_NAME | ConvertFrom-Json
if ($serviceExists.services.Count -gt 0 -and $serviceExists.services[0].status -eq "ACTIVE") {
    Write-Host "  Updating existing service..." -ForegroundColor Cyan
    aws ecs update-service `
        --cluster $CLUSTER_NAME `
        --service $SERVICE_NAME `
        --task-definition $taskDefArn `
        --force-new-deployment
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Service updated" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Failed to update service" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  Creating new service..." -ForegroundColor Cyan
    
    # Format subnets for JSON array
    $subnetsArray = ($subnets -split ",") | ForEach-Object { "`"$_`"" }
    $subnetsJson = $subnetsArray -join ","
    
    $serviceJson = @"
{
  "cluster": "$CLUSTER_NAME",
  "serviceName": "$SERVICE_NAME",
  "taskDefinition": "$taskDefArn",
  "desiredCount": 1,
  "launchType": "FARGATE",
  "networkConfiguration": {
    "awsvpcConfiguration": {
      "subnets": [$subnetsJson],
      "securityGroups": ["$securityGroupId"],
      "assignPublicIp": "DISABLED"
    }
  },
  "healthCheckGracePeriodSeconds": 60
}
"@
    
    $serviceJson | Out-File -FilePath "mcp-service.json" -Encoding ASCII
    aws ecs create-service --cli-input-json file://mcp-service.json
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Service created" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Failed to create service" -ForegroundColor Red
        exit 1
    }
    
    Remove-Item "mcp-service.json" -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  MCP SERVER DEPLOYMENT COMPLETE" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Service Details:" -ForegroundColor Yellow
Write-Host "  Cluster: $CLUSTER_NAME"
Write-Host "  Service: $SERVICE_NAME"
Write-Host "  Task Definition: $taskDefArn"
Write-Host "  Image: ${ACCOUNT_ID}.dkr.ecr.${Region}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}"
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Update agent services with MCP_SERVER_URL environment variable"
Write-Host "  2. Restart agent services to connect to MCP server"
Write-Host "  3. Monitor logs: aws logs tail /ecs/ca-a2a-mcp-server --follow"
Write-Host ""

