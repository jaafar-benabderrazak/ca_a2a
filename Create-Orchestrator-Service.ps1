# Create Orchestrator ECS Service
# This script creates the orchestrator service and exposes it via the ALB

$env:AWS_PROFILE = "reply-sso"
$AWS_REGION = "eu-west-3"
$CLUSTER = "ca-a2a-cluster"
$PROJECT_NAME = "ca-a2a"

# From ca-a2a-config.env
$PRIVATE_SUBNET_1 = "subnet-07484aca0e473e3d0"
$PRIVATE_SUBNET_2 = "subnet-0aef6b4fcce7748a9"
$ECS_SG = "sg-047a8f39f9cdcaf4c"
$TG_ARN = "arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Create Orchestrator ECS Service"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if task definition exists
Write-Host "[1/3] Checking task definition..." -ForegroundColor Yellow
$TASK_DEF = aws ecs describe-task-definition `
    --task-definition "${PROJECT_NAME}-orchestrator" `
    --region $AWS_REGION `
    --query 'taskDefinition.taskDefinitionArn' `
    --output text 2>$null

if ($TASK_DEF) {
    Write-Host "  [OK] Task definition exists: $TASK_DEF" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] Task definition not found!" -ForegroundColor Red
    Write-Host "  You need to create it first. Check deployment scripts." -ForegroundColor Yellow
    exit 1
}

# Check if service already exists
Write-Host ""
Write-Host "[2/3] Checking if service exists..." -ForegroundColor Yellow
$EXISTING_SERVICE = aws ecs describe-services `
    --cluster $CLUSTER `
    --services orchestrator `
    --region $AWS_REGION `
    --query 'services[0].status' `
    --output text 2>$null

if ($EXISTING_SERVICE -eq "ACTIVE") {
    Write-Host "  [INFO] Service already exists" -ForegroundColor Yellow
    Write-Host "  Updating service with force new deployment..." -ForegroundColor Cyan
    
    aws ecs update-service `
        --cluster $CLUSTER `
        --service orchestrator `
        --force-new-deployment `
        --region $AWS_REGION `
        --output json | Out-Null
    
    Write-Host "  [OK] Service updated" -ForegroundColor Green
} else {
    Write-Host "  Creating new service..." -ForegroundColor Cyan
    
    aws ecs create-service `
        --cluster $CLUSTER `
        --service-name orchestrator `
        --task-definition "${PROJECT_NAME}-orchestrator" `
        --desired-count 2 `
        --launch-type FARGATE `
        --platform-version LATEST `
        --network-configuration "awsvpcConfiguration={subnets=[$PRIVATE_SUBNET_1,$PRIVATE_SUBNET_2],securityGroups=[$ECS_SG],assignPublicIp=DISABLED}" `
        --load-balancers "targetGroupArn=$TG_ARN,containerName=orchestrator,containerPort=8001" `
        --health-check-grace-period-seconds 60 `
        --enable-execute-command `
        --region $AWS_REGION `
        --output json | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Service created successfully" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Failed to create service" -ForegroundColor Red
        exit 1
    }
}

# Wait for service to stabilize
Write-Host ""
Write-Host "[3/3] Waiting for service to start..." -ForegroundColor Yellow
Write-Host "  This may take 60-90 seconds..." -ForegroundColor Cyan
Start-Sleep -Seconds 90

# Check final status
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Service Status"
Write-Host "==========================================" -ForegroundColor Cyan
aws ecs describe-services `
    --cluster $CLUSTER `
    --services orchestrator `
    --region $AWS_REGION `
    --query 'services[0].{Name:serviceName,Status:status,Running:runningCount,Desired:desiredCount}' `
    --output table

Write-Host ""
Write-Host "Latest Events:" -ForegroundColor Yellow
aws ecs describe-services `
    --cluster $CLUSTER `
    --services orchestrator `
    --region $AWS_REGION `
    --query 'services[0].events[0:3].[createdAt,message]' `
    --output table

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "ALB Endpoint:" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test with:" -ForegroundColor Yellow
Write-Host 'curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health' -ForegroundColor White
Write-Host 'curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/card' -ForegroundColor White
Write-Host ""

