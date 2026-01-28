# Deploy CA-A2A to US-EAST-1 with Security Features Enabled
# Builds images, pushes to ECR, registers task definitions, creates ECS services

$ErrorActionPreference = "Continue"

# Configuration
$AWS_REGION = "us-east-1"
$AWS_ACCOUNT_ID = "555043101106"
$PROJECT_NAME = "ca-a2a"
$CLUSTER = "${PROJECT_NAME}-cluster"

# From CDK outputs
$S3_BUCKET = "ca-a2a-prod-documentsbucket9ec9deb9-uopiyxhvtpk0"
$DB_ENDPOINT = "ca-a2a-documents-db.cluster-crruu3dmzphw.us-east-1.rds.amazonaws.com"
$DB_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:555043101106:secret:DbPassword10268EB9-PPoTWCj0mqqC-3JuJbz"
$TASK_EXEC_ROLE = "arn:aws:iam::555043101106:role/ca-a2a-ecs-task-execution-role"
$TASK_ROLE = "arn:aws:iam::555043101106:role/ca-a2a-ecs-task-role"
$SG_ID = "sg-0b5abac328631d4f8"
$ALB_DNS = "ca-a2a-alb-51413545.us-east-1.elb.amazonaws.com"

# Get VPC private subnets
Write-Host "Getting VPC subnet information..." -ForegroundColor Cyan
$SUBNETS = aws ec2 describe-subnets `
    --region $AWS_REGION `
    --filters "Name=tag:Name,Values=*Private*" "Name=vpc-id,Values=vpc-0785992ea934823b2" `
    --query "Subnets[*].SubnetId" --output text

if (-not $SUBNETS) {
    Write-Host "No private subnets found, using any available..." -ForegroundColor Yellow
    $SUBNETS = aws ec2 describe-subnets `
        --region $AWS_REGION `
        --filters "Name=vpc-id,Values=vpc-0785992ea934823b2" `
        --query "Subnets[0:2].SubnetId" --output text
}

$SUBNET_LIST = ($SUBNETS -replace "`t", ",").Trim()
Write-Host "Using subnets: $SUBNET_LIST" -ForegroundColor Green

$AGENTS = @(
    @{name="orchestrator"; port=8001},
    @{name="extractor"; port=8002},
    @{name="validator"; port=8003},
    @{name="archivist"; port=8004}
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "CA-A2A US-EAST-1 Deployment with Security"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Region: $AWS_REGION" -ForegroundColor Yellow
Write-Host "S3 Bucket: $S3_BUCKET" -ForegroundColor Yellow
Write-Host "Database: $DB_ENDPOINT" -ForegroundColor Yellow
Write-Host "ALB: $ALB_DNS" -ForegroundColor Yellow
Write-Host ""
Write-Host "Security Features:" -ForegroundColor Green
Write-Host "  - A2A_REQUIRE_AUTH=true" -ForegroundColor White
Write-Host "  - API Key Authentication" -ForegroundColor White
Write-Host "  - RBAC Authorization" -ForegroundColor White
Write-Host "  - Rate Limiting" -ForegroundColor White
Write-Host "  - Replay Protection" -ForegroundColor White
Write-Host ""

# Step 1: Login to ECR
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Step 1/5: Login to ECR"
Write-Host "==========================================" -ForegroundColor Cyan
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
Write-Host ""

# Step 2: Build Docker images
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Step 2/5: Build Docker Images"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

foreach ($agent in $AGENTS) {
    $name = $agent.name
    Write-Host "Building ${name}..." -ForegroundColor Yellow
    $IMAGE_URI = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/${name}:latest"
    
    docker build -f "Dockerfile.${name}" -t $IMAGE_URI . 2>&1 | Out-Host
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Built ${name}" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Failed to build ${name}" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# Step 3: Push images to ECR
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Step 3/5: Push Images to ECR"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

foreach ($agent in $AGENTS) {
    $name = $agent.name
    Write-Host "Pushing ${name}..." -ForegroundColor Yellow
    $IMAGE_URI = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/${name}:latest"
    
    docker push $IMAGE_URI 2>&1 | Out-Host
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Pushed ${name}" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Failed to push ${name}" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# Step 4: Create CloudWatch log groups
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Step 4/5: Create Log Groups & Register Task Definitions"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

foreach ($agent in $AGENTS) {
    $name = $agent.name
    $port = $agent.port
    
    # Create log group
    Write-Host "Creating log group for ${name}..." -ForegroundColor Yellow
    aws logs create-log-group --log-group-name "/ecs/ca-a2a-${name}" --region $AWS_REGION 2>$null
    
    # Generate task definition with security enabled
    $taskDef = @{
        family = "ca-a2a-${name}"
        networkMode = "awsvpc"
        requiresCompatibilities = @("FARGATE")
        cpu = "512"
        memory = "1024"
        executionRoleArn = $TASK_EXEC_ROLE
        taskRoleArn = $TASK_ROLE
        containerDefinitions = @(@{
            name = $name
            image = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/${name}:latest"
            essential = $true
            portMappings = @(@{containerPort = $port; protocol = "tcp"})
            environment = @(
                @{name = "AGENT_HOST"; value = "0.0.0.0"}
                @{name = "AGENT_PORT"; value = "$port"}
                @{name = "POSTGRES_HOST"; value = $DB_ENDPOINT}
                @{name = "POSTGRES_DB"; value = "documents_db"}
                @{name = "POSTGRES_USER"; value = "postgres"}
                @{name = "POSTGRES_PORT"; value = "5432"}
                @{name = "S3_BUCKET_NAME"; value = $S3_BUCKET}
                @{name = "AWS_REGION"; value = $AWS_REGION}
                # Security features
                @{name = "A2A_REQUIRE_AUTH"; value = "true"}
                @{name = "A2A_RATE_LIMIT_ENABLED"; value = "true"}
                @{name = "A2A_RATE_LIMIT_MAX"; value = "100"}
                @{name = "A2A_RATE_LIMIT_WINDOW"; value = "60"}
                @{name = "A2A_REPLAY_PROTECTION"; value = "true"}
                @{name = "A2A_SCHEMA_VALIDATION"; value = "true"}
                @{name = "A2A_AUDIT_LOGGING"; value = "true"}
            )
            secrets = @(@{name = "POSTGRES_PASSWORD"; valueFrom = $DB_SECRET_ARN})
            logConfiguration = @{
                logDriver = "awslogs"
                options = @{
                    "awslogs-group" = "/ecs/ca-a2a-${name}"
                    "awslogs-region" = $AWS_REGION
                    "awslogs-stream-prefix" = "ecs"
                }
            }
            healthCheck = @{
                command = @("CMD-SHELL", "curl -f http://localhost:${port}/health || exit 1")
                interval = 30
                timeout = 5
                retries = 3
                startPeriod = 60
            }
        })
    }
    
    # Add orchestrator-specific env vars
    if ($name -eq "orchestrator") {
        $taskDef.containerDefinitions[0].environment += @(
            @{name = "EXTRACTOR_URL"; value = "http://extractor.local:8002"}
            @{name = "VALIDATOR_URL"; value = "http://validator.local:8003"}
            @{name = "ARCHIVIST_URL"; value = "http://archivist.local:8004"}
        )
    }
    
    # Write task definition to file
    $taskDefJson = $taskDef | ConvertTo-Json -Depth 10
    $taskDefFile = "task-def-${name}-temp.json"
    $taskDefJson | Out-File -FilePath $taskDefFile -Encoding utf8
    
    # Register task definition
    Write-Host "Registering task definition for ${name}..." -ForegroundColor Yellow
    aws ecs register-task-definition --cli-input-json "file://${taskDefFile}" --region $AWS_REGION | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Registered task definition for ${name}" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Failed to register task definition for ${name}" -ForegroundColor Red
    }
    
    # Clean up temp file
    Remove-Item $taskDefFile -ErrorAction SilentlyContinue
}
Write-Host ""

# Step 5: Create ECS services
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Step 5/5: Create ECS Services"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Get ALB target groups
Write-Host "Getting ALB target groups..." -ForegroundColor Yellow
$TG_ARN = aws elbv2 describe-target-groups `
    --region $AWS_REGION `
    --query "TargetGroups[?contains(TargetGroupName, 'orchestrator')].TargetGroupArn" `
    --output text 2>$null

if (-not $TG_ARN) {
    Write-Host "Creating target group for orchestrator..." -ForegroundColor Yellow
    $VPC_ID = "vpc-0785992ea934823b2"
    $TG_RESULT = aws elbv2 create-target-group `
        --name "ca-a2a-orchestrator-tg" `
        --protocol HTTP `
        --port 8001 `
        --vpc-id $VPC_ID `
        --target-type ip `
        --health-check-path "/health" `
        --health-check-interval-seconds 30 `
        --health-check-timeout-seconds 5 `
        --healthy-threshold-count 2 `
        --unhealthy-threshold-count 3 `
        --region $AWS_REGION `
        --output json | ConvertFrom-Json
    
    $TG_ARN = $TG_RESULT.TargetGroups[0].TargetGroupArn
    Write-Host "  Created target group: $TG_ARN" -ForegroundColor Green
    
    # Get listener ARN and add rule
    $LISTENER_ARN = aws elbv2 describe-listeners `
        --load-balancer-arn "arn:aws:elasticloadbalancing:us-east-1:555043101106:loadbalancer/app/ca-a2a-alb/b8850f22644b255c" `
        --region $AWS_REGION `
        --query "Listeners[0].ListenerArn" `
        --output text
    
    # Modify listener default action
    aws elbv2 modify-listener `
        --listener-arn $LISTENER_ARN `
        --default-actions Type=forward,TargetGroupArn=$TG_ARN `
        --region $AWS_REGION | Out-Null
    
    Write-Host "  Configured ALB listener" -ForegroundColor Green
}

foreach ($agent in $AGENTS) {
    $name = $agent.name
    $port = $agent.port
    
    Write-Host "Creating service ${name}..." -ForegroundColor Yellow
    
    # Check if service exists
    $existingService = aws ecs describe-services `
        --cluster $CLUSTER `
        --services $name `
        --region $AWS_REGION `
        --query "services[?status=='ACTIVE'].serviceName" `
        --output text 2>$null
    
    if ($existingService) {
        Write-Host "  Service ${name} exists, updating..." -ForegroundColor Yellow
        aws ecs update-service `
            --cluster $CLUSTER `
            --service $name `
            --task-definition "ca-a2a-${name}" `
            --force-new-deployment `
            --region $AWS_REGION | Out-Null
    } else {
        # Create service
        if ($name -eq "orchestrator") {
            # Orchestrator with load balancer
            aws ecs create-service `
                --cluster $CLUSTER `
                --service-name $name `
                --task-definition "ca-a2a-${name}" `
                --desired-count 1 `
                --launch-type FARGATE `
                --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_LIST],securityGroups=[$SG_ID],assignPublicIp=DISABLED}" `
                --load-balancers "targetGroupArn=$TG_ARN,containerName=$name,containerPort=$port" `
                --region $AWS_REGION | Out-Null
        } else {
            # Other services without load balancer
            aws ecs create-service `
                --cluster $CLUSTER `
                --service-name $name `
                --task-definition "ca-a2a-${name}" `
                --desired-count 1 `
                --launch-type FARGATE `
                --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_LIST],securityGroups=[$SG_ID],assignPublicIp=DISABLED}" `
                --region $AWS_REGION | Out-Null
        }
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Created/Updated service ${name}" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Issue with service ${name}" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Waiting for Services to Stabilize"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$maxWait = 300
$elapsed = 0
$interval = 30

while ($elapsed -lt $maxWait) {
    Start-Sleep -Seconds $interval
    $elapsed += $interval
    
    Write-Host "[$elapsed/$maxWait] Checking service status..." -ForegroundColor Cyan
    
    foreach ($agent in $AGENTS) {
        $name = $agent.name
        $status = aws ecs describe-services `
            --cluster $CLUSTER `
            --services $name `
            --region $AWS_REGION `
            --query "services[0].{running:runningCount,desired:desiredCount}" `
            --output json 2>$null | ConvertFrom-Json
        
        if ($status) {
            Write-Host "  ${name}: running=$($status.running), desired=$($status.desired)" -ForegroundColor White
        }
    }
    Write-Host ""
}

Write-Host "==========================================" -ForegroundColor Green
Write-Host "Deployment Complete"
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "ALB URL: http://$ALB_DNS" -ForegroundColor Yellow
Write-Host ""
Write-Host "Security Features Enabled:" -ForegroundColor Green
Write-Host "  - Authentication: Required (A2A_REQUIRE_AUTH=true)" -ForegroundColor White
Write-Host "  - Rate Limiting: 100 req/60s" -ForegroundColor White
Write-Host "  - Replay Protection: Enabled" -ForegroundColor White
Write-Host "  - Schema Validation: Enabled" -ForegroundColor White
Write-Host "  - Audit Logging: Enabled" -ForegroundColor White
Write-Host ""
Write-Host "Run security test:" -ForegroundColor Yellow
Write-Host "  .\Test-SecurityComprehensive.ps1 -Region us-east-1" -ForegroundColor White
Write-Host ""

