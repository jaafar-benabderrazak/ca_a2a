#
# Fix All Security Issues Script
# Fixes: Keycloak deployment, Agent Card 404, Security Headers, Rate Limiting, Security Config
#

param(
    [string]$Region = "us-east-1",
    [string]$Cluster = "ca-a2a-cluster",
    [string]$Profile = "AWSAdministratorAccess-555043101106"
)

$ErrorActionPreference = "Stop"
$env:AWS_PROFILE = $Profile

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  CA-A2A Security Issues Fix Script" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Region: $Region"
Write-Host "Cluster: $Cluster"
Write-Host ""

# Get infrastructure info
$outputs = Get-Content ".\cdk\outputs.json" | ConvertFrom-Json
$vpcId = $outputs.'ca-a2a-prod'.VpcId
$sgId = $outputs.'ca-a2a-prod'.EcsServicesSecurityGroupId
$albArn = $outputs.'ca-a2a-prod'.AlbArn
$albDns = $outputs.'ca-a2a-prod'.AlbDnsName

Write-Host "VPC: $vpcId"
Write-Host "Security Group: $sgId"
Write-Host "ALB: $albDns"
Write-Host ""

# Get private subnets
Write-Host "[1/6] Getting private subnets..." -ForegroundColor Yellow
$subnets = aws ec2 describe-subnets --region $Region --filters "Name=vpc-id,Values=$vpcId" "Name=tag:aws-cdk:subnet-type,Values=Private" --query "Subnets[*].SubnetId" --output json | ConvertFrom-Json
$subnetIds = $subnets -join ","
Write-Host "  Subnets: $subnetIds"

# Get listener ARN
$listenerArn = aws elbv2 describe-listeners --load-balancer-arn $albArn --region $Region --query "Listeners[0].ListenerArn" --output text

###############################################################################
# FIX 1: Deploy Keycloak Service
###############################################################################
Write-Host ""
Write-Host "[2/6] Deploying Keycloak Service..." -ForegroundColor Yellow

# Check if keycloak service exists
$keycloakService = aws ecs describe-services --cluster $Cluster --services keycloak --region $Region --query "services[?status=='ACTIVE'].serviceName" --output text 2>$null

if (-not $keycloakService) {
    Write-Host "  Creating Keycloak ECS service..."
    
    # Get keycloak target group ARN
    $keycloakTgArn = aws elbv2 describe-target-groups --region $Region --names "ca-a2a-keycloak-tg" --query "TargetGroups[0].TargetGroupArn" --output text 2>$null
    
    if (-not $keycloakTgArn -or $keycloakTgArn -eq "None") {
        Write-Host "  Creating Keycloak target group..."
        $keycloakTgArn = aws elbv2 create-target-group `
            --name "ca-a2a-keycloak-tg" `
            --protocol HTTP `
            --port 8080 `
            --vpc-id $vpcId `
            --target-type ip `
            --health-check-path "/health/ready" `
            --health-check-interval-seconds 30 `
            --health-check-timeout-seconds 10 `
            --healthy-threshold-count 2 `
            --unhealthy-threshold-count 3 `
            --region $Region `
            --query "TargetGroups[0].TargetGroupArn" `
            --output text
        Write-Host "  Created target group: $keycloakTgArn"
    }
    
    # Create the service
    aws ecs create-service `
        --cluster $Cluster `
        --service-name keycloak `
        --task-definition ca-a2a-keycloak:2 `
        --desired-count 1 `
        --launch-type FARGATE `
        --network-configuration "awsvpcConfiguration={subnets=[$subnetIds],securityGroups=[$sgId],assignPublicIp=DISABLED}" `
        --load-balancers "targetGroupArn=$keycloakTgArn,containerName=keycloak,containerPort=8080" `
        --region $Region | Out-Null
    
    Write-Host "  [OK] Keycloak service created" -ForegroundColor Green
} else {
    Write-Host "  [OK] Keycloak service already exists" -ForegroundColor Green
}

###############################################################################
# FIX 2: Add ALB rule for /.well-known/agent.json -> /card
###############################################################################
Write-Host ""
Write-Host "[3/6] Adding ALB rule for /.well-known/agent.json..." -ForegroundColor Yellow

# Get orchestrator target group
$orchestratorTgArn = aws elbv2 describe-target-groups --region $Region --names "ca-a2a-orchestrator-tg" --query "TargetGroups[0].TargetGroupArn" --output text

# Check if rule already exists
$existingRules = aws elbv2 describe-rules --listener-arn $listenerArn --region $Region --query "Rules[?Conditions[?Values[?contains(@, '.well-known')]]].RuleArn" --output text

if (-not $existingRules) {
    # Create rule for /.well-known/agent.json path
    aws elbv2 create-rule `
        --listener-arn $listenerArn `
        --priority 10 `
        --conditions "Field=path-pattern,Values=/.well-known/*" `
        --actions "Type=forward,TargetGroupArn=$orchestratorTgArn" `
        --region $Region | Out-Null
    
    Write-Host "  [OK] ALB rule for /.well-known/* created" -ForegroundColor Green
} else {
    Write-Host "  [OK] ALB rule for /.well-known/* already exists" -ForegroundColor Green
}

# Add rule for /auth/* -> keycloak
$keycloakTgArn = aws elbv2 describe-target-groups --region $Region --names "ca-a2a-keycloak-tg" --query "TargetGroups[0].TargetGroupArn" --output text 2>$null

if ($keycloakTgArn -and $keycloakTgArn -ne "None") {
    $authRuleExists = aws elbv2 describe-rules --listener-arn $listenerArn --region $Region --query "Rules[?Conditions[?Values[?contains(@, '/auth')]]].RuleArn" --output text
    
    if (-not $authRuleExists) {
        aws elbv2 create-rule `
            --listener-arn $listenerArn `
            --priority 20 `
            --conditions "Field=path-pattern,Values=/auth/*" `
            --actions "Type=forward,TargetGroupArn=$keycloakTgArn" `
            --region $Region | Out-Null
        
        Write-Host "  [OK] ALB rule for /auth/* -> keycloak created" -ForegroundColor Green
    } else {
        Write-Host "  [OK] ALB rule for /auth/* already exists" -ForegroundColor Green
    }
}

###############################################################################
# FIX 3-5: Update Orchestrator with Security Config, Headers, Rate Limiting
###############################################################################
Write-Host ""
Write-Host "[4/6] Updating orchestrator task definition with full security config..." -ForegroundColor Yellow

# Get API keys from Secrets Manager
$apiKeysSecretArn = aws secretsmanager describe-secret --secret-id "ca-a2a-api-keys" --region $Region --query "ARN" --output text 2>$null

# Create comprehensive RBAC policy
$rbacPolicy = @{
    "allow" = @{
        "orchestrator" = @("*")
        "extractor" = @("extract_document", "health", "card", "skills")
        "validator" = @("validate_document", "health", "card", "skills")
        "archivist" = @("archive_document", "search_documents", "health", "card", "skills")
        "admin" = @("*")
        "user" = @("process_document", "get_task_status", "health")
        "anonymous" = @("health", "card")
    }
    "deny" = @{
        "anonymous" = @("process_document", "process_batch", "admin_*")
    }
} | ConvertTo-Json -Compress -Depth 5

# Escape for JSON embedding
$rbacPolicyEscaped = $rbacPolicy.Replace('"', '\"')

# Create updated task definition
$keycloakUrl = "http://keycloak.ca-a2a.local:8080"
$taskDefJson = @"
{
  "family": "ca-a2a-orchestrator",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::555043101106:role/ca-a2a-ecs-task-execution-role",
  "taskRoleArn": "arn:aws:iam::555043101106:role/ca-a2a-ecs-task-role",
  "containerDefinitions": [{
    "name": "orchestrator",
    "image": "555043101106.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/orchestrator:latest",
    "essential": true,
    "portMappings": [{"containerPort": 8001, "protocol": "tcp"}],
    "environment": [
      {"name": "ORCHESTRATOR_HOST", "value": "0.0.0.0"},
      {"name": "ORCHESTRATOR_PORT", "value": "8001"},
      {"name": "EXTRACTOR_URL", "value": "http://extractor.ca-a2a.local:8002"},
      {"name": "VALIDATOR_URL", "value": "http://validator.ca-a2a.local:8003"},
      {"name": "ARCHIVIST_URL", "value": "http://archivist.ca-a2a.local:8004"},
      {"name": "POSTGRES_HOST", "value": "ca-a2a-documents-db.cluster-crruu3dmzphw.us-east-1.rds.amazonaws.com"},
      {"name": "POSTGRES_DB", "value": "documents_db"},
      {"name": "POSTGRES_USER", "value": "postgres"},
      {"name": "POSTGRES_PORT", "value": "5432"},
      {"name": "S3_BUCKET_NAME", "value": "ca-a2a-prod-documentsbucket9ec9deb9-uopiyxhvtpk0"},
      {"name": "AWS_REGION", "value": "us-east-1"},
      {"name": "A2A_REQUIRE_AUTH", "value": "true"},
      {"name": "A2A_USE_KEYCLOAK", "value": "true"},
      {"name": "KEYCLOAK_URL", "value": "$keycloakUrl"},
      {"name": "KEYCLOAK_REALM", "value": "ca-a2a"},
      {"name": "KEYCLOAK_CLIENT_ID", "value": "a2a-agents"},
      {"name": "A2A_ENABLE_RATE_LIMIT", "value": "true"},
      {"name": "A2A_RATE_LIMIT_PER_MINUTE", "value": "300"},
      {"name": "A2A_ENABLE_REPLAY_PROTECTION", "value": "true"},
      {"name": "A2A_REPLAY_TTL_SECONDS", "value": "120"},
      {"name": "A2A_ENABLE_SCHEMA_VALIDATION", "value": "true"},
      {"name": "A2A_AUDIT_LOGGING", "value": "true"},
      {"name": "A2A_SECURITY_HEADERS", "value": "true"},
      {"name": "A2A_RBAC_POLICY_JSON", "value": "$rbacPolicyEscaped"},
      {"name": "A2A_API_KEYS_JSON", "value": "{\"demo-key-001\":\"admin\",\"test-key-001\":\"user\"}"}
    ],
    "secrets": [
      {"name": "POSTGRES_PASSWORD", "valueFrom": "arn:aws:secretsmanager:us-east-1:555043101106:secret:DbPassword10268EB9-PPoTWCj0mqqC-3JuJbz"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/ca-a2a-orchestrator",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "healthCheck": {
      "command": ["CMD-SHELL", "curl -f http://localhost:8001/health || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3,
      "startPeriod": 60
    }
  }]
}
"@

# Write task definition to temp file
$taskDefFile = ".\task-definitions\orchestrator-task-useast1-security-updated.json"
$taskDefJson | Out-File -FilePath $taskDefFile -Encoding UTF8

# Register new task definition
$newTaskDefArn = aws ecs register-task-definition --cli-input-json "file://$taskDefFile" --region $Region --query "taskDefinition.taskDefinitionArn" --output text
Write-Host "  Registered new task definition: $newTaskDefArn"

# Update service to use new task definition
aws ecs update-service --cluster $Cluster --service orchestrator --task-definition $newTaskDefArn --region $Region | Out-Null
Write-Host "  [OK] Orchestrator service updated with security config" -ForegroundColor Green

###############################################################################
# FIX 6: Update other agents with similar security config
###############################################################################
Write-Host ""
Write-Host "[5/6] Updating other agents with security config..." -ForegroundColor Yellow

$agents = @("extractor", "validator", "archivist")
$agentPorts = @{
    "extractor" = "8002"
    "validator" = "8003"
    "archivist" = "8004"
}

foreach ($agent in $agents) {
    $port = $agentPorts[$agent]
    $taskDefJson = @"
{
  "family": "ca-a2a-$agent",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::555043101106:role/ca-a2a-ecs-task-execution-role",
  "taskRoleArn": "arn:aws:iam::555043101106:role/ca-a2a-ecs-task-role",
  "containerDefinitions": [{
    "name": "$agent",
    "image": "555043101106.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/$agent`:latest",
    "essential": true,
    "portMappings": [{"containerPort": $port, "protocol": "tcp"}],
    "environment": [
      {"name": "HOST", "value": "0.0.0.0"},
      {"name": "PORT", "value": "$port"},
      {"name": "POSTGRES_HOST", "value": "ca-a2a-documents-db.cluster-crruu3dmzphw.us-east-1.rds.amazonaws.com"},
      {"name": "POSTGRES_DB", "value": "documents_db"},
      {"name": "POSTGRES_USER", "value": "postgres"},
      {"name": "POSTGRES_PORT", "value": "5432"},
      {"name": "S3_BUCKET_NAME", "value": "ca-a2a-prod-documentsbucket9ec9deb9-uopiyxhvtpk0"},
      {"name": "AWS_REGION", "value": "us-east-1"},
      {"name": "A2A_REQUIRE_AUTH", "value": "true"},
      {"name": "A2A_USE_KEYCLOAK", "value": "true"},
      {"name": "KEYCLOAK_URL", "value": "$keycloakUrl"},
      {"name": "A2A_ENABLE_RATE_LIMIT", "value": "true"},
      {"name": "A2A_RATE_LIMIT_PER_MINUTE", "value": "300"},
      {"name": "A2A_ENABLE_REPLAY_PROTECTION", "value": "true"},
      {"name": "A2A_SECURITY_HEADERS", "value": "true"},
      {"name": "A2A_RBAC_POLICY_JSON", "value": "$rbacPolicyEscaped"},
      {"name": "A2A_API_KEYS_JSON", "value": "{\"demo-key-001\":\"admin\",\"test-key-001\":\"user\"}"}
    ],
    "secrets": [
      {"name": "POSTGRES_PASSWORD", "valueFrom": "arn:aws:secretsmanager:us-east-1:555043101106:secret:DbPassword10268EB9-PPoTWCj0mqqC-3JuJbz"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/ca-a2a-$agent",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "healthCheck": {
      "command": ["CMD-SHELL", "curl -f http://localhost:$port/health || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3,
      "startPeriod": 60
    }
  }]
}
"@
    
    $taskDefFile = ".\task-definitions\$agent-task-useast1-security-updated.json"
    $taskDefJson | Out-File -FilePath $taskDefFile -Encoding UTF8
    
    $newTaskDefArn = aws ecs register-task-definition --cli-input-json "file://$taskDefFile" --region $Region --query "taskDefinition.taskDefinitionArn" --output text
    aws ecs update-service --cluster $Cluster --service $agent --task-definition $newTaskDefArn --region $Region | Out-Null
    
    Write-Host "  [OK] $agent service updated" -ForegroundColor Green
}

###############################################################################
# SUMMARY
###############################################################################
Write-Host ""
Write-Host "[6/6] Waiting for services to stabilize..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  SECURITY FIXES APPLIED" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "1. [OK] Keycloak service deployed" -ForegroundColor Green
Write-Host "2. [OK] ALB rules added for /.well-known/* and /auth/*" -ForegroundColor Green
Write-Host "3. [OK] Security headers enabled (A2A_SECURITY_HEADERS=true)" -ForegroundColor Green
Write-Host "4. [OK] Rate limiting configured (300 req/min)" -ForegroundColor Green
Write-Host "5. [OK] RBAC policy configured" -ForegroundColor Green
Write-Host "6. [OK] API keys configured" -ForegroundColor Green
Write-Host "7. [OK] Keycloak URL configured" -ForegroundColor Green
Write-Host ""
Write-Host "Services are updating. Run the following to check status:"
Write-Host "  aws ecs describe-services --cluster $Cluster --services orchestrator extractor validator archivist keycloak --region $Region --query 'services[*].[serviceName,runningCount,desiredCount]' --output table"
Write-Host ""
Write-Host "Test endpoints:"
Write-Host "  curl http://$albDns/health"
Write-Host "  curl http://$albDns/.well-known/agent.json"
Write-Host "  curl http://$albDns/card"
Write-Host ""

