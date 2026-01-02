# 🚨 Troubleshooting Guide

## Common Issues

### 1. Import Error: MCP SDK Client Session (FIXED)

**Symptom:**
- New orchestrator container fails to start
- Error: `ImportError: cannot import name 'ClientSession' from 'mcp.client'`
- Old containers work, new containers fail

**Root Cause:**
- `mcp_client.py` imports MCP stdio SDK at module level
- MCP SDK API changed between versions
- In AWS, we only use HTTP mode but the import still executes

**Solution:**
✅ **Fixed in commit**: Make MCP stdio imports conditional and defensive
- `mcp_client.py`: Conditional import with API compatibility check
- All `Dockerfile.*`: Updated to Python 3.11 (required for `mcp>=0.9.0`)
- `Rebuild-And-Redeploy-Orchestrator.ps1`: Script to rebuild and redeploy

**Steps to Deploy Fix:**
```powershell
# Rebuild and redeploy orchestrator with fixed code
.\Rebuild-And-Redeploy-Orchestrator.ps1
```

**What Changed:**
1. `mcp_client.py` now safely handles missing/incompatible MCP SDK
2. Initialize variables to None before attempting import
3. Check if SDK classes exist before importing (API compatibility)
4. All Dockerfiles updated to Python 3.11 for consistency

---

### 2. ALB Timeout Issue

## Problem
- ECS services are ACTIVE
- ALB requests timeout (no response after 30+ seconds)
- CloudShell can't reach the orchestrator

## Diagnosis Steps

### Step 1: Check Target Group Health

```bash
# Check if targets are healthy
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region eu-west-3 \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State,TargetHealth.Reason]' \
  --output table
```

**Expected:** Both targets should be "healthy"  
**If "unhealthy":** Targets are failing health checks

### Step 2: Check Orchestrator Logs

```bash
# Check for errors in orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 5m \
  --region eu-west-3 \
  --filter-pattern "ERROR" | head -20

# Check if orchestrator is starting
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 5m \
  --region eu-west-3 | grep "started" | tail -5
```

### Step 3: Check Orchestrator Task Status

```bash
# Get orchestrator tasks
aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --region eu-west-3

# Describe the tasks
aws ecs describe-tasks \
  --cluster ca-a2a-cluster \
  --tasks $(aws ecs list-tasks --cluster ca-a2a-cluster --service orchestrator --region eu-west-3 --query 'taskArns[0]' --output text) \
  --region eu-west-3 \
  --query 'tasks[0].{Status:lastStatus,Health:healthStatus,Started:startedAt}'
```

### Step 4: Check Service Events

```bash
# Check for service deployment issues
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].events[0:5].[createdAt,message]' \
  --output table
```

## Common Fixes

### Fix 1: Tasks are Unhealthy

```bash
# Stop all tasks to force restart
aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --region eu-west-3 \
  --query 'taskArns' \
  --output text | xargs -I {} aws ecs stop-task \
  --cluster ca-a2a-cluster \
  --task {} \
  --region eu-west-3

# Wait 60 seconds for new tasks
sleep 60

# Check status
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].[serviceName,runningCount,desiredCount]' \
  --output table
```

### Fix 2: Force New Deployment

```bash
# Force new deployment with fresh tasks
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force-new-deployment \
  --region eu-west-3

# Wait 90 seconds
sleep 90

# Check target health
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region eu-west-3 \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State]' \
  --output table
```

### Fix 3: Scale Down and Up

```bash
# Scale to 0
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --desired-count 0 \
  --region eu-west-3

# Wait for tasks to stop
sleep 30

# Scale back to 2
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --desired-count 2 \
  --region eu-west-3

# Wait for tasks to start
sleep 90

# Test again
curl $ALB_URL/health
```

## Quick Diagnostic Script

Copy and paste this entire block:

```bash
#!/bin/bash
echo "=== Diagnostic Report ==="
echo ""

echo "1. Target Health:"
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region eu-west-3 \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State,TargetHealth.Reason]' \
  --output table

echo ""
echo "2. Service Status:"
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].{Name:serviceName,Running:runningCount,Desired:desiredCount,Status:status}' \
  --output table

echo ""
echo "3. Recent Service Events:"
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].events[0:3].message' \
  --output text

echo ""
echo "4. Recent Logs (last 2 minutes):"
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --start-time $(($(date +%s) - 120))000 \
  --region eu-west-3 \
  --query 'events[*].message' \
  --output text | tail -10

echo ""
echo "=== End Report ==="
```

## If Nothing Works

### Nuclear Option: Recreate Service

```bash
# Delete service
aws ecs delete-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force \
  --region eu-west-3

# Wait for deletion
sleep 30

# Recreate service (use Create-Orchestrator-Service.ps1 or this):
aws ecs create-service \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --task-definition ca-a2a-orchestrator:6 \
  --desired-count 2 \
  --launch-type FARGATE \
  --platform-version LATEST \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-07484aca0e473e3d0,subnet-0aef6b4fcce7748a9],securityGroups=[sg-047a8f39f9cdcaf4c],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779,containerName=orchestrator,containerPort=8001" \
  --health-check-grace-period-seconds 60 \
  --enable-execute-command \
  --region eu-west-3
```

## What to Check Next

1. Are targets "healthy" or "unhealthy"?
2. Are there ERROR messages in logs?
3. Are tasks actually running?
4. Is the health check path correct (/health)?

Run the diagnostic script above and share the output!

