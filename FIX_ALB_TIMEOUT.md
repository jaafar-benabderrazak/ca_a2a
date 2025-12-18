# 🚨 URGENT FIX: ALB Timeout Issue

Your orchestrator service isn't responding. Let's diagnose and fix it.

---

## Step 1: Quick Diagnosis (Run These in CloudShell)

```bash
export AWS_REGION=eu-west-3

# Check 1: Are targets healthy?
echo "=== Checking ALB Target Health ==="
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region $AWS_REGION \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State,TargetHealth.Reason,TargetHealth.Description]' \
  --output table
```

**If targets show "unhealthy"** → Go to Fix #1  
**If targets show "healthy"** → Go to Fix #2

```bash
# Check 2: Are orchestrator tasks running?
echo "=== Checking Orchestrator Tasks ==="
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region $AWS_REGION \
  --query 'services[0].{Running:runningCount,Desired:desiredCount,Status:status}' \
  --output table

# Check 3: Recent service events
echo "=== Recent Events ==="
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region $AWS_REGION \
  --query 'services[0].events[0:3].message' \
  --output text
```

```bash
# Check 4: Check for errors in logs
echo "=== Checking Logs for Errors ==="
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "ERROR" \
  --start-time $(($(date +%s) - 600))000 \
  --region $AWS_REGION \
  --query 'events[*].message' \
  --output text | head -10
```

---

## Fix #1: Restart Orchestrator Service (Most Common)

```bash
echo "=== Forcing Service Restart ==="

# Stop all current tasks
TASK_ARNS=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --region $AWS_REGION \
  --query 'taskArns' \
  --output text)

for task in $TASK_ARNS; do
  echo "Stopping task: $task"
  aws ecs stop-task \
    --cluster ca-a2a-cluster \
    --task $task \
    --region $AWS_REGION \
    --output text > /dev/null
done

echo "Waiting 30 seconds for tasks to stop..."
sleep 30

# Force new deployment
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force-new-deployment \
  --region $AWS_REGION \
  --output json > /dev/null

echo "✓ Deployment triggered"
echo ""
echo "Waiting 90 seconds for new tasks to start..."
sleep 90

# Check status
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region $AWS_REGION \
  --query 'services[0].{Running:runningCount,Desired:desiredCount}' \
  --output table

# Check target health
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region $AWS_REGION \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State]' \
  --output table

# Test API
echo "Testing API..."
curl -s -m 10 http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health | jq '.'
```

---

## Fix #2: Scale Down and Up (Nuclear Option)

```bash
echo "=== Scaling Service ==="

# Scale to 0
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --desired-count 0 \
  --region $AWS_REGION

echo "Waiting 30 seconds..."
sleep 30

# Scale back to 2
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --desired-count 2 \
  --region $AWS_REGION

echo "Waiting 90 seconds for startup..."
sleep 90

# Test
curl -s http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health | jq '.'
```

---

## Fix #3: Check Recent Logs for Root Cause

```bash
# Get all recent logs (not just errors)
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 10m \
  --region $AWS_REGION | tail -50
```

**Look for these issues:**
- ❌ `Connection refused` → Database issue
- ❌ `Port already in use` → Container port conflict
- ❌ `Permission denied` → IAM/Secrets Manager issue
- ❌ `Timeout` → Network/VPC endpoint issue

---

## Fix #4: Check Database Connectivity

```bash
# Check RDS status
aws rds describe-db-instances \
  --db-instance-identifier ca-a2a-postgres \
  --region $AWS_REGION \
  --query 'DBInstances[0].{Status:DBInstanceStatus,Endpoint:Endpoint.Address,Port:Endpoint.Port}'
```

**If RDS is not "available"** → Wait for it to start

---

## Fix #5: Recreate Service (Last Resort)

```bash
# Delete service
aws ecs delete-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force \
  --region $AWS_REGION

# Wait for deletion
echo "Waiting 60 seconds for deletion..."
sleep 60

# Recreate service
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
  --region $AWS_REGION

echo "Waiting 2 minutes for service to start..."
sleep 120

# Test
curl -s http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health | jq '.'
```

---

## Quick One-Liner Fix (Try This First!)

```bash
# Quick restart and wait
aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --force-new-deployment --region eu-west-3 && echo "Waiting 90s..." && sleep 90 && curl -s http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health | jq '.'
```

---

## Expected Output After Fix

```json
{
  "status": "healthy",
  "agent": "Orchestrator",
  "version": "1.0.0",
  "timestamp": "2025-12-18T18:00:00Z"
}
```

---

## If Nothing Works

### Check Task Definition

```bash
# See what the task is configured to do
aws ecs describe-task-definition \
  --task-definition ca-a2a-orchestrator:6 \
  --region $AWS_REGION \
  --query 'taskDefinition.{Image:containerDefinitions[0].image,Port:containerDefinitions[0].portMappings[0].containerPort,Health:containerDefinitions[0].healthCheck}' \
  --output json
```

### Get Task Details

```bash
# Get actual running task info
TASK_ARN=$(aws ecs list-tasks --cluster ca-a2a-cluster --service orchestrator --region $AWS_REGION --query 'taskArns[0]' --output text)

aws ecs describe-tasks \
  --cluster ca-a2a-cluster \
  --tasks $TASK_ARN \
  --region $AWS_REGION \
  --query 'tasks[0].{Status:lastStatus,Health:healthStatus,Containers:containers[0].{Name:name,Status:lastStatus,ExitCode:exitCode}}' \
  --output json
```

---

## Most Likely Issue

Based on the symptoms (timeouts on both endpoints), the most likely causes are:

1. **Tasks crashed/failing** → Fix #1 (restart) should work
2. **Database connection issues** → Check logs with Fix #3
3. **Port binding conflict** → Fix #2 (scale down/up) should work

**Start with Fix #1 - it solves 90% of cases!**

---

## After Fix - Test Commands

```bash
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Test 1
curl -s "$ALB_URL/health"

# Test 2
curl -s "$ALB_URL/card" | jq '.agent_name'

# Test 3
curl -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/test.txt"}'
```

All three should return JSON (not timeout).

---

**Run Fix #1 now and let me know the results!** 🚀

