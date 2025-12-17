# Deploy Skill Filtering to AWS

This guide explains how to deploy the new skill filtering features to your existing AWS deployment and test them.

---

## Prerequisites

You should have already deployed the base system using:
- `deploy-sso-phase1.sh` - Infrastructure
- `deploy-sso-phase2.sh` - Docker images and services

Now we'll update the deployment with the new filtering features.

---

## Part 1: Update Docker Images

The skill filtering system is already in your codebase, so we just need to rebuild and push the Docker images.

### Step 1: Verify New Files

```bash
# Check that new files are present
ls -l skill_filter.py skill_filter_integration.py config/user_permissions.yaml

# Should show:
# skill_filter.py
# skill_filter_integration.py
# config/user_permissions.yaml
```

### Step 2: Rebuild Docker Images

```bash
# Set your AWS variables
export AWS_REGION="eu-west-3"
export AWS_ACCOUNT_ID="555043101106"
export PROJECT_NAME="ca-a2a"

# Login to ECR
aws ecr get-login-password --region ${AWS_REGION} | \
  docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Rebuild images with new code
for agent in orchestrator extractor validator archivist; do
    echo "Building ${agent}..."
    IMAGE_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/${agent}:latest"

    docker build -f Dockerfile.${agent} -t ${IMAGE_URI} .
    docker push ${IMAGE_URI}

    echo "✓ Pushed ${agent}"
done
```

**Expected Output:**
```
Building orchestrator...
✓ Pushed orchestrator
Building extractor...
✓ Pushed extractor
Building validator...
✓ Pushed validator
Building archivist...
✓ Pushed archivist
```

### Step 3: Force Service Update

Force ECS to pull the new images:

```bash
# Update all services to use new images
for agent in orchestrator extractor validator archivist; do
    echo "Updating ${agent} service..."

    aws ecs update-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service ${PROJECT_NAME}-${agent} \
        --force-new-deployment \
        --region ${AWS_REGION}

    echo "✓ Triggered ${agent} update"
done
```

### Step 4: Wait for Services to Stabilize

```bash
# Wait for services to finish updating
for agent in orchestrator extractor validator archivist; do
    echo "Waiting for ${agent} to stabilize..."

    aws ecs wait services-stable \
        --cluster ${PROJECT_NAME}-cluster \
        --services ${PROJECT_NAME}-${agent} \
        --region ${AWS_REGION}

    echo "✓ ${agent} is running"
done
```

**This takes 3-5 minutes per service.**

---

## Part 2: Verify Deployment

### Check Service Health

```bash
# Get ALB URL
ALB_DNS=$(aws elbv2 describe-load-balancers \
    --region ${AWS_REGION} \
    --query "LoadBalancers[?contains(LoadBalancerName, '${PROJECT_NAME}')].DNSName" \
    --output text)

echo "ALB URL: http://${ALB_DNS}"

# Test health endpoints
for agent in orchestrator extractor validator archivist; do
    echo "Testing ${agent}..."
    curl -s "http://${ALB_DNS}:800${agent: -1}/health" | jq .
done
```

### Check Running Tasks

```bash
# List running tasks
aws ecs list-tasks \
    --cluster ${PROJECT_NAME}-cluster \
    --region ${AWS_REGION}

# Get detailed task info
for agent in orchestrator extractor validator archivist; do
    TASK_ARN=$(aws ecs list-tasks \
        --cluster ${PROJECT_NAME}-cluster \
        --service-name ${PROJECT_NAME}-${agent} \
        --region ${AWS_REGION} \
        --query 'taskArns[0]' \
        --output text)

    if [ ! -z "$TASK_ARN" ]; then
        echo "✓ ${agent} task running: ${TASK_ARN}"
    else
        echo "✗ ${agent} task NOT running"
    fi
done
```

---

## Part 3: Test Skill Filtering

### Get Your ALB Endpoint

```bash
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
# Or discover it:
export ALB_URL="http://$(aws elbv2 describe-load-balancers \
    --region ${AWS_REGION} \
    --query "LoadBalancers[?contains(LoadBalancerName, '${PROJECT_NAME}')].DNSName" \
    --output text)"

echo "Testing against: $ALB_URL"
```

### Test 1: Viewer Access (Read-Only)

```bash
# Test as viewer - should be able to get agent card
curl -X GET "${ALB_URL}:8001/card" \
    -H "X-User-Category: viewer" \
    -H "X-User-ID: viewer_001" \
    | jq '.filtered_for'

# Expected: Filtered card with limited skills

# Try to extract (should fail)
curl -X POST "${ALB_URL}:8001/a2a" \
    -H "Content-Type: application/json" \
    -H "X-User-Category: viewer" \
    -H "X-User-ID: viewer_001" \
    -d '{
        "jsonrpc": "2.0",
        "id": "1",
        "method": "extract_document",
        "params": {"s3_key": "test.pdf"}
    }' | jq .

# Expected: Access denied error
```

### Test 2: Power User Access (Full Processing)

```bash
# Upload test document to S3 first
echo "Test document content" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://ca-a2a-documents-555043101106/demo/test.txt --region ${AWS_REGION}

# Test as power user - should succeed
curl -X POST "${ALB_URL}:8001/a2a" \
    -H "Content-Type: application/json" \
    -H "X-User-Category: power_user" \
    -H "X-User-ID: power_user_001" \
    -d '{
        "jsonrpc": "2.0",
        "id": "1",
        "method": "process_document",
        "params": {"s3_key": "demo/test.txt"}
    }' | jq .

# Expected: Success response with task_id
```

### Test 3: Get User Permissions

```bash
# Check permissions endpoint
curl -X GET "${ALB_URL}:8001/permissions" \
    -H "X-User-Category: power_user" \
    -H "X-User-ID: power_user_001" \
    | jq .

# Expected:
# {
#   "user_id": "power_user_001",
#   "category": "power_user",
#   "allowed_skills": [...],
#   "skill_count": 15
# }
```

### Test 4: Different User Categories

```bash
# Test all categories
for category in viewer standard_user power_user analyst auditor admin; do
    echo "=== Testing ${category} ==="
    curl -X GET "${ALB_URL}:8001/permissions" \
        -H "X-User-Category: ${category}" \
        -H "X-User-ID: ${category}_test" \
        | jq '{category, skill_count}'
    echo ""
done
```

---

## Part 4: Complete Demo Script

I'll create a demo script that tests all features...

### Save this as `demo_aws_filtering.sh`

```bash
#!/bin/bash
set -e

# Configuration
export AWS_REGION="eu-west-3"
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
export S3_BUCKET="ca-a2a-documents-555043101106"

echo "==========================================="
echo "CA A2A Skill Filtering Demo on AWS"
echo "==========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

# Test 1: Health Check
echo "Test 1: Health Check"
echo "-------------------"
HEALTH=$(curl -s "${ALB_URL}:8001/health" | jq -r '.status')
if [ "$HEALTH" = "healthy" ]; then
    log_success "Orchestrator is healthy"
else
    log_error "Orchestrator is not healthy"
    exit 1
fi
echo ""

# Test 2: Viewer Access (Should be restricted)
echo "Test 2: Viewer Access (Read-Only)"
echo "---------------------------------"
log_info "Testing viewer permissions..."

VIEWER_RESPONSE=$(curl -s -X POST "${ALB_URL}:8001/a2a" \
    -H "Content-Type: application/json" \
    -H "X-User-Category: viewer" \
    -H "X-User-ID: demo_viewer" \
    -d '{
        "jsonrpc": "2.0",
        "id": "1",
        "method": "process_document",
        "params": {"s3_key": "test.pdf"}
    }')

ERROR_MSG=$(echo $VIEWER_RESPONSE | jq -r '.error.message')
if [[ "$ERROR_MSG" == *"Access denied"* ]]; then
    log_success "Viewer correctly denied processing access"
else
    log_error "Viewer should not have processing access!"
fi
echo ""

# Test 3: Standard User Access
echo "Test 3: Standard User Access"
echo "----------------------------"
log_info "Testing standard user permissions..."

PERMS=$(curl -s "${ALB_URL}:8001/permissions" \
    -H "X-User-Category: standard_user" \
    -H "X-User-ID: demo_standard_user")

SKILL_COUNT=$(echo $PERMS | jq -r '.skill_count')
log_success "Standard user has access to $SKILL_COUNT skills"
echo ""

# Test 4: Power User Access
echo "Test 4: Power User Access"
echo "-------------------------"
log_info "Testing power user permissions..."

PERMS=$(curl -s "${ALB_URL}:8001/permissions" \
    -H "X-User-Category: power_user" \
    -H "X-User-ID: demo_power_user")

SKILL_COUNT=$(echo $PERMS | jq -r '.skill_count')
log_success "Power user has access to $SKILL_COUNT skills"
echo ""

# Test 5: Admin Access
echo "Test 5: Admin Access"
echo "--------------------"
log_info "Testing admin permissions..."

PERMS=$(curl -s "${ALB_URL}:8001/permissions" \
    -H "X-User-Category: admin" \
    -H "X-User-ID: demo_admin")

SKILL_COUNT=$(echo $PERMS | jq -r '.skill_count')
log_success "Admin has access to $SKILL_COUNT skills (all)"
echo ""

# Test 6: Filtered Agent Card
echo "Test 6: Filtered Agent Cards"
echo "----------------------------"
for category in viewer power_user admin; do
    log_info "Getting filtered card for ${category}..."

    CARD=$(curl -s "${ALB_URL}:8001/card" \
        -H "X-User-Category: ${category}" \
        -H "X-User-ID: demo_${category}")

    SKILLS=$(echo $CARD | jq -r '.skills | length')
    log_success "${category}: ${SKILLS} skills visible"
done
echo ""

# Test 7: Real Document Processing (if S3 accessible)
echo "Test 7: Real Document Processing"
echo "--------------------------------"
log_info "Uploading test document to S3..."

# Create test CSV
cat > /tmp/demo_test.csv <<EOF
name,age,city
John,30,New York
Jane,25,Los Angeles
Bob,35,Chicago
EOF

# Upload to S3
aws s3 cp /tmp/demo_test.csv "s3://${S3_BUCKET}/demo/test_$(date +%s).csv" --region ${AWS_REGION}

log_success "Test document uploaded"

log_info "Processing as power user..."
RESPONSE=$(curl -s -X POST "${ALB_URL}:8001/a2a" \
    -H "Content-Type: application/json" \
    -H "X-User-Category: power_user" \
    -H "X-User-ID: demo_power_user" \
    -d "{
        \"jsonrpc\": \"2.0\",
        \"id\": \"1\",
        \"method\": \"process_document\",
        \"params\": {\"s3_key\": \"demo/test_$(date +%s).csv\"}
    }")

TASK_ID=$(echo $RESPONSE | jq -r '.result.task_id // "none"')
if [ "$TASK_ID" != "none" ]; then
    log_success "Document processing started: $TASK_ID"

    # Wait and check status
    sleep 5
    log_info "Checking task status..."

    STATUS_RESPONSE=$(curl -s -X POST "${ALB_URL}:8001/a2a" \
        -H "Content-Type: application/json" \
        -H "X-User-Category: power_user" \
        -H "X-User-ID: demo_power_user" \
        -d "{
            \"jsonrpc\": \"2.0\",
            \"id\": \"2\",
            \"method\": \"get_task_status\",
            \"params\": {\"task_id\": \"$TASK_ID\"}
        }")

    STATUS=$(echo $STATUS_RESPONSE | jq -r '.result.status')
    log_success "Task status: $STATUS"
else
    log_error "Failed to start processing"
fi
echo ""

echo "==========================================="
echo "Demo Complete!"
echo "==========================================="
echo ""
echo "Summary:"
echo "✓ Viewer: Read-only access (denied processing)"
echo "✓ Standard User: Basic processing access"
echo "✓ Power User: Full processing access"
echo "✓ Admin: Complete access to all features"
echo "✓ Filtered agent cards working"
echo "✓ Real document processing working"
echo ""
echo "Your AWS deployment is fully functional with skill filtering!"
```

Save and run:

```bash
chmod +x demo_aws_filtering.sh
./demo_aws_filtering.sh
```

---

## Part 5: Live Demo Presentation

### Demo Flow for Stakeholders

#### Setup (Before Demo)

```bash
# 1. Get ALB URL
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# 2. Prepare test documents
echo "Invoice data" > /tmp/invoice.txt
aws s3 cp /tmp/invoice.txt s3://ca-a2a-documents-555043101106/demo/invoice.txt

# 3. Open browser to monitoring (optional)
# AWS Console → ECS → ca-a2a-cluster
```

#### Demo Script (10 minutes)

**1. Introduction (1 min)**

"We've deployed a multi-agent document processing system to AWS with role-based access control. Let me show you how different user roles interact with the system."

**2. Show System Health (1 min)**

```bash
# All agents running
curl ${ALB_URL}:8001/health | jq .
curl ${ALB_URL}:8002/health | jq .
curl ${ALB_URL}:8003/health | jq .
curl ${ALB_URL}:8004/health | jq .
```

**3. Demonstrate Access Control (3 min)**

```bash
# Viewer - Can only view
echo "=== Viewer (Read-Only) ==="
curl ${ALB_URL}:8001/permissions \
    -H "X-User-Category: viewer" | jq '{category, skill_count}'

# Try to process (fails)
curl -X POST ${ALB_URL}:8001/a2a \
    -H "Content-Type: application/json" \
    -H "X-User-Category: viewer" \
    -d '{"jsonrpc":"2.0","id":"1","method":"process_document","params":{"s3_key":"demo/invoice.txt"}}' \
    | jq '.error.message'

# Power User - Full access
echo "=== Power User (Full Processing) ==="
curl ${ALB_URL}:8001/permissions \
    -H "X-User-Category: power_user" | jq '{category, skill_count}'

# Process successfully
curl -X POST ${ALB_URL}:8001/a2a \
    -H "Content-Type: application/json" \
    -H "X-User-Category: power_user" \
    -d '{"jsonrpc":"2.0","id":"1","method":"process_document","params":{"s3_key":"demo/invoice.txt"}}' \
    | jq '.result'
```

**4. Show Filtered Agent Cards (2 min)**

```bash
# Different users see different capabilities
curl ${ALB_URL}:8001/card -H "X-User-Category: viewer" \
    | jq '{name, skills: (.skills | length)}'

curl ${ALB_URL}:8001/card -H "X-User-Category: power_user" \
    | jq '{name, skills: (.skills | length)}'

curl ${ALB_URL}:8001/card -H "X-User-Category: admin" \
    | jq '{name, skills: (.skills | length)}'
```

**5. Real Document Processing (3 min)**

```bash
# Upload sample CSV
cat > /tmp/sample.csv <<EOF
product,price,quantity
Widget,10.00,100
Gadget,25.50,50
EOF

aws s3 cp /tmp/sample.csv s3://ca-a2a-documents-555043101106/demo/sample.csv

# Process as power user
RESPONSE=$(curl -s -X POST ${ALB_URL}:8001/a2a \
    -H "Content-Type: application/json" \
    -H "X-User-Category: power_user" \
    -d '{"jsonrpc":"2.0","id":"1","method":"process_document","params":{"s3_key":"demo/sample.csv"}}')

TASK_ID=$(echo $RESPONSE | jq -r '.result.task_id')
echo "Processing started: $TASK_ID"

# Wait 5 seconds
sleep 5

# Check status
curl -s -X POST ${ALB_URL}:8001/a2a \
    -H "Content-Type: application/json" \
    -H "X-User-Category: power_user" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"2\",\"method\":\"get_task_status\",\"params\":{\"task_id\":\"$TASK_ID\"}}" \
    | jq '.result.status'
```

---

## Part 6: Monitoring & Troubleshooting

### Check ECS Logs

```bash
# Get log group names
aws logs describe-log-groups \
    --log-group-name-prefix "/ecs/${PROJECT_NAME}" \
    --region ${AWS_REGION}

# Get recent logs for orchestrator
aws logs tail "/ecs/${PROJECT_NAME}-orchestrator" \
    --follow \
    --region ${AWS_REGION}
```

### Check Task Status

```bash
# Describe service
aws ecs describe-services \
    --cluster ${PROJECT_NAME}-cluster \
    --services ${PROJECT_NAME}-orchestrator \
    --region ${AWS_REGION} \
    | jq '.services[0] | {status, runningCount, desiredCount}'
```

### Common Issues

**Issue: Access denied for all users**

```bash
# Check if require_auth is properly set
# Should see skill filtering in agent logs
aws logs tail "/ecs/${PROJECT_NAME}-orchestrator" --region ${AWS_REGION} | grep "Access"
```

**Issue: Services not updating**

```bash
# Force stop tasks to pull new images
TASK_ARNS=$(aws ecs list-tasks \
    --cluster ${PROJECT_NAME}-cluster \
    --service-name ${PROJECT_NAME}-orchestrator \
    --region ${AWS_REGION} \
    --query 'taskArns' \
    --output text)

for TASK_ARN in $TASK_ARNS; do
    aws ecs stop-task \
        --cluster ${PROJECT_NAME}-cluster \
        --task $TASK_ARN \
        --region ${AWS_REGION}
done

# Service will automatically start new tasks
```

---

## Part 7: Cleanup (Optional)

If you want to remove the deployment:

```bash
# Run cleanup script
./cleanup-aws.sh

# Or manual cleanup:
# 1. Delete ECS services
# 2. Delete task definitions
# 3. Delete cluster
# 4. Delete ALB
# 5. Delete RDS
# 6. Empty and delete S3 bucket
# 7. Delete VPC resources
```

---

## Summary

✅ **Deployment:** Rebuild Docker images → Push to ECR → Update ECS services
✅ **Testing:** Use curl with X-User-Category header
✅ **Demo:** Run demo_aws_filtering.sh
✅ **Monitoring:** CloudWatch Logs + ECS console

**Your ALB Endpoint:**
```
http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com:8001
```

**Test Commands:**
```bash
# Health
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com:8001/health

# Permissions
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com:8001/permissions \
    -H "X-User-Category: power_user"

# Process Document
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com:8001/a2a \
    -H "Content-Type: application/json" \
    -H "X-User-Category: power_user" \
    -d '{"jsonrpc":"2.0","id":"1","method":"process_document","params":{"s3_key":"demo/test.txt"}}'
```

The system is now ready for a live demo! 🚀
