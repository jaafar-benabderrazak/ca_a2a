# Quick AWS Demo Guide

Ultra-fast guide to deploy and demo skill filtering on AWS.

---

## ⚡ Quick Deploy (5 minutes)

### 1. Set Environment Variables

```bash
export AWS_REGION="eu-west-3"
export AWS_ACCOUNT_ID="555043101106"
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
```

### 2. Update Deployment

```bash
./update-aws-deployment.sh
```

**This script:**
- ✅ Rebuilds Docker images with new filtering code
- ✅ Pushes to ECR
- ✅ Updates all ECS services
- ✅ Waits for services to stabilize
- ✅ Verifies health and filtering

**Time:** 3-5 minutes

### 3. Run Demo

```bash
./demo_aws_filtering.sh
```

**This script tests:**
- ✅ System health (all 4 agents)
- ✅ Permission endpoints (6 user categories)
- ✅ Access control (allow/deny)
- ✅ Filtered agent cards
- ✅ Real document processing
- ✅ Analytics access (analyst role)
- ✅ Audit access (auditor role)

**Time:** 2-3 minutes

---

## 🎯 Manual Testing (30 seconds)

### Test 1: Health Check

```bash
curl ${ALB_URL}:8001/health | jq .
```

### Test 2: User Permissions

```bash
# Viewer (6 skills)
curl ${ALB_URL}:8001/permissions \
    -H "X-User-Category: viewer" | jq '{category, skill_count}'

# Power User (15 skills)
curl ${ALB_URL}:8001/permissions \
    -H "X-User-Category: power_user" | jq '{category, skill_count}'

# Admin (26 skills)
curl ${ALB_URL}:8001/permissions \
    -H "X-User-Category: admin" | jq '{category, skill_count}'
```

### Test 3: Access Control

```bash
# Viewer DENIED processing
curl -X POST ${ALB_URL}:8001/a2a \
    -H "Content-Type: application/json" \
    -H "X-User-Category: viewer" \
    -d '{"jsonrpc":"2.0","id":"1","method":"process_document","params":{"s3_key":"test.pdf"}}' \
    | jq '.error.message'

# Power User ALLOWED processing
curl -X POST ${ALB_URL}:8001/a2a \
    -H "Content-Type: application/json" \
    -H "X-User-Category: power_user" \
    -d '{"jsonrpc":"2.0","id":"1","method":"process_document","params":{"s3_key":"test.pdf"}}' \
    | jq .
```

### Test 4: Filtered Agent Card

```bash
# Viewer sees limited skills
curl ${ALB_URL}:8001/card \
    -H "X-User-Category: viewer" \
    | jq '{name, skills: (.skills | length)}'

# Admin sees all skills
curl ${ALB_URL}:8001/card \
    -H "X-User-Category: admin" \
    | jq '{name, skills: (.skills | length)}'
```

---

## 📊 Live Demo Script (10 minutes)

For stakeholder presentations:

### Part 1: Introduction (1 min)

"We've deployed a multi-agent document processing system to AWS with role-based access control. Different users see and can use different capabilities."

### Part 2: Show System (2 min)

```bash
# Show all agents healthy
curl ${ALB_URL}:8001/health | jq .
curl ${ALB_URL}:8002/health | jq .
curl ${ALB_URL}:8003/health | jq .
curl ${ALB_URL}:8004/health | jq .
```

### Part 3: Demonstrate Access Control (4 min)

```bash
# Show different permission levels
echo "=== Viewer (Read-Only) ==="
curl ${ALB_URL}:8001/permissions -H "X-User-Category: viewer" \
    | jq '{category, skill_count, skills: .allowed_skills[:3]}'

echo "=== Power User (Full Processing) ==="
curl ${ALB_URL}:8001/permissions -H "X-User-Category: power_user" \
    | jq '{category, skill_count, skills: .allowed_skills[:5]}'

# Show access denied
echo "=== Viewer Denied Processing ==="
curl -X POST ${ALB_URL}:8001/a2a \
    -H "Content-Type: application/json" \
    -H "X-User-Category: viewer" \
    -d '{"jsonrpc":"2.0","id":"1","method":"process_document","params":{"s3_key":"test.pdf"}}' \
    | jq '.error.message'

# Show access granted
echo "=== Power User Allowed Processing ==="
curl -X POST ${ALB_URL}:8001/a2a \
    -H "Content-Type: application/json" \
    -H "X-User-Category: power_user" \
    -d '{"jsonrpc":"2.0","id":"1","method":"process_document","params":{"s3_key":"demo/sample.csv"}}' \
    | jq '.result'
```

### Part 4: Real Document Processing (3 min)

```bash
# Upload sample document
cat > /tmp/demo.csv <<EOF
product,price,quantity
Widget,10.00,100
Gadget,25.00,50
EOF

aws s3 cp /tmp/demo.csv s3://ca-a2a-documents-555043101106/demo/sample.csv

# Process it
RESPONSE=$(curl -s -X POST ${ALB_URL}:8001/a2a \
    -H "Content-Type: application/json" \
    -H "X-User-Category: power_user" \
    -d '{"jsonrpc":"2.0","id":"1","method":"process_document","params":{"s3_key":"demo/sample.csv"}}')

TASK_ID=$(echo $RESPONSE | jq -r '.result.task_id')
echo "Processing started: $TASK_ID"

# Wait and check
sleep 5
curl -s -X POST ${ALB_URL}:8001/a2a \
    -H "Content-Type: application/json" \
    -H "X-User-Category: power_user" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"2\",\"method\":\"get_task_status\",\"params\":{\"task_id\":\"$TASK_ID\"}}" \
    | jq '.result.status'
```

---

## 🔍 Troubleshooting

### Issue: Services not updating

```bash
# Force stop tasks
aws ecs list-tasks --cluster ca-a2a-cluster --region eu-west-3 --query 'taskArns' --output text | \
    xargs -I {} aws ecs stop-task --cluster ca-a2a-cluster --task {} --region eu-west-3
```

### Issue: Cannot connect to ALB

```bash
# Verify ALB URL
aws elbv2 describe-load-balancers --region eu-west-3 \
    --query "LoadBalancers[?contains(LoadBalancerName, 'ca-a2a')].DNSName" \
    --output text

# Check target health
aws elbv2 describe-target-health \
    --target-group-arn $(aws elbv2 describe-target-groups --region eu-west-3 \
        --query "TargetGroups[?contains(TargetGroupName, 'ca-a2a')].TargetGroupArn" \
        --output text | head -1) \
    --region eu-west-3
```

### Issue: Permission endpoint not working

```bash
# Check logs
aws logs tail "/ecs/ca-a2a-orchestrator" --follow --region eu-west-3

# Look for:
# - "Access granted" / "Access denied" messages
# - Error traces
# - Skill filter initialization
```

---

## 📈 Expected Results

| Test | Expected Result |
|------|----------------|
| **Health** | All 4 agents: `status: "healthy"` |
| **Viewer Permissions** | 6 skills (read-only) |
| **Standard User Permissions** | 9 skills (processing) |
| **Power User Permissions** | 15 skills (full pipeline) |
| **Admin Permissions** | 26 skills (all) |
| **Viewer Processing** | Access denied error |
| **Power User Processing** | Success with task_id |
| **Filtered Card (Viewer)** | ~6 skills shown |
| **Filtered Card (Admin)** | ~26 skills shown |

---

## 🎬 One-Liner Tests

```bash
# Quick health check all agents
for port in 8001 8002 8003 8004; do curl -s ${ALB_URL}:${port}/health | jq -r '.agent + ": " + .status'; done

# Compare permissions for all categories
for cat in viewer standard_user power_user analyst auditor admin; do \
    echo -n "$cat: "; \
    curl -s ${ALB_URL}:8001/permissions -H "X-User-Category: $cat" | jq -r '.skill_count + " skills"'; \
done

# Test access control (should see denied then success)
curl -s -X POST ${ALB_URL}:8001/a2a -H "Content-Type: application/json" -H "X-User-Category: viewer" \
    -d '{"jsonrpc":"2.0","id":"1","method":"process_document","params":{"s3_key":"test.pdf"}}' | jq -r '.error.message'; \
curl -s -X POST ${ALB_URL}:8001/a2a -H "Content-Type: application/json" -H "X-User-Category: power_user" \
    -d '{"jsonrpc":"2.0","id":"1","method":"process_document","params":{"s3_key":"test.pdf"}}' | jq -r '.result.status // .error.message'
```

---

## 📚 Related Documentation

- **Full Guide:** [AWS_DEPLOYMENT_WITH_FILTERING.md](./AWS_DEPLOYMENT_WITH_FILTERING.md)
- **Filtering Docs:** [SKILL_FILTERING_GUIDE.md](./SKILL_FILTERING_GUIDE.md)
- **Architecture:** [TECHNICAL_ARCHITECTURE.md](./TECHNICAL_ARCHITECTURE.md)
- **Use Cases:** [AGENT_SKILLS_BY_CLIENT_USE_CASE.md](./AGENT_SKILLS_BY_CLIENT_USE_CASE.md)

---

## ✅ Checklist

- [ ] Environment variables set
- [ ] Ran `./update-aws-deployment.sh`
- [ ] All services healthy
- [ ] Ran `./demo_aws_filtering.sh`
- [ ] All tests passed
- [ ] Ready for demo!

---

**Your deployment is ready!** 🚀

ALB URL: `http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com`
