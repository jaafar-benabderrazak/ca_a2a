#!/bin/bash
# Test ALB Configuration - Run in CloudShell

export AWS_REGION=eu-west-3

echo "========================================="
echo "  ALB TROUBLESHOOTING"
echo "========================================="
echo ""

echo "=== Step 1: Test Targets Directly (Bypass ALB) ==="
echo "Note: This will only work if CloudShell is in same VPC"
echo ""
echo "Testing 10.0.20.158:8001..."
timeout 5 curl -s http://10.0.20.158:8001/health && echo "  ✓ Target 1 works!" || echo "  ✗ Target 1 failed (expected - different VPC)"
echo ""
echo "Testing 10.0.10.75:8001..."
timeout 5 curl -s http://10.0.10.75:8001/health && echo "  ✓ Target 2 works!" || echo "  ✗ Target 2 failed (expected - different VPC)"
echo ""

echo "=== Step 2: Check ALB Listener Configuration ==="
aws elbv2 describe-listeners \
  --load-balancer-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:loadbalancer/app/ca-a2a-alb/5413cf0f14cbc0db \
  --region $AWS_REGION \
  --query 'Listeners[*].[ListenerArn,Port,Protocol,DefaultActions[0].Type,DefaultActions[0].TargetGroupArn]' \
  --output table

echo ""
echo "=== Step 3: Verify Target Group Configuration ==="
aws elbv2 describe-target-groups \
  --target-group-arns arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region $AWS_REGION \
  --query 'TargetGroups[0].[Port,Protocol,HealthCheckPath,HealthCheckPort,Matcher.HttpCode]' \
  --output table

echo ""
echo "=== Step 4: Check ALB Attributes ==="
aws elbv2 describe-load-balancers \
  --names ca-a2a-alb \
  --region $AWS_REGION \
  --query 'LoadBalancers[0].[DNSName,Scheme,State.Code,VpcId]' \
  --output table

echo ""
echo "=== Step 5: Test ALB with Verbose Curl ==="
echo "Testing with full curl output..."
curl -v -m 10 http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health 2>&1

echo ""
echo ""
echo "=== Step 6: Check Recent ALB Access Logs ==="
echo "Looking for ALB bucket..."
BUCKET=$(aws s3 ls | grep -i "alb\|log" | head -1 | awk '{print $3}')
if [ -n "$BUCKET" ]; then
  echo "Found bucket: $BUCKET"
  echo "Recent logs:"
  aws s3 ls s3://$BUCKET/AWSLogs/ --recursive | tail -5
else
  echo "No ALB log bucket found (logs might not be enabled)"
fi

echo ""
echo "========================================="
echo "  DIAGNOSIS"
echo "========================================="

