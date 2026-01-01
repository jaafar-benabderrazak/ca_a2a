#!/bin/bash
# Find and Fix ALB Issues - Run in CloudShell

export AWS_REGION=eu-west-3

echo "========================================="
echo "  FINDING ACTUAL ALB CONFIGURATION"
echo "========================================="
echo ""

echo "=== Step 1: List ALL Load Balancers ==="
aws elbv2 describe-load-balancers \
  --region $AWS_REGION \
  --query 'LoadBalancers[*].[LoadBalancerName,DNSName,LoadBalancerArn,State.Code,Scheme]' \
  --output table

echo ""
echo "=== Step 2: Get ALB by DNS Name ==="
ALB_INFO=$(aws elbv2 describe-load-balancers \
  --region $AWS_REGION \
  --query 'LoadBalancers[?DNSName==`ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com`]' \
  --output json)

if [ "$ALB_INFO" == "[]" ]; then
  echo "❌ ALB with DNS 'ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com' NOT FOUND!"
  echo ""
  echo "This means the ALB was deleted or never existed with this DNS."
  echo "We need to create a new ALB!"
else
  echo "✓ Found ALB!"
  echo "$ALB_INFO" | jq '.'
  
  # Get the correct ARN
  CORRECT_ARN=$(echo "$ALB_INFO" | jq -r '.[0].LoadBalancerArn')
  echo ""
  echo "Correct ARN: $CORRECT_ARN"
  
  # Check listeners
  echo ""
  echo "=== Step 3: Check Listeners ==="
  aws elbv2 describe-listeners \
    --load-balancer-arn $CORRECT_ARN \
    --region $AWS_REGION \
    --output table
fi

echo ""
echo "=== Step 4: Check if ALB Name 'ca-a2a-alb' Exists ==="
ALB_BY_NAME=$(aws elbv2 describe-load-balancers \
  --names ca-a2a-alb \
  --region $AWS_REGION \
  --output json 2>&1)

if echo "$ALB_BY_NAME" | grep -q "LoadBalancerNotFound"; then
  echo "❌ ALB named 'ca-a2a-alb' does NOT exist!"
  echo ""
  echo "SOLUTION: We need to create the ALB!"
else
  echo "✓ Found ALB by name!"
  echo "$ALB_BY_NAME" | jq -r '.LoadBalancers[0] | {Name:.LoadBalancerName, DNS:.DNSName, ARN:.LoadBalancerArn, Scheme:.Scheme, State:.State.Code}'
fi

echo ""
echo "========================================="
echo "  DIAGNOSIS COMPLETE"
echo "========================================="

