#!/bin/bash
# Fix ALB - Move to Public Subnets with Internet Gateway
# Run in CloudShell

export AWS_REGION=eu-west-3

echo "========================================="
echo "  FIXING ALB SUBNET CONFIGURATION"
echo "========================================="
echo ""

# Get VPC ID
VPC_ID=$(aws ec2 describe-vpcs \
  --filters "Name=tag:Name,Values=ca-a2a-vpc" \
  --region $AWS_REGION \
  --query 'Vpcs[0].VpcId' \
  --output text)

echo "VPC: $VPC_ID"

# Find subnets with Internet Gateway routes (= public subnets)
echo ""
echo "=== Finding Public Subnets ==="

ALL_SUBNETS=$(aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --region $AWS_REGION \
  --query 'Subnets[*].SubnetId' \
  --output text)

PUBLIC_SUBNETS=()

for subnet in $ALL_SUBNETS; do
  # Get route table for this subnet
  RT=$(aws ec2 describe-route-tables \
    --filters "Name=association.subnet-id,Values=$subnet" \
    --region $AWS_REGION \
    --query 'RouteTables[0].RouteTableId' \
    --output text)
  
  # Check if it has IGW route
  HAS_IGW=$(aws ec2 describe-route-tables \
    --route-table-ids $RT \
    --region $AWS_REGION \
    --query 'RouteTables[0].Routes[?GatewayId!=`local` && starts_with(GatewayId, `igw-`)] | [0].GatewayId' \
    --output text 2>/dev/null)
  
  if [ "$HAS_IGW" != "None" ] && [ -n "$HAS_IGW" ]; then
    echo "✓ Public: $subnet (Route Table: $RT, IGW: $HAS_IGW)"
    PUBLIC_SUBNETS+=($subnet)
  fi
done

echo ""
echo "Found ${#PUBLIC_SUBNETS[@]} public subnets"

if [ ${#PUBLIC_SUBNETS[@]} -lt 2 ]; then
  echo "❌ ERROR: Need at least 2 public subnets in different AZs for ALB"
  echo ""
  echo "SOLUTION: Create public subnets or add Internet Gateway routes"
  exit 1
fi

# Use first 2 public subnets
PUBLIC_SUBNET_1=${PUBLIC_SUBNETS[0]}
PUBLIC_SUBNET_2=${PUBLIC_SUBNETS[1]}

echo "Will use:"
echo "  - $PUBLIC_SUBNET_1"
echo "  - $PUBLIC_SUBNET_2"

# Update ALB subnets
echo ""
echo "=== Updating ALB Subnet Configuration ==="
aws elbv2 set-subnets \
  --load-balancer-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:loadbalancer/app/ca-a2a-alb/3c05d16b10706799 \
  --subnets $PUBLIC_SUBNET_1 $PUBLIC_SUBNET_2 \
  --region $AWS_REGION

echo "✓ ALB subnets updated!"

# Get new DNS (should be same but check)
NEW_DNS=$(aws elbv2 describe-load-balancers \
  --load-balancer-arns arn:aws:elasticloadbalancing:eu-west-3:555043101106:loadbalancer/app/ca-a2a-alb/3c05d16b10706799 \
  --region $AWS_REGION \
  --query 'LoadBalancers[0].DNSName' \
  --output text)

echo ""
echo "ALB DNS: $NEW_DNS"
echo ""
echo "Waiting 20 seconds for changes to propagate..."
sleep 20

echo ""
echo "=== Testing ALB ==="
curl -s -m 10 http://$NEW_DNS/health | jq '.'

echo ""
echo "========================================="
echo "  FIX COMPLETE!"
echo "========================================="

