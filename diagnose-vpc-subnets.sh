#!/bin/bash

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

echo "=== VPC and Subnet Diagnostic ==="
echo ""

echo "Step 1: Find all ca-a2a VPCs"
aws ec2 describe-vpcs \
    --filters "Name=tag:Project,Values=ca-a2a" \
    --region ${AWS_REGION} \
    --query 'Vpcs[*].{VpcId:VpcId,CidrBlock:CidrBlock,Name:Tags[?Key==`Name`].Value|[0],State:State}' \
    --output table

echo ""
echo "Step 2: Find all ca-a2a subnets and their VPCs"
aws ec2 describe-subnets \
    --filters "Name=tag:Project,Values=ca-a2a" \
    --region ${AWS_REGION} \
    --query 'Subnets[*].{SubnetId:SubnetId,VpcId:VpcId,CIDR:CidrBlock,AZ:AvailabilityZone,Name:Tags[?Key==`Name`].Value|[0]}' \
    --output table

echo ""
echo "Step 3: Find the CURRENT VPC (most recently used by deployment)"
CURRENT_VPC=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Project,Values=ca-a2a" \
    --region ${AWS_REGION} \
    --query 'Vpcs[0].VpcId' \
    --output text)

echo "Current VPC: $CURRENT_VPC"

echo ""
echo "Step 4: Find subnets in the CURRENT VPC"
aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${CURRENT_VPC}" "Name=tag:Project,Values=ca-a2a" \
    --region ${AWS_REGION} \
    --query 'Subnets[*].{SubnetId:SubnetId,CIDR:CidrBlock,AZ:AvailabilityZone,Name:Tags[?Key==`Name`].Value|[0],Type:Tags[?Key==`Type`].Value|[0]}' \
    --output table

echo ""
echo "Step 5: Get correct private subnet IDs for current VPC"
PRIVATE_SUBNETS=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${CURRENT_VPC}" "Name=tag:Project,Values=ca-a2a" "Name=tag:Type,Values=private" \
    --region ${AWS_REGION} \
    --query 'Subnets[*].SubnetId' \
    --output text)

echo "Private subnets in current VPC: $PRIVATE_SUBNETS"

echo ""
echo "=== Recommended Fix ==="
echo ""
echo "Use these subnet IDs for the DB subnet group:"
for subnet in $PRIVATE_SUBNETS; do
    echo "  - $subnet"
done

echo ""
echo "Command to create DB subnet group:"
echo ""
echo "aws rds create-db-subnet-group \\"
echo "  --db-subnet-group-name ca-a2a-db-subnet \\"
echo "  --db-subnet-group-description \"DB subnet group for ca-a2a\" \\"
echo "  --subnet-ids $PRIVATE_SUBNETS \\"
echo "  --region us-east-1"

