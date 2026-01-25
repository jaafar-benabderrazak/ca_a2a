#!/bin/bash

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║         Fix DB Subnet Group - VPC Mismatch Resolution                ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

echo "Step 1: Find all ca-a2a VPCs"
aws ec2 describe-vpcs \
    --filters "Name=tag:Project,Values=ca-a2a" \
    --region ${AWS_REGION} \
    --query 'Vpcs[*].{VpcId:VpcId,CidrBlock:CidrBlock,Name:Tags[?Key==`Name`].Value|[0]}' \
    --output table

echo ""
echo "Step 2: Find all ca-a2a subnets and their VPCs"
aws ec2 describe-subnets \
    --filters "Name=tag:Project,Values=ca-a2a" \
    --region ${AWS_REGION} \
    --query 'Subnets[*].{SubnetId:SubnetId,VpcId:VpcId,CIDR:CidrBlock,Name:Tags[?Key==`Name`].Value|[0]}' \
    --output table

echo ""
echo "Step 3: Identify the CORRECT VPC (10.1.0.0/16 from latest deployment)"
VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Project,Values=ca-a2a" "Name=cidr-block-association.cidr-block,Values=10.1.0.0/16" \
    --region ${AWS_REGION} \
    --query 'Vpcs[0].VpcId' \
    --output text)

echo "✓ Correct VPC ID: $VPC_ID"

echo ""
echo "Step 4: Get private subnets from correct VPC"
PRIVATE_SUBNET_1=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Name,Values=ca-a2a-private-subnet-1" \
    --region ${AWS_REGION} \
    --query 'Subnets[0].SubnetId' \
    --output text)

PRIVATE_SUBNET_2=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Name,Values=ca-a2a-private-subnet-2" \
    --region ${AWS_REGION} \
    --query 'Subnets[0].SubnetId' \
    --output text)

echo "✓ Private Subnet 1: $PRIVATE_SUBNET_1"
echo "✓ Private Subnet 2: $PRIVATE_SUBNET_2"

echo ""
echo "Step 5: Delete existing DB subnet group (if any)"
aws rds delete-db-subnet-group \
    --db-subnet-group-name ca-a2a-db-subnet \
    --region ${AWS_REGION} 2>/dev/null && echo "✓ Old subnet group deleted" || echo "• No existing subnet group to delete"

echo ""
echo "Step 6: Create DB subnet group with correct subnets"
aws rds create-db-subnet-group \
    --db-subnet-group-name ca-a2a-db-subnet \
    --db-subnet-group-description "DB subnet group for ca-a2a" \
    --subnet-ids $PRIVATE_SUBNET_1 $PRIVATE_SUBNET_2 \
    --region ${AWS_REGION}

echo ""
echo "Step 7: Verify DB subnet group"
aws rds describe-db-subnet-groups \
    --db-subnet-group-name ca-a2a-db-subnet \
    --region ${AWS_REGION} \
    --query 'DBSubnetGroups[0].{Name:DBSubnetGroupName,VpcId:VpcId,Subnets:Subnets[*].SubnetIdentifier}' \
    --output table

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║  ✅ DB Subnet Group Fixed!                                            ║"
echo "║  Now you can continue with: ./cloudshell-complete-deploy.sh          ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

