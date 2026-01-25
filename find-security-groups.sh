#!/bin/bash

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"
VPC_ID="vpc-0839f598c557a60c8"  # From your output

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║     Find Actual Security Groups                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

echo "=== All Security Groups for ca-a2a project ==="
aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Project,Values=ca-a2a" \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName,Tag:Tags[?Key==`Name`].Value|[0]}' \
    --output table

echo ""
echo "=== Searching for RDS-related security group ==="
RDS_SG=$(aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[?contains(GroupName, `rds`) || contains(Tags[?Key==`Name`].Value|[0], `rds`)].GroupId' \
    --output text)

if [ ! -z "$RDS_SG" ] && [ "$RDS_SG" != "None" ]; then
    echo "✓ Found RDS Security Group: $RDS_SG"
else
    echo "✗ No RDS security group found"
    echo ""
    echo "Looking for security group with DB access (port 5432)..."
    aws ec2 describe-security-groups \
        --filters "Name=vpc-id,Values=${VPC_ID}" \
        --region ${AWS_REGION} \
        --query 'SecurityGroups[?length(IpPermissions[?FromPort==`5432`]) > `0`].{ID:GroupId,Name:GroupName,Tag:Tags[?Key==`Name`].Value|[0]}' \
        --output table
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║  If RDS SG is missing, the deployment stopped before Phase 2         ║"
echo "║  Rerun: ./cloudshell-complete-deploy.sh                              ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

