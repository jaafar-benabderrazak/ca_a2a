#!/bin/bash

AWS_REGION="us-east-1"
CURRENT_VPC="vpc-0839f598c557a60c8"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║     Find Correct RDS Security Group in Current VPC                    ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

echo "Current VPC: $CURRENT_VPC"
echo ""

echo "=== All Security Groups in Current VPC ==="
aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=${CURRENT_VPC}" \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName,Description:Description}' \
    --output table

echo ""
echo "=== Looking for RDS Security Group ==="
RDS_SG=$(aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=${CURRENT_VPC}" "Name=group-name,Values=ca-a2a-rds-sg" \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[0].GroupId' \
    --output text)

if [ "$RDS_SG" != "None" ] && [ ! -z "$RDS_SG" ]; then
    echo "✓ Found RDS Security Group in current VPC: $RDS_SG"
    
    echo ""
    echo "=== Test Aurora Cluster Creation with Correct SG ==="
    
    DB_PASSWORD=$(aws secretsmanager get-secret-value \
        --secret-id ca-a2a/db-password \
        --region ${AWS_REGION} \
        --query SecretString \
        --output text)
    
    echo "Running test cluster creation..."
    aws rds create-db-cluster \
        --db-cluster-identifier ca-a2a-documents-db \
        --engine aurora-postgresql \
        --engine-version 15.15 \
        --master-username postgres \
        --master-user-password "${DB_PASSWORD}" \
        --vpc-security-group-ids ${RDS_SG} \
        --db-subnet-group-name ca-a2a-db-subnet \
        --backup-retention-period 7 \
        --storage-encrypted \
        --database-name documents \
        --enable-cloudwatch-logs-exports '["postgresql"]' \
        --region ${AWS_REGION}
    
    echo ""
    echo "✅ Aurora cluster creation initiated!"
    echo "Cluster will take 8-10 minutes to become available"
else
    echo "✗ RDS Security Group not found in current VPC"
    echo ""
    echo "This means the deployment script didn't complete Phase 2 properly"
    echo "You need to rerun: ./cloudshell-complete-deploy.sh"
fi

