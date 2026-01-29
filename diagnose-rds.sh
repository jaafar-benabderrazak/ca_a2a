#!/bin/bash

# Diagnostic script for RDS cluster creation issues

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

echo "=== RDS Cluster Diagnostic ==="
echo ""

echo "Step 1: Check for existing Aurora clusters"
aws rds describe-db-clusters \
    --region ${AWS_REGION} \
    --query 'DBClusters[?contains(DBClusterIdentifier, `ca-a2a`)].{ID:DBClusterIdentifier,Status:Status,Engine:Engine}' \
    --output table

echo ""
echo "Step 2: Check for existing DB instances"
aws rds describe-db-instances \
    --region ${AWS_REGION} \
    --query 'DBInstances[?contains(DBInstanceIdentifier, `ca-a2a`)].{ID:DBInstanceIdentifier,Status:DBInstanceStatus,Engine:Engine}' \
    --output table

echo ""
echo "Step 3: Check DB subnet groups"
aws rds describe-db-subnet-groups \
    --region ${AWS_REGION} \
    --query 'DBSubnetGroups[?contains(DBSubnetGroupName, `ca-a2a`)].{Name:DBSubnetGroupName,VpcId:VpcId,SubnetCount:length(Subnets)}' \
    --output table

echo ""
echo "Step 4: Try creating Aurora cluster with verbose output"
echo "Testing cluster creation: ${PROJECT_NAME}-documents-db"

# Get DB password from secrets
DB_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id ca-a2a/db-password \
    --region ${AWS_REGION} \
    --query SecretString \
    --output text)

# Get RDS SG
RDS_SG=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=${PROJECT_NAME}-rds-sg" \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[0].GroupId' \
    --output text)

echo "  RDS Security Group: $RDS_SG"
echo "  DB Subnet Group: ${PROJECT_NAME}-db-subnet"
echo ""

echo "Attempting to create cluster..."
aws rds create-db-cluster \
    --db-cluster-identifier ${PROJECT_NAME}-documents-db \
    --engine aurora-postgresql \
    --engine-version 15.4 \
    --master-username postgres \
    --master-user-password "${DB_PASSWORD}" \
    --vpc-security-group-ids ${RDS_SG} \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --backup-retention-period 7 \
    --storage-encrypted \
    --database-name documents \
    --enable-cloudwatch-logs-exports '["postgresql"]' \
    --region ${AWS_REGION} 2>&1

EXIT_CODE=$?
echo ""
echo "Exit code: $EXIT_CODE"

if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ Cluster creation succeeded"
elif [ $EXIT_CODE -eq 254 ] || [ $EXIT_CODE -eq 255 ]; then
    echo "⚠ Cluster may already exist (common exit codes)"
else
    echo "✗ Cluster creation failed with exit code $EXIT_CODE"
fi

echo ""
echo "Step 5: Check if cluster exists now"
aws rds describe-db-clusters \
    --db-cluster-identifier ${PROJECT_NAME}-documents-db \
    --region ${AWS_REGION} \
    --query 'DBClusters[0].{ID:DBClusterIdentifier,Status:Status,Endpoint:Endpoint}' \
    --output table 2>&1

echo ""
echo "=== Diagnostic Complete ==="

