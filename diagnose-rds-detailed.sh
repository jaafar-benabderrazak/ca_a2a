#!/bin/bash

# Enhanced RDS diagnostic - test cluster creation with all parameters

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

echo "=== Enhanced RDS Cluster Diagnostic ==="
echo ""

# Get all necessary parameters
echo "Step 1: Gathering parameters..."
DB_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id ca-a2a/db-password \
    --region ${AWS_REGION} \
    --query SecretString \
    --output text 2>/dev/null)

RDS_SG=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=${PROJECT_NAME}-rds-sg" \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[0].GroupId' \
    --output text 2>/dev/null)

echo "  DB Password length: ${#DB_PASSWORD}"
echo "  RDS Security Group: $RDS_SG"
echo "  DB Subnet Group: ${PROJECT_NAME}-db-subnet"
echo ""

# Check if subnet group exists
echo "Step 2: Verify DB subnet group..."
aws rds describe-db-subnet-groups \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --region ${AWS_REGION} \
    --query 'DBSubnetGroups[0].{Name:DBSubnetGroupName,VpcId:VpcId,SubnetIds:Subnets[*].SubnetIdentifier}' \
    --output json 2>&1

SUBNET_GROUP_EXISTS=$?
echo "  Subnet group check exit code: $SUBNET_GROUP_EXISTS"
echo ""

# Check available Aurora versions
echo "Step 3: Check if version 15.5 is available..."
AVAILABLE_VERSION=$(aws rds describe-db-engine-versions \
    --engine aurora-postgresql \
    --engine-version 15.5 \
    --region ${AWS_REGION} \
    --query 'DBEngineVersions[0].EngineVersion' \
    --output text 2>&1)

echo "  Version 15.5 available: $AVAILABLE_VERSION"
echo ""

# Try creating with minimal parameters first
echo "Step 4: Test cluster creation with FULL error output..."
echo ""

set -x  # Enable command tracing

aws rds create-db-cluster \
    --db-cluster-identifier ${PROJECT_NAME}-test-cluster-$(date +%s) \
    --engine aurora-postgresql \
    --engine-version 15.5 \
    --master-username postgres \
    --master-user-password "${DB_PASSWORD}" \
    --vpc-security-group-ids ${RDS_SG} \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --backup-retention-period 7 \
    --storage-encrypted \
    --database-name documents \
    --region ${AWS_REGION}

TEST_EXIT_CODE=$?
set +x  # Disable command tracing

echo ""
echo "Test cluster creation exit code: $TEST_EXIT_CODE"
echo ""

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✓ Test cluster creation SUCCEEDED!"
    TEST_CLUSTER_ID="${PROJECT_NAME}-test-cluster-$(date +%s)"
    echo "  Cleaning up test cluster..."
    aws rds delete-db-cluster \
        --db-cluster-identifier ${TEST_CLUSTER_ID} \
        --skip-final-snapshot \
        --region ${AWS_REGION} >/dev/null 2>&1
else
    echo "✗ Test cluster creation FAILED"
    echo ""
    echo "Common issues:"
    echo "  - Subnet group doesn't exist or has issues"
    echo "  - Security group doesn't exist"
    echo "  - Engine version not available"
    echo "  - Insufficient permissions"
    echo "  - Quota limits reached"
fi

echo ""
echo "Step 5: Check for any existing ca-a2a clusters..."
aws rds describe-db-clusters \
    --region ${AWS_REGION} \
    --query 'DBClusters[?contains(DBClusterIdentifier, `ca-a2a`)].{ID:DBClusterIdentifier,Status:Status,Engine:Engine,Version:EngineVersion}' \
    --output table

echo ""
echo "=== Diagnostic Complete ==="

