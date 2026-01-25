#!/bin/bash

set -x  # Enable verbose output

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║     Aurora Cluster Creation Diagnostic                                ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

# Get the DB password from Secrets Manager
echo "=== Step 1: Get DB Password from Secrets Manager ==="
DB_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id ${PROJECT_NAME}/db-password \
    --region ${AWS_REGION} \
    --query SecretString \
    --output text 2>&1)

if [ $? -ne 0 ]; then
    echo "✗ Failed to get DB password: $DB_PASSWORD"
    exit 1
fi
echo "✓ DB Password retrieved (length: ${#DB_PASSWORD})"

# Get RDS Security Group
echo ""
echo "=== Step 2: Get RDS Security Group ==="
RDS_SG=$(aws ec2 describe-security-groups \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-rds-sg" \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[0].GroupId' \
    --output text 2>&1)

if [ "$RDS_SG" == "None" ] || [ -z "$RDS_SG" ]; then
    echo "✗ RDS Security Group not found"
    exit 1
fi
echo "✓ RDS Security Group: $RDS_SG"

# Verify DB Subnet Group
echo ""
echo "=== Step 3: Verify DB Subnet Group ==="
DB_SUBNET_STATUS=$(aws rds describe-db-subnet-groups \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --region ${AWS_REGION} \
    --query 'DBSubnetGroups[0].SubnetGroupStatus' \
    --output text 2>&1)

if [ "$DB_SUBNET_STATUS" != "Complete" ]; then
    echo "✗ DB Subnet Group not ready: $DB_SUBNET_STATUS"
    exit 1
fi
echo "✓ DB Subnet Group is Complete"

# Check Aurora version availability
echo ""
echo "=== Step 4: Verify Aurora PostgreSQL 15.3 is available ==="
VERSION_CHECK=$(aws rds describe-db-engine-versions \
    --engine aurora-postgresql \
    --engine-version 15.3 \
    --region ${AWS_REGION} \
    --query 'DBEngineVersions[0].EngineVersion' \
    --output text 2>&1)

if [ "$VERSION_CHECK" == "None" ] || [ -z "$VERSION_CHECK" ]; then
    echo "✗ Aurora PostgreSQL 15.3 not available"
    echo "Available versions:"
    aws rds describe-db-engine-versions \
        --engine aurora-postgresql \
        --region ${AWS_REGION} \
        --query 'DBEngineVersions[?starts_with(EngineVersion, `15.`)].EngineVersion' \
        --output table
    exit 1
fi
echo "✓ Aurora PostgreSQL 15.3 is available"

# Check RDS quotas
echo ""
echo "=== Step 5: Check RDS Service Quotas ==="
CLUSTER_QUOTA=$(aws service-quotas get-service-quota \
    --service-code rds \
    --quota-code L-952B80B8 \
    --region ${AWS_REGION} \
    --query 'Quota.Value' \
    --output text 2>/dev/null || echo "Unable to check")
echo "DB Clusters quota: $CLUSTER_QUOTA"

CURRENT_CLUSTERS=$(aws rds describe-db-clusters \
    --region ${AWS_REGION} \
    --query 'length(DBClusters)' \
    --output text)
echo "Current DB Clusters: $CURRENT_CLUSTERS"

# Test cluster creation with FULL error output
echo ""
echo "=== Step 6: Attempt to Create Aurora Cluster (WITH FULL OUTPUT) ==="
echo "This will show the exact error if it fails..."
echo ""

set +e  # Don't exit on error
CREATE_OUTPUT=$(aws rds create-db-cluster \
    --db-cluster-identifier ${PROJECT_NAME}-documents-db \
    --engine aurora-postgresql \
    --engine-version 15.3 \
    --master-username postgres \
    --master-user-password "${DB_PASSWORD}" \
    --vpc-security-group-ids ${RDS_SG} \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --backup-retention-period 7 \
    --storage-encrypted \
    --database-name documents \
    --enable-cloudwatch-logs-exports '["postgresql"]' \
    --region ${AWS_REGION} 2>&1)

CREATE_EXIT_CODE=$?
set -e

echo "Exit code: $CREATE_EXIT_CODE"
echo ""
echo "Output:"
echo "$CREATE_OUTPUT"
echo ""

if [ $CREATE_EXIT_CODE -eq 0 ]; then
    echo "✓ Aurora cluster creation initiated successfully!"
    CLUSTER_ID=$(echo "$CREATE_OUTPUT" | jq -r '.DBCluster.DBClusterIdentifier' 2>/dev/null || echo "unknown")
    echo "Cluster ID: $CLUSTER_ID"
else
    echo "✗ Aurora cluster creation FAILED"
    echo ""
    echo "Common issues:"
    echo "1. Insufficient permissions (check IAM role)"
    echo "2. Service quota exceeded (check quotas above)"
    echo "3. Invalid parameter combination"
    echo "4. Network configuration issue"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║  Diagnostic Complete                                                  ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

