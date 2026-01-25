#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# Resume CA-A2A Deployment - Wait for Aurora and Continue
# ══════════════════════════════════════════════════════════════════════════════

set -e

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║            CA-A2A Deployment Resumption Script                        ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# Step 1: Check Aurora Cluster Status
# ══════════════════════════════════════════════════════════════════════════════

echo "▸ Checking Aurora cluster status..."
CLUSTER_STATUS=$(aws rds describe-db-clusters \
    --db-cluster-identifier ${PROJECT_NAME}-documents-db \
    --region ${AWS_REGION} \
    --query 'DBClusters[0].Status' \
    --output text 2>/dev/null || echo "not-found")

echo "  Cluster Status: ${CLUSTER_STATUS}"

if [ "$CLUSTER_STATUS" == "creating" ]; then
    echo ""
    echo "⏳ Aurora cluster is still creating..."
    echo "   This typically takes 8-10 minutes."
    echo ""
    echo "   Monitoring status (will check every 30 seconds)..."
    echo ""
    
    while [ "$CLUSTER_STATUS" == "creating" ]; do
        sleep 30
        CLUSTER_STATUS=$(aws rds describe-db-clusters \
            --db-cluster-identifier ${PROJECT_NAME}-documents-db \
            --region ${AWS_REGION} \
            --query 'DBClusters[0].Status' \
            --output text)
        echo "   $(date +%H:%M:%S) - Status: ${CLUSTER_STATUS}"
    done
fi

if [ "$CLUSTER_STATUS" != "available" ]; then
    echo "✗ Aurora cluster is not available yet (status: ${CLUSTER_STATUS})"
    echo "  Please wait and try again later."
    exit 1
fi

echo "✓ Aurora cluster is available!"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# Step 2: Get Configuration from Existing Resources
# ══════════════════════════════════════════════════════════════════════════════

echo "▸ Gathering configuration from existing resources..."

VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Project,Values=${PROJECT_NAME}" \
    --region ${AWS_REGION} \
    --query 'Vpcs[0].VpcId' \
    --output text)

RDS_SG=$(aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=group-name,Values=${PROJECT_NAME}-rds-sg" \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[0].GroupId' \
    --output text)

DB_SUBNET_GROUP=$(aws rds describe-db-subnet-groups \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --region ${AWS_REGION} \
    --query 'DBSubnetGroups[0].DBSubnetGroupName' \
    --output text 2>/dev/null || echo "not-found")

echo "  VPC: ${VPC_ID}"
echo "  RDS SG: ${RDS_SG}"
echo "  DB Subnet Group: ${DB_SUBNET_GROUP}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# Step 3: Create Aurora Instance
# ══════════════════════════════════════════════════════════════════════════════

echo "▸ Creating Aurora instance (db.t3.medium)..."
INSTANCE_STATUS=$(aws rds describe-db-instances \
    --db-instance-identifier ${PROJECT_NAME}-documents-db-instance-1 \
    --region ${AWS_REGION} \
    --query 'DBInstances[0].DBInstanceStatus' \
    --output text 2>/dev/null || echo "not-found")

if [ "$INSTANCE_STATUS" == "not-found" ]; then
    aws rds create-db-instance \
        --db-instance-identifier ${PROJECT_NAME}-documents-db-instance-1 \
        --db-instance-class db.t3.medium \
        --engine aurora-postgresql \
        --db-cluster-identifier ${PROJECT_NAME}-documents-db \
        --no-publicly-accessible \
        --region ${AWS_REGION}
    
    echo "✓ Aurora instance creation initiated (2-3 minutes)"
else
    echo "✓ Aurora instance already exists (status: ${INSTANCE_STATUS})"
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# Step 4: Create Keycloak Database
# ══════════════════════════════════════════════════════════════════════════════

echo "▸ Creating Keycloak database (PostgreSQL 16.6)..."
KEYCLOAK_STATUS=$(aws rds describe-db-instances \
    --db-instance-identifier ${PROJECT_NAME}-keycloak-db \
    --region ${AWS_REGION} \
    --query 'DBInstances[0].DBInstanceStatus' \
    --output text 2>/dev/null || echo "not-found")

if [ "$KEYCLOAK_STATUS" == "not-found" ]; then
    KEYCLOAK_PASSWORD=$(aws secretsmanager get-secret-value \
        --secret-id ${PROJECT_NAME}/keycloak-db-password \
        --region ${AWS_REGION} \
        --query SecretString \
        --output text)
    
    aws rds create-db-instance \
        --db-instance-identifier ${PROJECT_NAME}-keycloak-db \
        --db-instance-class db.t3.small \
        --engine postgres \
        --engine-version 16.6 \
        --master-username postgres \
        --master-user-password "${KEYCLOAK_PASSWORD}" \
        --allocated-storage 20 \
        --storage-type gp3 \
        --vpc-security-group-ids ${RDS_SG} \
        --db-subnet-group-name ${DB_SUBNET_GROUP} \
        --backup-retention-period 7 \
        --storage-encrypted \
        --db-name keycloak \
        --no-publicly-accessible \
        --region ${AWS_REGION}
    
    echo "✓ Keycloak database creation initiated (3-5 minutes)"
else
    echo "✓ Keycloak database already exists (status: ${KEYCLOAK_STATUS})"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo ""
echo "✅ Database creation in progress!"
echo ""
echo "Next steps:"
echo "  1. Wait for databases to become available (~5-10 minutes total)"
echo "  2. Run: ./cloudshell-complete-deploy.sh"
echo "     (It will skip already-created resources and continue with ECS)"
echo ""
echo "To monitor status:"
echo "  ./check-deployment-health.sh"
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
