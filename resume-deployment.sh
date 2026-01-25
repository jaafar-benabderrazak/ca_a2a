#!/bin/bash

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║          Resume Deployment - Skip to Current Phase                    ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

# Check what's already deployed
echo "Checking deployment status..."
echo ""

# Check VPC
VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Project,Values=ca-a2a" "Name=cidr-block-association.cidr-block,Values=10.1.0.0/16" \
    --region ${AWS_REGION} \
    --query 'Vpcs[0].VpcId' \
    --output text 2>/dev/null)

if [ "$VPC_ID" != "None" ] && [ ! -z "$VPC_ID" ]; then
    echo "✓ VPC exists: $VPC_ID"
else
    echo "✗ VPC not found - run full deployment"
    exit 1
fi

# Check Security Groups
SG_COUNT=$(aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Project,Values=ca-a2a" \
    --region ${AWS_REGION} \
    --query 'length(SecurityGroups)' \
    --output text)
echo "✓ Security Groups: $SG_COUNT"

# Check Secrets
SECRET_COUNT=$(aws secretsmanager list-secrets \
    --region ${AWS_REGION} \
    --query 'length(SecretList[?starts_with(Name, `ca-a2a`)])' \
    --output text)
echo "✓ Secrets: $SECRET_COUNT"

# Check S3
S3_BUCKET="ca-a2a-documents-555043101106"
aws s3 ls "s3://${S3_BUCKET}" >/dev/null 2>&1 && echo "✓ S3 Bucket: $S3_BUCKET" || echo "✗ S3 Bucket not found"

# Check DB Subnet Group
aws rds describe-db-subnet-groups \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --region ${AWS_REGION} >/dev/null 2>&1 && echo "✓ DB Subnet Group exists" || echo "✗ DB Subnet Group not found"

# Check Aurora Cluster
CLUSTER_STATUS=$(aws rds describe-db-clusters \
    --db-cluster-identifier ${PROJECT_NAME}-documents-db \
    --region ${AWS_REGION} \
    --query 'DBClusters[0].Status' \
    --output text 2>/dev/null)

if [ "$CLUSTER_STATUS" != "None" ] && [ ! -z "$CLUSTER_STATUS" ]; then
    echo "✓ Aurora Cluster: $CLUSTER_STATUS"
    
    if [ "$CLUSTER_STATUS" == "creating" ]; then
        echo ""
        echo "⚠ Aurora cluster is still creating..."
        echo "  Waiting for cluster to become available..."
        aws rds wait db-cluster-available --db-cluster-identifier ${PROJECT_NAME}-documents-db --region ${AWS_REGION}
        echo "  ✓ Cluster is now available!"
    elif [ "$CLUSTER_STATUS" != "available" ]; then
        echo "⚠ Cluster status is $CLUSTER_STATUS - may need intervention"
    fi
else
    echo "✗ Aurora Cluster not found - deployment stopped before RDS creation"
    echo ""
    echo "You can:"
    echo "1. Rerun: ./cloudshell-complete-deploy.sh (will skip existing resources)"
    echo "2. Manually create cluster with: ./create-rds-manually.sh"
    exit 1
fi

# Check Keycloak DB
KC_DB_STATUS=$(aws rds describe-db-instances \
    --db-instance-identifier ${PROJECT_NAME}-keycloak-db \
    --region ${AWS_REGION} \
    --query 'DBInstances[0].DBInstanceStatus' \
    --output text 2>/dev/null)

if [ "$KC_DB_STATUS" != "None" ] && [ ! -z "$KC_DB_STATUS" ]; then
    echo "✓ Keycloak DB: $KC_DB_STATUS"
else
    echo "✗ Keycloak DB not created yet"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║  Recommendation:                                                      ║"
echo "║  Run: ./cloudshell-complete-deploy.sh                                ║"
echo "║  The script will skip already-created resources and continue         ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

