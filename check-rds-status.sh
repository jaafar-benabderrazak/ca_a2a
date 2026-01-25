#!/bin/bash

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║          RDS Cluster Status Check                                     ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

echo "=== Step 1: Check Aurora Cluster Status ==="
aws rds describe-db-clusters \
    --db-cluster-identifier ${PROJECT_NAME}-documents-db \
    --region ${AWS_REGION} \
    --query 'DBClusters[0].{ID:DBClusterIdentifier,Status:Status,Engine:Engine,Version:EngineVersion,Endpoint:Endpoint}' \
    --output table 2>&1

CLUSTER_STATUS=$?

if [ $CLUSTER_STATUS -ne 0 ]; then
    echo ""
    echo "✗ Cluster does not exist yet or failed to create"
    echo ""
    echo "=== Checking AWS CloudWatch Events for errors ==="
    aws rds describe-events \
        --source-identifier ${PROJECT_NAME}-documents-db \
        --source-type db-cluster \
        --region ${AWS_REGION} \
        --duration 60 \
        --query 'Events[*].{Time:Date,Message:Message}' \
        --output table 2>/dev/null || echo "No events found"
else
    echo ""
    echo "✓ Cluster exists"
    
    # Get detailed status
    CLUSTER_STATE=$(aws rds describe-db-clusters \
        --db-cluster-identifier ${PROJECT_NAME}-documents-db \
        --region ${AWS_REGION} \
        --query 'DBClusters[0].Status' \
        --output text)
    
    echo "Current Status: $CLUSTER_STATE"
    
    case $CLUSTER_STATE in
        "creating")
            echo "• Cluster is still being created (this can take 8-10 minutes)"
            echo "• Wait and check again, or let the deployment script continue"
            ;;
        "available")
            echo "✓ Cluster is ready!"
            ;;
        "failed"|"failed-to-create")
            echo "✗ Cluster creation failed"
            echo ""
            echo "Recent events:"
            aws rds describe-events \
                --source-identifier ${PROJECT_NAME}-documents-db \
                --source-type db-cluster \
                --region ${AWS_REGION} \
                --duration 60 \
                --query 'Events[*].{Time:Date,Message:Message}' \
                --output table
            ;;
        *)
            echo "• Status: $CLUSTER_STATE"
            ;;
    esac
fi

echo ""
echo "=== Step 2: Check Aurora Instances ==="
aws rds describe-db-instances \
    --db-instance-identifier ${PROJECT_NAME}-documents-db-instance-1 \
    --region ${AWS_REGION} \
    --query 'DBInstances[0].{ID:DBInstanceIdentifier,Status:DBInstanceStatus,Class:DBInstanceClass,AZ:AvailabilityZone}' \
    --output table 2>&1 || echo "Instance not created yet"

echo ""
echo "=== Step 3: Check Keycloak DB ==="
aws rds describe-db-instances \
    --db-instance-identifier ${PROJECT_NAME}-keycloak-db \
    --region ${AWS_REGION} \
    --query 'DBInstances[0].{ID:DBInstanceIdentifier,Status:DBInstanceStatus,Endpoint:Endpoint.Address}' \
    --output table 2>&1 || echo "Keycloak DB not created yet"

echo ""
echo "=== Step 4: Check for RDS Events (last 60 minutes) ==="
aws rds describe-events \
    --region ${AWS_REGION} \
    --duration 60 \
    --query 'Events[?contains(SourceIdentifier, `ca-a2a`)].{Time:Date,Source:SourceIdentifier,Message:Message}' \
    --output table 2>/dev/null || echo "No events found"

echo ""
echo "=== Step 5: Verify DB Subnet Group ==="
aws rds describe-db-subnet-groups \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --region ${AWS_REGION} \
    --query 'DBSubnetGroups[0].{Name:DBSubnetGroupName,VpcId:VpcId,Status:SubnetGroupStatus,Subnets:length(Subnets)}' \
    --output table

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║  Next Steps:                                                          ║"
echo "║  - If cluster is 'creating': Wait 5-10 minutes and rerun this script ║"
echo "║  - If cluster is 'available': Continue with deployment script        ║"
echo "║  - If cluster 'failed': Review events above and troubleshoot         ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

