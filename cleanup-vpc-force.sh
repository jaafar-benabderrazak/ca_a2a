#!/bin/bash
set -eo pipefail

# Enhanced VPC Cleanup Script - Force delete remaining resources
# This script targets the specific VPC and aggressively removes all dependencies

VPC_ID="vpc-086392a3eed899f72"
AWS_REGION="eu-west-3"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║          FORCE VPC CLEANUP - vpc-086392a3eed899f72                   ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

echo ""
echo "=== Step 1: Force Delete Lambda Functions ==="
# Search more broadly for Lambda functions
for func in $(aws lambda list-functions --region ${AWS_REGION} --query "Functions[?starts_with(FunctionName, 'ca-a2a') || contains(FunctionName, 's3-processor')].FunctionName" --output text); do
    echo "Deleting Lambda: $func"
    aws lambda delete-function --function-name $func --region ${AWS_REGION} 2>/dev/null || echo "  ⚠ Already deleted or not found"
done

echo ""
echo "=== Step 2: Force Delete ALL RDS Instances ==="
# Delete any RDS instances that might still be around
for instance in $(aws rds describe-db-instances --region ${AWS_REGION} --query "DBInstances[?contains(DBInstanceIdentifier, 'ca-a2a')].DBInstanceIdentifier" --output text); do
    echo "Force deleting RDS instance: $instance"
    aws rds delete-db-instance \
        --db-instance-identifier $instance \
        --skip-final-snapshot \
        --delete-automated-backups \
        --region ${AWS_REGION} 2>/dev/null || echo "  ⚠ Already deleted"
done

# Delete Aurora clusters
for cluster in $(aws rds describe-db-clusters --region ${AWS_REGION} --query "DBClusters[?contains(DBClusterIdentifier, 'ca-a2a')].DBClusterIdentifier" --output text); do
    echo "Force deleting Aurora cluster: $cluster"
    aws rds delete-db-cluster \
        --db-cluster-identifier $cluster \
        --skip-final-snapshot \
        --region ${AWS_REGION} 2>/dev/null || echo "  ⚠ Already deleted"
done

echo ""
echo "=== Waiting 90 seconds for RDS and Lambda to release ENIs ==="
sleep 90

echo ""
echo "=== Step 3: Check ENI status ==="
aws ec2 describe-network-interfaces \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --region ${AWS_REGION} \
    --query 'NetworkInterfaces[*].[NetworkInterfaceId,Status,Description]' \
    --output table

echo ""
echo "=== Step 4: Force delete ENIs if now available ==="
for eni in $(aws ec2 describe-network-interfaces \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --region ${AWS_REGION} \
    --query 'NetworkInterfaces[?Status==`available`].NetworkInterfaceId' \
    --output text); do
    echo "Deleting available ENI: $eni"
    aws ec2 delete-network-interface --network-interface-id $eni --region ${AWS_REGION} 2>/dev/null || echo "  ⚠ Failed to delete"
done

echo ""
echo "=== Step 5: Wait another 120 seconds for remaining ENIs to auto-delete ==="
sleep 120

echo ""
echo "=== Step 6: Remove ALL security group rules first ==="
SG_IDS=$(aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'SecurityGroups[?GroupName!=`default`].GroupId' \
    --output text \
    --region ${AWS_REGION})

for sg in $SG_IDS; do
    echo "Removing all rules from SG: $sg"
    
    # Remove ingress rules
    INGRESS_RULES=$(aws ec2 describe-security-groups \
        --group-ids $sg \
        --region ${AWS_REGION} \
        --query 'SecurityGroups[0].IpPermissions' 2>/dev/null)
    
    if [ "$INGRESS_RULES" != "[]" ] && [ "$INGRESS_RULES" != "null" ]; then
        aws ec2 revoke-security-group-ingress \
            --group-id $sg \
            --ip-permissions "$INGRESS_RULES" \
            --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Ingress rules removed" || echo "  ⚠ No ingress rules or already removed"
    fi
    
    # Remove egress rules
    EGRESS_RULES=$(aws ec2 describe-security-groups \
        --group-ids $sg \
        --region ${AWS_REGION} \
        --query 'SecurityGroups[0].IpPermissionsEgress' 2>/dev/null)
    
    if [ "$EGRESS_RULES" != "[]" ] && [ "$EGRESS_RULES" != "null" ]; then
        aws ec2 revoke-security-group-egress \
            --group-id $sg \
            --ip-permissions "$EGRESS_RULES" \
            --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Egress rules removed" || echo "  ⚠ No egress rules or already removed"
    fi
done

echo ""
echo "=== Step 7: Delete remaining subnets ==="
SUBNET_IDS=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'Subnets[*].SubnetId' \
    --output text \
    --region ${AWS_REGION})

for subnet in $SUBNET_IDS; do
    aws ec2 delete-subnet --subnet-id $subnet --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Deleted $subnet" || echo "  ✗ Failed $subnet"
done

echo ""
echo "=== Step 8: Delete remaining security groups ==="
SG_IDS=$(aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'SecurityGroups[?GroupName!=`default`].GroupId' \
    --output text \
    --region ${AWS_REGION})

for sg in $SG_IDS; do
    aws ec2 delete-security-group --group-id $sg --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Deleted $sg" || echo "  ✗ Failed $sg"
done

echo ""
echo "=== Step 9: Delete Internet Gateway ==="
IGW_ID=$(aws ec2 describe-internet-gateways \
    --filters "Name=attachment.vpc-id,Values=${VPC_ID}" \
    --query 'InternetGateways[0].InternetGatewayId' \
    --output text \
    --region ${AWS_REGION})

if [ "$IGW_ID" != "None" ] && [ ! -z "$IGW_ID" ]; then
    echo "Detaching and deleting IGW: $IGW_ID"
    aws ec2 detach-internet-gateway \
        --internet-gateway-id ${IGW_ID} \
        --vpc-id ${VPC_ID} \
        --region ${AWS_REGION} 2>/dev/null || echo "  ⚠ Already detached"
    aws ec2 delete-internet-gateway \
        --internet-gateway-id ${IGW_ID} \
        --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Deleted" || echo "  ✗ Failed"
fi

echo ""
echo "=== Step 10: Final VPC deletion attempt ==="
if aws ec2 delete-vpc --vpc-id ${VPC_ID} --region ${AWS_REGION} 2>/dev/null; then
    echo "✅ VPC DELETED SUCCESSFULLY!"
else
    echo "❌ VPC deletion still failed"
    echo ""
    echo "Checking what's still blocking..."
    
    echo ""
    echo "Network Interfaces:"
    aws ec2 describe-network-interfaces \
        --filters "Name=vpc-id,Values=${VPC_ID}" \
        --region ${AWS_REGION} \
        --query 'NetworkInterfaces[*].[NetworkInterfaceId,Status,Description]' \
        --output table
    
    echo ""
    echo "💡 If RDS ENIs are still shown, you need to:"
    echo "   1. Go to AWS Console → RDS"
    echo "   2. Verify all databases are DELETED (not just 'deleting')"
    echo "   3. Wait 5 minutes for complete deletion"
    echo "   4. Then run: aws ec2 delete-vpc --vpc-id ${VPC_ID} --region ${AWS_REGION}"
    echo ""
    echo "💡 If Lambda ENIs persist:"
    echo "   1. Go to AWS Console → Lambda"
    echo "   2. Verify ca-a2a-s3-processor is completely deleted"
    echo "   3. Check CloudFormation for any stacks that might own these resources"
    echo "   4. ENIs should auto-delete within 10-15 minutes after Lambda deletion"
fi

