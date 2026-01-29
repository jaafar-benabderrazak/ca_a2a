#!/bin/bash
set -eo pipefail

# Final VPC Cleanup Script - Wait for RDS and complete cleanup
VPC_ID="vpc-086392a3eed899f72"
AWS_REGION="eu-west-3"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║          FINAL VPC CLEANUP - Waiting for RDS deletion                ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

echo ""
echo "=== Step 1: Check RDS deletion status ==="
RDS_COUNT=$(aws rds describe-db-clusters --region ${AWS_REGION} --query "length(DBClusters[?contains(DBClusterIdentifier, 'ca-a2a')])" --output text 2>/dev/null || echo "0")
echo "RDS clusters still deleting: $RDS_COUNT"

if [ "$RDS_COUNT" != "0" ]; then
    echo ""
    echo "⏳ Waiting for RDS to complete deletion (checking every 30 seconds)..."
    for i in {1..20}; do
        sleep 30
        RDS_COUNT=$(aws rds describe-db-clusters --region ${AWS_REGION} --query "length(DBClusters[?contains(DBClusterIdentifier, 'ca-a2a')])" --output text 2>/dev/null || echo "0")
        echo "  Check $i/20: $RDS_COUNT clusters remaining"
        if [ "$RDS_COUNT" == "0" ]; then
            echo "  ✅ All RDS clusters deleted!"
            break
        fi
    done
    
    if [ "$RDS_COUNT" != "0" ]; then
        echo "  ⚠ RDS is still deleting after 10 minutes. You may need to wait longer."
        echo "  Run this script again in 5 minutes."
        exit 1
    fi
else
    echo "✅ No RDS clusters found - proceeding with cleanup"
fi

echo ""
echo "=== Step 2: Wait 60 seconds for ENIs to fully detach ==="
sleep 60

echo ""
echo "=== Step 3: Check for remaining ENIs ==="
ENI_COUNT=$(aws ec2 describe-network-interfaces --filters "Name=vpc-id,Values=${VPC_ID}" --region ${AWS_REGION} --query 'length(NetworkInterfaces)' --output text 2>/dev/null || echo "0")
echo "Network interfaces remaining: $ENI_COUNT"

if [ "$ENI_COUNT" != "0" ]; then
    echo ""
    echo "Remaining ENIs:"
    aws ec2 describe-network-interfaces --filters "Name=vpc-id,Values=${VPC_ID}" --region ${AWS_REGION} --query 'NetworkInterfaces[*].[NetworkInterfaceId,Status,Description]' --output table
    
    echo ""
    echo "Attempting to delete available ENIs..."
    for eni in $(aws ec2 describe-network-interfaces --filters "Name=vpc-id,Values=${VPC_ID}" --region ${AWS_REGION} --query 'NetworkInterfaces[?Status==`available`].NetworkInterfaceId' --output text); do
        echo "  Deleting ENI: $eni"
        aws ec2 delete-network-interface --network-interface-id $eni --region ${AWS_REGION} 2>/dev/null && echo "    ✓ Deleted" || echo "    ✗ Failed"
    done
fi

echo ""
echo "=== Step 4: Delete DB subnet groups ==="
for subnet_group in $(aws rds describe-db-subnet-groups --region ${AWS_REGION} --query "DBSubnetGroups[?contains(DBSubnetGroupName, 'ca-a2a')].DBSubnetGroupName" --output text); do
    echo "Deleting DB subnet group: $subnet_group"
    aws rds delete-db-subnet-group --db-subnet-group-name $subnet_group --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Deleted" || echo "  ⚠ Already deleted or not found"
done

echo ""
echo "=== Step 5: Delete security groups (with retries) ==="
for attempt in {1..3}; do
    echo "Attempt $attempt/3:"
    SG_IDS=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=${VPC_ID}" --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text --region ${AWS_REGION})
    
    if [ -z "$SG_IDS" ]; then
        echo "  ✅ All security groups deleted"
        break
    fi
    
    for sg in $SG_IDS; do
        aws ec2 delete-security-group --group-id $sg --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Deleted $sg" || echo "  ⚠ Failed $sg (will retry)"
    done
    
    if [ $attempt -lt 3 ]; then
        echo "  Waiting 15 seconds before retry..."
        sleep 15
    fi
done

echo ""
echo "=== Step 6: Delete subnets (with retries) ==="
for attempt in {1..3}; do
    echo "Attempt $attempt/3:"
    SUBNET_IDS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=${VPC_ID}" --query 'Subnets[*].SubnetId' --output text --region ${AWS_REGION})
    
    if [ -z "$SUBNET_IDS" ]; then
        echo "  ✅ All subnets deleted"
        break
    fi
    
    for subnet in $SUBNET_IDS; do
        aws ec2 delete-subnet --subnet-id $subnet --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Deleted $subnet" || echo "  ⚠ Failed $subnet (will retry)"
    done
    
    if [ $attempt -lt 3 ]; then
        echo "  Waiting 15 seconds before retry..."
        sleep 15
    fi
done

echo ""
echo "=== Step 7: Delete route tables ==="
RT_IDS=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=${VPC_ID}" --query 'RouteTables[?Associations[0].Main==`false`].RouteTableId' --output text --region ${AWS_REGION})
for rt in $RT_IDS; do
    # Disassociate first
    ASSOC_IDS=$(aws ec2 describe-route-tables --route-table-ids $rt --region ${AWS_REGION} --query 'RouteTables[0].Associations[*].RouteTableAssociationId' --output text)
    for assoc in $ASSOC_IDS; do
        aws ec2 disassociate-route-table --association-id $assoc --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Disassociated $assoc" || true
    done
    # Delete
    aws ec2 delete-route-table --route-table-id $rt --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Deleted route table $rt" || echo "  ⚠ Failed $rt"
done

echo ""
echo "=== Step 8: Delete Internet Gateway ==="
IGW_ID=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=${VPC_ID}" --query 'InternetGateways[0].InternetGatewayId' --output text --region ${AWS_REGION})
if [ "$IGW_ID" != "None" ] && [ ! -z "$IGW_ID" ]; then
    echo "Detaching and deleting IGW: $IGW_ID"
    aws ec2 detach-internet-gateway --internet-gateway-id ${IGW_ID} --vpc-id ${VPC_ID} --region ${AWS_REGION} 2>/dev/null || echo "  ⚠ Already detached"
    aws ec2 delete-internet-gateway --internet-gateway-id ${IGW_ID} --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Deleted" || echo "  ✗ Failed"
fi

echo ""
echo "=== Step 9: FINAL VPC DELETION ==="
if aws ec2 delete-vpc --vpc-id ${VPC_ID} --region ${AWS_REGION} 2>/dev/null; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                       ║"
    echo "║                  ✅ VPC SUCCESSFULLY DELETED! ✅                      ║"
    echo "║                                                                       ║"
    echo "║              You can now run a fresh deployment:                     ║"
    echo "║                ./cloudshell-complete-deploy.sh                       ║"
    echo "║                                                                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
else
    echo ""
    echo "❌ VPC deletion still failed. Checking remaining dependencies..."
    echo ""
    echo "Remaining resources:"
    echo ""
    echo "Network Interfaces:"
    aws ec2 describe-network-interfaces --filters "Name=vpc-id,Values=${VPC_ID}" --region ${AWS_REGION} --query 'NetworkInterfaces[*].[NetworkInterfaceId,Status,Description]' --output table 2>/dev/null || echo "  None"
    echo ""
    echo "Subnets:"
    aws ec2 describe-subnets --filters "Name=vpc-id,Values=${VPC_ID}" --region ${AWS_REGION} --query 'Subnets[*].[SubnetId,CidrBlock]' --output table 2>/dev/null || echo "  None"
    echo ""
    echo "Security Groups:"
    aws ec2 describe-security-groups --filters "Name=vpc-id,Values=${VPC_ID}" --region ${AWS_REGION} --query 'SecurityGroups[*].[GroupId,GroupName]' --output table 2>/dev/null || echo "  None"
    echo ""
    echo "Route Tables:"
    aws ec2 describe-route-tables --filters "Name=vpc-id,Values=${VPC_ID}" --region ${AWS_REGION} --query 'RouteTables[*].[RouteTableId]' --output table 2>/dev/null || echo "  None"
fi

