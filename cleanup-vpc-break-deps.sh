#!/bin/bash
set -eo pipefail

# Break circular security group dependencies and cleanup
VPC_ID="vpc-086392a3eed899f72"
AWS_REGION="eu-west-3"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║     BREAKING CIRCULAR DEPENDENCIES - Final VPC Cleanup               ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

# List of security groups to clean
SG_LIST=(
    "sg-05f6157bddaaf9358"
    "sg-0bae968c462dc62c1"
    "sg-00eb295c34057af8a"
    "sg-0f547640a05ad30b4"
    "sg-047a8f39f9cdcaf4c"
)

echo ""
echo "=== Step 1: Remove ALL security group rules (break circular deps) ==="
for sg in "${SG_LIST[@]}"; do
    echo "Processing SG: $sg"
    
    # Get and revoke ALL ingress rules
    INGRESS=$(aws ec2 describe-security-groups --group-ids $sg --region ${AWS_REGION} --query 'SecurityGroups[0].IpPermissions' --output json 2>/dev/null)
    if [ "$INGRESS" != "[]" ] && [ "$INGRESS" != "null" ] && [ ! -z "$INGRESS" ]; then
        echo "  Removing ingress rules..."
        aws ec2 revoke-security-group-ingress --group-id $sg --ip-permissions "$INGRESS" --region ${AWS_REGION} 2>/dev/null && echo "    ✓ Done" || echo "    ⚠ Failed or already removed"
    fi
    
    # Get and revoke ALL egress rules
    EGRESS=$(aws ec2 describe-security-groups --group-ids $sg --region ${AWS_REGION} --query 'SecurityGroups[0].IpPermissionsEgress' --output json 2>/dev/null)
    if [ "$EGRESS" != "[]" ] && [ "$EGRESS" != "null" ] && [ ! -z "$EGRESS" ]; then
        echo "  Removing egress rules..."
        aws ec2 revoke-security-group-egress --group-id $sg --ip-permissions "$EGRESS" --region ${AWS_REGION} 2>/dev/null && echo "    ✓ Done" || echo "    ⚠ Failed or already removed"
    fi
done

echo ""
echo "=== Step 2: Wait 10 seconds for AWS to propagate rule deletions ==="
sleep 10

echo ""
echo "=== Step 3: Delete route tables ==="
RT_IDS=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=${VPC_ID}" --query 'RouteTables[?Associations[0].Main!=`true`].RouteTableId' --output text --region ${AWS_REGION})

if [ ! -z "$RT_IDS" ]; then
    for rt in $RT_IDS; do
        echo "Processing route table: $rt"
        
        # Remove all associations first
        ASSOC_IDS=$(aws ec2 describe-route-tables --route-table-ids $rt --region ${AWS_REGION} --query 'RouteTables[0].Associations[?Main==`false`].RouteTableAssociationId' --output text 2>/dev/null)
        for assoc in $ASSOC_IDS; do
            echo "  Disassociating: $assoc"
            aws ec2 disassociate-route-table --association-id $assoc --region ${AWS_REGION} 2>/dev/null && echo "    ✓ Done" || echo "    ⚠ Failed"
        done
        
        # Delete the route table
        echo "  Deleting route table: $rt"
        aws ec2 delete-route-table --route-table-id $rt --region ${AWS_REGION} 2>/dev/null && echo "    ✓ Deleted" || echo "    ⚠ Failed (might be main or still in use)"
    done
else
    echo "  No non-main route tables found"
fi

echo ""
echo "=== Step 4: Delete Internet Gateway ==="
IGW_ID=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=${VPC_ID}" --query 'InternetGateways[0].InternetGatewayId' --output text --region ${AWS_REGION})
if [ "$IGW_ID" != "None" ] && [ ! -z "$IGW_ID" ]; then
    echo "Found IGW: $IGW_ID"
    echo "  Detaching..."
    aws ec2 detach-internet-gateway --internet-gateway-id ${IGW_ID} --vpc-id ${VPC_ID} --region ${AWS_REGION} 2>/dev/null && echo "    ✓ Detached" || echo "    ⚠ Already detached"
    echo "  Deleting..."
    aws ec2 delete-internet-gateway --internet-gateway-id ${IGW_ID} --region ${AWS_REGION} 2>/dev/null && echo "    ✓ Deleted" || echo "    ⚠ Failed"
else
    echo "  No IGW found"
fi

echo ""
echo "=== Step 5: Delete security groups (retry with delays) ==="
for attempt in {1..5}; do
    echo "Attempt $attempt/5:"
    
    SG_IDS=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=${VPC_ID}" --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text --region ${AWS_REGION})
    
    if [ -z "$SG_IDS" ]; then
        echo "  ✅ All security groups deleted!"
        break
    fi
    
    for sg in $SG_IDS; do
        aws ec2 delete-security-group --group-id $sg --region ${AWS_REGION} 2>/dev/null && echo "  ✓ Deleted $sg" || echo "  ⚠ Failed $sg"
    done
    
    if [ $attempt -lt 5 ]; then
        echo "  Waiting 20 seconds before retry..."
        sleep 20
    fi
done

echo ""
echo "=== Step 6: Final check before VPC deletion ==="
echo "Remaining security groups:"
REMAINING_SGS=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=${VPC_ID}" --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text --region ${AWS_REGION})
if [ -z "$REMAINING_SGS" ]; then
    echo "  ✅ None (ready for VPC deletion)"
else
    echo "  ⚠ Still have: $REMAINING_SGS"
    echo "  Attempting one more forceful cleanup..."
    
    for sg in $REMAINING_SGS; do
        echo "  Final attempt on $sg:"
        # One more attempt to remove any lingering rules
        aws ec2 revoke-security-group-ingress --group-id $sg --ip-permissions "$(aws ec2 describe-security-groups --group-ids $sg --region ${AWS_REGION} --query 'SecurityGroups[0].IpPermissions' --output json)" --region ${AWS_REGION} 2>/dev/null || true
        aws ec2 revoke-security-group-egress --group-id $sg --ip-permissions "$(aws ec2 describe-security-groups --group-ids $sg --region ${AWS_REGION} --query 'SecurityGroups[0].IpPermissionsEgress' --output json)" --region ${AWS_REGION} 2>/dev/null || true
        sleep 2
        aws ec2 delete-security-group --group-id $sg --region ${AWS_REGION} 2>/dev/null && echo "    ✓ Deleted" || echo "    ✗ Still failed"
    done
fi

echo ""
echo "=== Step 7: DELETE VPC ==="
if aws ec2 delete-vpc --vpc-id ${VPC_ID} --region ${AWS_REGION} 2>&1; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                       ║"
    echo "║              ✅✅✅ VPC SUCCESSFULLY DELETED! ✅✅✅                  ║"
    echo "║                                                                       ║"
    echo "║                                                                       ║"
    echo "║              You can now run a fresh deployment:                     ║"
    echo "║                                                                       ║"
    echo "║                ./cloudshell-complete-deploy.sh                       ║"
    echo "║                                                                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
else
    echo ""
    echo "❌ VPC deletion still failed. Final diagnostics:"
    echo ""
    echo "Security Groups still present:"
    aws ec2 describe-security-groups --filters "Name=vpc-id,Values=${VPC_ID}" --region ${AWS_REGION} --query 'SecurityGroups[*].[GroupId,GroupName,Description]' --output table
    echo ""
    echo "Route Tables still present:"
    aws ec2 describe-route-tables --filters "Name=vpc-id,Values=${VPC_ID}" --region ${AWS_REGION} --query 'RouteTables[*].[RouteTableId,Associations[0].Main]' --output table
    echo ""
    echo "💡 Manual intervention may be required:"
    echo "   Check AWS Console → VPC → vpc-086392a3eed899f72"
    echo "   Look for any remaining dependencies"
fi

