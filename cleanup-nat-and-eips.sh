#!/bin/bash

AWS_REGION="us-east-1"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║     Clean Up Old NAT Gateways and Elastic IPs                        ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

echo "=== Step 1: List all NAT Gateways ==="
aws ec2 describe-nat-gateways \
    --region ${AWS_REGION} \
    --query 'NatGateways[*].{ID:NatGatewayId,State:State,VpcId:VpcId,SubnetId:SubnetId}' \
    --output table

echo ""
echo "=== Step 2: Find NAT Gateways from old VPCs ==="

# Get the current/active VPC (10.1.0.0/16)
CURRENT_VPC=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Project,Values=ca-a2a" "Name=cidr-block-association.cidr-block,Values=10.1.0.0/16" \
    --region ${AWS_REGION} \
    --query 'Vpcs[0].VpcId' \
    --output text)

if [ "$CURRENT_VPC" != "None" ] && [ ! -z "$CURRENT_VPC" ]; then
    echo "Current active VPC: $CURRENT_VPC"
else
    echo "No current VPC found (10.1.0.0/16)"
    CURRENT_VPC=""
fi

# Find NAT Gateways NOT in the current VPC
ALL_NAT_GWS=$(aws ec2 describe-nat-gateways \
    --region ${AWS_REGION} \
    --filter "Name=state,Values=available,pending,deleting" \
    --query 'NatGateways[*].[NatGatewayId,VpcId,State]' \
    --output text)

echo ""
echo "=== Step 3: Delete old NAT Gateways ==="

if [ -z "$ALL_NAT_GWS" ]; then
    echo "No NAT Gateways found"
else
    while IFS=$'\t' read -r nat_id vpc_id state; do
        if [ "$vpc_id" != "$CURRENT_VPC" ]; then
            echo "Found NAT Gateway in old VPC: $nat_id (VPC: $vpc_id, State: $state)"
            if [ "$state" != "deleting" ]; then
                echo "  Deleting NAT Gateway: $nat_id..."
                aws ec2 delete-nat-gateway --nat-gateway-id $nat_id --region ${AWS_REGION} 2>&1
                if [ $? -eq 0 ]; then
                    echo "  ✓ Deletion initiated: $nat_id"
                else
                    echo "  ✗ Failed to delete: $nat_id"
                fi
            else
                echo "  • Already deleting: $nat_id"
            fi
        else
            echo "Keeping NAT Gateway in current VPC: $nat_id"
        fi
    done <<< "$ALL_NAT_GWS"
fi

echo ""
echo "=== Step 4: Wait for NAT Gateways to finish deleting (60 seconds) ==="
sleep 60

echo ""
echo "=== Step 5: Release unassociated Elastic IPs ==="
UNASSOCIATED_EIPS=$(aws ec2 describe-addresses \
    --region ${AWS_REGION} \
    --query 'Addresses[?AssociationId==`null`].AllocationId' \
    --output text)

if [ -z "$UNASSOCIATED_EIPS" ]; then
    echo "✓ No unassociated Elastic IPs found"
else
    echo "Found unassociated Elastic IPs:"
    for eip in $UNASSOCIATED_EIPS; do
        echo "  Releasing $eip..."
        aws ec2 release-address --allocation-id $eip --region ${AWS_REGION} 2>&1
        if [ $? -eq 0 ]; then
            echo "  ✓ Released: $eip"
        else
            echo "  ✗ Failed to release: $eip (may still be associated)"
        fi
    done
fi

echo ""
echo "=== Step 6: Final EIP Status ==="
TOTAL_EIPS=$(aws ec2 describe-addresses --region ${AWS_REGION} --query 'length(Addresses)' --output text)
AVAILABLE_EIPS=$(( 5 - TOTAL_EIPS ))

echo "Total Elastic IPs: $TOTAL_EIPS / 5"
echo "Available EIPs: $AVAILABLE_EIPS"

echo ""
if [ $AVAILABLE_EIPS -gt 0 ]; then
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║  ✅ Cleanup Complete - You can now run the deployment!               ║"
    echo "║  Run: ./cloudshell-complete-deploy.sh                                ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
else
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║  ⚠  Still at EIP limit. Options:                                      ║"
    echo "║  1. Wait longer for NAT Gateways to fully delete (can take 5 min)    ║"
    echo "║  2. Run cleanup-deployment.sh --force to clean everything            ║"
    echo "║  3. Manually delete NAT Gateways from AWS Console                    ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
fi

