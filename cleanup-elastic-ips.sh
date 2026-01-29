#!/bin/bash

AWS_REGION="us-east-1"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║          Elastic IP Cleanup - Release Unused EIPs                     ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

echo "=== Step 1: List all Elastic IPs ==="
aws ec2 describe-addresses \
    --region ${AWS_REGION} \
    --query 'Addresses[*].{AllocationId:AllocationId,PublicIp:PublicIp,AssociationId:AssociationId,Name:Tags[?Key==`Name`].Value|[0]}' \
    --output table

echo ""
echo "=== Step 2: Find unassociated (unused) Elastic IPs ==="
UNASSOCIATED_EIPS=$(aws ec2 describe-addresses \
    --region ${AWS_REGION} \
    --query 'Addresses[?AssociationId==`null`].AllocationId' \
    --output text)

if [ -z "$UNASSOCIATED_EIPS" ]; then
    echo "✓ No unassociated Elastic IPs found"
    echo ""
    echo "All EIPs are in use. To free up space, you need to:"
    echo "1. Delete NAT Gateways: aws ec2 delete-nat-gateway --nat-gateway-id <id>"
    echo "2. Wait for NAT Gateway deletion (takes 2-3 minutes)"
    echo "3. Release the EIP: aws ec2 release-address --allocation-id <id>"
    echo ""
    echo "Or use the cleanup-deployment.sh script to clean up entire deployments."
else
    echo "Found unassociated Elastic IPs:"
    for eip in $UNASSOCIATED_EIPS; do
        echo "  - $eip"
    done
    
    echo ""
    echo "=== Step 3: Release unassociated Elastic IPs ==="
    for eip in $UNASSOCIATED_EIPS; do
        echo "Releasing $eip..."
        aws ec2 release-address --allocation-id $eip --region ${AWS_REGION} 2>&1
        if [ $? -eq 0 ]; then
            echo "  ✓ Released: $eip"
        else
            echo "  ✗ Failed to release: $eip"
        fi
    done
fi

echo ""
echo "=== Step 4: Current Elastic IP usage ==="
TOTAL_EIPS=$(aws ec2 describe-addresses --region ${AWS_REGION} --query 'length(Addresses)' --output text)
echo "Total Elastic IPs: $TOTAL_EIPS / 5 (default limit)"

if [ "$TOTAL_EIPS" -lt 5 ]; then
    echo "✓ You have $(( 5 - TOTAL_EIPS )) EIP(s) available"
else
    echo "⚠ You are at the EIP limit. Consider:"
    echo "  1. Deleting old NAT Gateways"
    echo "  2. Running cleanup-deployment.sh to remove old deployments"
    echo "  3. Requesting a limit increase from AWS Support"
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║  Cleanup Complete                                                     ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

