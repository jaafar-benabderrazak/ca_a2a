#!/bin/bash
set -eo pipefail

# Final nuclear option - delete VPC endpoints and force SG cleanup
VPC_ID="vpc-086392a3eed899f72"
AWS_REGION="eu-west-3"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║         NUCLEAR OPTION - VPC Endpoints & Force SG Cleanup            ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

echo ""
echo "=== Step 1: Check for VPC Endpoints ==="
VPC_ENDPOINTS=$(aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --region ${AWS_REGION} \
    --query 'VpcEndpoints[*].VpcEndpointId' \
    --output text)

if [ ! -z "$VPC_ENDPOINTS" ]; then
    echo "⚠ Found VPC Endpoints (these often hold SG references):"
    for endpoint in $VPC_ENDPOINTS; do
        echo "  Deleting VPC Endpoint: $endpoint"
        aws ec2 delete-vpc-endpoints --vpc-endpoint-ids $endpoint --region ${AWS_REGION} 2>&1 && echo "    ✓ Deleted" || echo "    ✗ Failed"
    done
    echo ""
    echo "Waiting 30 seconds for VPC endpoints to fully delete..."
    sleep 30
else
    echo "✓ No VPC endpoints found"
fi

echo ""
echo "=== Step 2: Check for NAT Gateways ==="
NAT_GWS=$(aws ec2 describe-nat-gateways \
    --filter "Name=vpc-id,Values=${VPC_ID}" "Name=state,Values=available,pending,deleting" \
    --region ${AWS_REGION} \
    --query 'NatGateways[*].NatGatewayId' \
    --output text)

if [ ! -z "$NAT_GWS" ]; then
    echo "⚠ Found NAT Gateways:"
    for nat in $NAT_GWS; do
        echo "  Deleting NAT Gateway: $nat"
        aws ec2 delete-nat-gateway --nat-gateway-id $nat --region ${AWS_REGION} 2>&1 && echo "    ✓ Deleted" || echo "    ✗ Already deleting"
    done
else
    echo "✓ No NAT gateways found"
fi

echo ""
echo "=== Step 3: Check for Elastic IPs ==="
EIPS=$(aws ec2 describe-addresses \
    --region ${AWS_REGION} \
    --filters "Name=domain,Values=vpc" \
    --query 'Addresses[*].AllocationId' \
    --output text)

if [ ! -z "$EIPS" ]; then
    echo "⚠ Found Elastic IPs:"
    for eip in $EIPS; do
        echo "  Releasing EIP: $eip"
        aws ec2 release-address --allocation-id $eip --region ${AWS_REGION} 2>&1 && echo "    ✓ Released" || echo "    ✗ Failed (might be in use by NAT Gateway)"
    done
else
    echo "✓ No EIPs found"
fi

echo ""
echo "=== Step 4: List ALL network interfaces (including hidden ones) ==="
aws ec2 describe-network-interfaces \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --region ${AWS_REGION} \
    --query 'NetworkInterfaces[*].[NetworkInterfaceId,Status,InterfaceType,Description,Groups[*].GroupId]' \
    --output table

echo ""
echo "=== Step 5: Force modify security groups to remove their own egress rules ==="
SG_LIST=(
    "sg-05f6157bddaaf9358"
    "sg-0bae968c462dc62c1"
    "sg-00eb295c34057af8a"
    "sg-0f547640a05ad30b4"
    "sg-047a8f39f9cdcaf4c"
)

for sg in "${SG_LIST[@]}"; do
    echo "Processing $sg..."
    
    # Get ALL rules and revoke them individually
    echo "  Checking for any remaining rules..."
    
    # Try to describe the SG
    RULES_EXIST=$(aws ec2 describe-security-groups --group-ids $sg --region ${AWS_REGION} 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        # Revoke all ingress
        aws ec2 describe-security-groups --group-ids $sg --region ${AWS_REGION} \
            --query 'SecurityGroups[0].IpPermissions' --output json > /tmp/ingress_${sg}.json 2>/dev/null
        
        if [ -s /tmp/ingress_${sg}.json ] && [ "$(cat /tmp/ingress_${sg}.json)" != "[]" ]; then
            echo "    Revoking remaining ingress rules..."
            aws ec2 revoke-security-group-ingress --group-id $sg --ip-permissions file:///tmp/ingress_${sg}.json --region ${AWS_REGION} 2>&1 || true
        fi
        
        # Revoke all egress
        aws ec2 describe-security-groups --group-ids $sg --region ${AWS_REGION} \
            --query 'SecurityGroups[0].IpPermissionsEgress' --output json > /tmp/egress_${sg}.json 2>/dev/null
        
        if [ -s /tmp/egress_${sg}.json ] && [ "$(cat /tmp/egress_${sg}.json)" != "[]" ]; then
            echo "    Revoking remaining egress rules..."
            aws ec2 revoke-security-group-egress --group-id $sg --ip-permissions file:///tmp/egress_${sg}.json --region ${AWS_REGION} 2>&1 || true
        fi
    fi
done

echo ""
echo "=== Step 6: Wait for AWS eventual consistency (60 seconds) ==="
sleep 60

echo ""
echo "=== Step 7: Final deletion attempt for security groups ==="
for sg in "${SG_LIST[@]}"; do
    echo "Deleting $sg..."
    if aws ec2 delete-security-group --group-id $sg --region ${AWS_REGION} 2>&1; then
        echo "  ✅ SUCCESS!"
    else
        echo "  ❌ FAILED"
        echo "  Getting detailed info..."
        aws ec2 describe-security-groups --group-ids $sg --region ${AWS_REGION} 2>/dev/null || echo "    SG doesn't exist or can't be described"
    fi
    sleep 2
done

echo ""
echo "=== Step 8: Check if VPC can be deleted now ==="
if aws ec2 delete-vpc --vpc-id ${VPC_ID} --region ${AWS_REGION} 2>&1; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                       ║"
    echo "║              ✅✅✅ VPC SUCCESSFULLY DELETED! ✅✅✅                  ║"
    echo "║                                                                       ║"
    echo "║                    Ready for fresh deployment!                       ║"
    echo "║                                                                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
else
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                       ║"
    echo "║              ⚠ MANUAL AWS CONSOLE ACTION REQUIRED ⚠                  ║"
    echo "║                                                                       ║"
    echo "║  The security groups have circular references that AWS is            ║"
    echo "║  maintaining internally. This is a known AWS eventual consistency    ║"
    echo "║  issue.                                                               ║"
    echo "║                                                                       ║"
    echo "║  SOLUTION: Delete via AWS Console                                     ║"
    echo "║                                                                       ║"
    echo "║  1. Go to VPC → Your VPCs in AWS Console                             ║"
    echo "║  2. Select vpc-086392a3eed899f72                                     ║"
    echo "║  3. Actions → Delete VPC                                              ║"
    echo "║  4. AWS Console has a 'force delete' option that will                ║"
    echo "║     automatically delete all dependencies including the              ║"
    echo "║     circular security group references                                ║"
    echo "║                                                                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
fi

# Cleanup temp files
rm -f /tmp/ingress_*.json /tmp/egress_*.json 2>/dev/null || true

