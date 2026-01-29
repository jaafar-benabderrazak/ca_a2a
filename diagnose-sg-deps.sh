#!/bin/bash
set -eo pipefail

# Deep diagnostic script for security group dependencies
VPC_ID="vpc-086392a3eed899f72"
AWS_REGION="eu-west-3"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║         DEEP SECURITY GROUP DEPENDENCY DIAGNOSTICS                   ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

# List of problematic security groups
SG_LIST=(
    "sg-05f6157bddaaf9358"
    "sg-0bae968c462dc62c1"
    "sg-00eb295c34057af8a"
    "sg-0f547640a05ad30b4"
    "sg-047a8f39f9cdcaf4c"
)

echo ""
echo "=== Checking for network interfaces using these SGs ==="
for sg in "${SG_LIST[@]}"; do
    echo ""
    echo "Security Group: $sg"
    ENIS=$(aws ec2 describe-network-interfaces \
        --filters "Name=group-id,Values=$sg" \
        --region ${AWS_REGION} \
        --query 'NetworkInterfaces[*].[NetworkInterfaceId,Status,Description,Attachment.InstanceId]' \
        --output text 2>/dev/null)
    
    if [ -z "$ENIS" ]; then
        echo "  ✓ No ENIs found using this SG"
    else
        echo "  ⚠ ENIs still using this SG:"
        echo "$ENIS"
    fi
done

echo ""
echo "=== Checking all network interfaces in VPC ==="
aws ec2 describe-network-interfaces \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --region ${AWS_REGION} \
    --query 'NetworkInterfaces[*].[NetworkInterfaceId,Status,Description,Groups[0].GroupId]' \
    --output table

echo ""
echo "=== Checking security group rules for cross-references ==="
for sg in "${SG_LIST[@]}"; do
    echo ""
    echo "SG: $sg"
    echo "  Ingress rules:"
    aws ec2 describe-security-groups \
        --group-ids $sg \
        --region ${AWS_REGION} \
        --query 'SecurityGroups[0].IpPermissions' \
        --output json 2>/dev/null | grep -q '\[\]' && echo "    ✓ None" || echo "    ⚠ Still has rules!"
    
    echo "  Egress rules:"
    aws ec2 describe-security-groups \
        --group-ids $sg \
        --region ${AWS_REGION} \
        --query 'SecurityGroups[0].IpPermissionsEgress' \
        --output json 2>/dev/null | grep -q '\[\]' && echo "    ✓ None" || echo "    ⚠ Still has rules!"
done

echo ""
echo "=== Checking for other resources that might reference these SGs ==="

echo ""
echo "ECS Services:"
aws ecs list-services --cluster ca-a2a-cluster --region ${AWS_REGION} 2>/dev/null || echo "  ✓ No ECS cluster found"

echo ""
echo "ECS Tasks:"
aws ecs list-tasks --cluster ca-a2a-cluster --region ${AWS_REGION} 2>/dev/null || echo "  ✓ No ECS cluster found"

echo ""
echo "Lambda Functions:"
aws lambda list-functions --region ${AWS_REGION} \
    --query "Functions[?starts_with(FunctionName, 'ca-a2a')].FunctionName" \
    --output text 2>/dev/null | grep -q '.' && echo "  ⚠ Lambda functions still exist" || echo "  ✓ No Lambda functions"

echo ""
echo "RDS Instances:"
aws rds describe-db-instances --region ${AWS_REGION} \
    --query "DBInstances[?contains(DBInstanceIdentifier, 'ca-a2a')].DBInstanceIdentifier" \
    --output text 2>/dev/null | grep -q '.' && echo "  ⚠ RDS instances still exist" || echo "  ✓ No RDS instances"

echo ""
echo "ALBs:"
aws elbv2 describe-load-balancers --region ${AWS_REGION} \
    --query "LoadBalancers[?VpcId=='${VPC_ID}'].LoadBalancerName" \
    --output text 2>/dev/null | grep -q '.' && echo "  ⚠ ALBs still exist" || echo "  ✓ No ALBs"

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║                    ATTEMPTED FIXES                                    ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

echo ""
echo "=== Attempting to delete any remaining ENIs manually ==="
for eni in $(aws ec2 describe-network-interfaces \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --region ${AWS_REGION} \
    --query 'NetworkInterfaces[?Status==`available`].NetworkInterfaceId' \
    --output text); do
    echo "Deleting ENI: $eni"
    aws ec2 delete-network-interface --network-interface-id $eni --region ${AWS_REGION} 2>&1 && echo "  ✓ Deleted" || echo "  ✗ Failed"
done

echo ""
echo "=== Final attempt: Delete security groups with verbose error output ==="
for sg in "${SG_LIST[@]}"; do
    echo ""
    echo "Attempting to delete: $sg"
    OUTPUT=$(aws ec2 delete-security-group --group-id $sg --region ${AWS_REGION} 2>&1)
    if [ $? -eq 0 ]; then
        echo "  ✅ SUCCESS! $sg deleted"
    else
        echo "  ❌ FAILED: $OUTPUT"
    fi
done

echo ""
echo "=== Summary: VPC deletion attempt ==="
if aws ec2 delete-vpc --vpc-id ${VPC_ID} --region ${AWS_REGION} 2>&1; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                       ║"
    echo "║              ✅✅✅ VPC SUCCESSFULLY DELETED! ✅✅✅                  ║"
    echo "║                                                                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
else
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                       ║"
    echo "║           ⚠ VPC DELETION STILL BLOCKED ⚠                             ║"
    echo "║                                                                       ║"
    echo "║  These security groups have hidden dependencies in AWS               ║"
    echo "║  that may take 5-15 minutes to fully clear.                          ║"
    echo "║                                                                       ║"
    echo "║  RECOMMENDED ACTION:                                                  ║"
    echo "║  1. Wait 10 minutes                                                   ║"
    echo "║  2. Rerun this diagnostic script                                      ║"
    echo "║                                                                       ║"
    echo "║  OR                                                                   ║"
    echo "║                                                                       ║"
    echo "║  Use AWS Console:                                                     ║"
    echo "║  • Go to VPC → Security Groups                                        ║"
    echo "║  • Try to delete each SG manually                                     ║"
    echo "║  • AWS Console will show the exact blocking resource                  ║"
    echo "║                                                                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
fi

