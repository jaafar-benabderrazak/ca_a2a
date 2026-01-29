#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# Complete CA-A2A Cleanup for us-east-1
# Removes ALL ca-a2a resources to free up quotas
# ══════════════════════════════════════════════════════════════════════════════

set -e

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                        ║"
echo "║       CA-A2A Complete Cleanup - us-east-1                             ║"
echo "║       This will delete ALL ca-a2a resources                           ║"
echo "║                                                                        ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# 1. Delete CloudFormation Stack (if exists)
# ══════════════════════════════════════════════════════════════════════════════

echo "▸ Deleting CloudFormation stack..."
aws cloudformation delete-stack --stack-name ca-a2a-prod --region ${AWS_REGION} 2>/dev/null || echo "  No stack to delete"
echo "  Waiting 2 minutes for stack deletion..."
sleep 120

# ══════════════════════════════════════════════════════════════════════════════
# 2. Delete Secrets Manager Secrets
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "▸ Deleting Secrets Manager secrets..."
SECRETS=$(aws secretsmanager list-secrets --region ${AWS_REGION} \
    --query "SecretList[?starts_with(Name, '${PROJECT_NAME}/')].Name" --output text)

if [ ! -z "$SECRETS" ]; then
    for secret in $SECRETS; do
        echo "  Deleting: $secret"
        aws secretsmanager delete-secret \
            --secret-id "$secret" \
            --force-delete-without-recovery \
            --region ${AWS_REGION} 2>/dev/null || echo "    Already deleted"
    done
    echo "✓ Secrets deleted"
else
    echo "  No secrets to delete"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 3. Get All ca-a2a VPCs
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "▸ Finding all ca-a2a VPCs..."
VPCS=$(aws ec2 describe-vpcs --region ${AWS_REGION} \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-vpc" \
    --query 'Vpcs[*].VpcId' --output text)

if [ -z "$VPCS" ]; then
    echo "  No ca-a2a VPCs found"
    exit 0
fi

echo "  Found VPCs: $VPCS"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# 4. Clean Up Each VPC
# ══════════════════════════════════════════════════════════════════════════════

for VPC_ID in $VPCS; do
    echo "═══════════════════════════════════════════════════════════════════════"
    echo "Cleaning VPC: $VPC_ID"
    echo "═══════════════════════════════════════════════════════════════════════"
    
    # Delete NAT Gateways
    echo "  ▸ Deleting NAT Gateways..."
    NAT_GWS=$(aws ec2 describe-nat-gateways --region ${AWS_REGION} \
        --filter "Name=vpc-id,Values=$VPC_ID" "Name=state,Values=available,pending" \
        --query 'NatGateways[*].NatGatewayId' --output text)
    
    for nat in $NAT_GWS; do
        echo "    Deleting NAT Gateway: $nat"
        aws ec2 delete-nat-gateway --nat-gateway-id $nat --region ${AWS_REGION}
    done
    
    if [ ! -z "$NAT_GWS" ]; then
        echo "    Waiting 60 seconds for NAT Gateway deletion..."
        sleep 60
    fi
    
    # Release Elastic IPs
    echo "  ▸ Releasing Elastic IPs..."
    EIPS=$(aws ec2 describe-addresses --region ${AWS_REGION} \
        --filters "Name=domain,Values=vpc" \
        --query "Addresses[?NetworkInterfaceId==null].AllocationId" --output text)
    
    for eip in $EIPS; do
        echo "    Releasing EIP: $eip"
        aws ec2 release-address --allocation-id $eip --region ${AWS_REGION} 2>/dev/null || true
    done
    
    # Delete Load Balancers
    echo "  ▸ Deleting Load Balancers..."
    LBSET=$(aws elbv2 describe-load-balancers --region ${AWS_REGION} \
        --query "LoadBalancers[?VpcId=='$VPC_ID'].LoadBalancerArn" --output text)
    
    for lb in $LBSET; do
        echo "    Deleting Load Balancer: $lb"
        aws elbv2 delete-load-balancer --load-balancer-arn $lb --region ${AWS_REGION}
    done
    
    # Delete RDS Instances
    echo "  ▸ Deleting RDS instances..."
    RDS_INSTANCES=$(aws rds describe-db-instances --region ${AWS_REGION} \
        --query "DBInstances[?DBSubnetGroup.VpcId=='$VPC_ID'].DBInstanceIdentifier" --output text)
    
    for db in $RDS_INSTANCES; do
        echo "    Deleting RDS instance: $db"
        aws rds delete-db-instance \
            --db-instance-identifier $db \
            --skip-final-snapshot \
            --delete-automated-backups \
            --region ${AWS_REGION} 2>/dev/null || true
    done
    
    # Delete RDS Clusters
    echo "  ▸ Deleting RDS clusters..."
    RDS_CLUSTERS=$(aws rds describe-db-clusters --region ${AWS_REGION} \
        --query "DBClusters[?DBSubnetGroup=='${PROJECT_NAME}-db-subnet'].DBClusterIdentifier" --output text)
    
    for cluster in $RDS_CLUSTERS; do
        # Delete cluster instances first
        CLUSTER_INSTANCES=$(aws rds describe-db-clusters --region ${AWS_REGION} \
            --db-cluster-identifier $cluster \
            --query 'DBClusters[0].DBClusterMembers[*].DBInstanceIdentifier' --output text)
        
        for inst in $CLUSTER_INSTANCES; do
            echo "    Deleting cluster instance: $inst"
            aws rds delete-db-instance \
                --db-instance-identifier $inst \
                --skip-final-snapshot \
                --region ${AWS_REGION} 2>/dev/null || true
        done
        
        echo "    Deleting cluster: $cluster"
        aws rds delete-db-cluster \
            --db-cluster-identifier $cluster \
            --skip-final-snapshot \
            --delete-automated-backups \
            --region ${AWS_REGION} 2>/dev/null || true
    done
    
    if [ ! -z "$RDS_INSTANCES" ] || [ ! -z "$RDS_CLUSTERS" ]; then
        echo "    Waiting 90 seconds for RDS deletion..."
        sleep 90
    fi
    
    # Delete Network Interfaces
    echo "  ▸ Deleting network interfaces..."
    ENIS=$(aws ec2 describe-network-interfaces --region ${AWS_REGION} \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query 'NetworkInterfaces[?Status==`available`].NetworkInterfaceId' --output text)
    
    for eni in $ENIS; do
        echo "    Deleting ENI: $eni"
        aws ec2 delete-network-interface --network-interface-id $eni --region ${AWS_REGION} 2>/dev/null || true
    done
    
    # Delete Security Groups (except default)
    echo "  ▸ Deleting security groups..."
    SGS=$(aws ec2 describe-security-groups --region ${AWS_REGION} \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text)
    
    for sg in $SGS; do
        echo "    Deleting SG: $sg"
        aws ec2 delete-security-group --group-id $sg --region ${AWS_REGION} 2>/dev/null || true
    done
    
    sleep 5
    
    # Delete Subnets
    echo "  ▸ Deleting subnets..."
    SUBNETS=$(aws ec2 describe-subnets --region ${AWS_REGION} \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query 'Subnets[*].SubnetId' --output text)
    
    for subnet in $SUBNETS; do
        echo "    Deleting subnet: $subnet"
        aws ec2 delete-subnet --subnet-id $subnet --region ${AWS_REGION} 2>/dev/null || true
    done
    
    # Delete Route Tables (except main)
    echo "  ▸ Deleting route tables..."
    RTS=$(aws ec2 describe-route-tables --region ${AWS_REGION} \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query 'RouteTables[?Associations[0].Main!=`true`].RouteTableId' --output text)
    
    for rt in $RTS; do
        echo "    Deleting route table: $rt"
        aws ec2 delete-route-table --route-table-id $rt --region ${AWS_REGION} 2>/dev/null || true
    done
    
    # Detach and Delete Internet Gateways
    echo "  ▸ Deleting internet gateway..."
    IGW=$(aws ec2 describe-internet-gateways --region ${AWS_REGION} \
        --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
        --query 'InternetGateways[0].InternetGatewayId' --output text)
    
    if [ "$IGW" != "None" ] && [ ! -z "$IGW" ]; then
        echo "    Detaching IGW: $IGW"
        aws ec2 detach-internet-gateway --internet-gateway-id $IGW --vpc-id $VPC_ID --region ${AWS_REGION} 2>/dev/null || true
        echo "    Deleting IGW: $IGW"
        aws ec2 delete-internet-gateway --internet-gateway-id $IGW --region ${AWS_REGION} 2>/dev/null || true
    fi
    
    # Delete VPC
    echo "  ▸ Deleting VPC..."
    aws ec2 delete-vpc --vpc-id $VPC_ID --region ${AWS_REGION} 2>/dev/null && echo "    ✓ VPC deleted: $VPC_ID" || echo "    ⚠ VPC deletion failed (may have dependencies)"
    
    echo ""
done

# ══════════════════════════════════════════════════════════════════════════════
# 5. Delete DB Subnet Groups
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "▸ Deleting DB subnet groups..."
aws rds delete-db-subnet-group --db-subnet-group-name ${PROJECT_NAME}-db-subnet --region ${AWS_REGION} 2>/dev/null || echo "  No subnet group to delete"

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                        ║"
echo "║                    ✅ Cleanup Complete!                               ║"
echo "║                                                                        ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "You can now run: cd cdk && ./quickstart.sh"
echo ""

