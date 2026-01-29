#!/bin/bash

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║          Deployment State Diagnostic                                  ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

echo "=== VPC Status ==="
VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Project,Values=ca-a2a" "Name=cidr-block-association.cidr-block,Values=10.1.0.0/16" \
    --region ${AWS_REGION} \
    --query 'Vpcs[0].VpcId' \
    --output text)

if [ "$VPC_ID" != "None" ] && [ ! -z "$VPC_ID" ]; then
    echo "✓ VPC exists: $VPC_ID"
else
    echo "✗ VPC not found"
    exit 1
fi

echo ""
echo "=== Subnets Status ==="
aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --region ${AWS_REGION} \
    --query 'Subnets[*].{SubnetId:SubnetId,CIDR:CidrBlock,AZ:AvailabilityZone,Name:Tags[?Key==`Name`].Value|[0]}' \
    --output table

echo ""
echo "=== NAT Gateway Status ==="
NAT_STATUS=$(aws ec2 describe-nat-gateways \
    --filter "Name=vpc-id,Values=${VPC_ID}" \
    --region ${AWS_REGION} \
    --query 'NatGateways[*].{ID:NatGatewayId,State:State,SubnetId:SubnetId}' \
    --output table)

if [ -z "$NAT_STATUS" ]; then
    echo "✗ No NAT Gateway found"
    echo ""
    echo "Checking Elastic IPs..."
    aws ec2 describe-addresses \
        --filters "Name=tag:Project,Values=ca-a2a" \
        --region ${AWS_REGION} \
        --query 'Addresses[*].{AllocationId:AllocationId,PublicIp:PublicIp,AssociationId:AssociationId}' \
        --output table
else
    echo "$NAT_STATUS"
fi

echo ""
echo "=== Internet Gateway Status ==="
aws ec2 describe-internet-gateways \
    --filters "Name=attachment.vpc-id,Values=${VPC_ID}" \
    --region ${AWS_REGION} \
    --query 'InternetGateways[*].{ID:InternetGatewayId,State:Attachments[0].State}' \
    --output table

echo ""
echo "=== Route Tables Status ==="
aws ec2 describe-route-tables \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --region ${AWS_REGION} \
    --query 'RouteTables[*].{ID:RouteTableId,Routes:length(Routes),Associations:length(Associations)}' \
    --output table

echo ""
echo "=== Security Groups Status ==="
aws ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Project,Values=ca-a2a" \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[*].{ID:GroupId,Name:GroupName}' \
    --output table

echo ""
echo "=== Secrets Status ==="
aws secretsmanager list-secrets \
    --region ${AWS_REGION} \
    --query 'SecretList[?starts_with(Name, `ca-a2a`)].{Name:Name,Created:CreatedDate}' \
    --output table

echo ""
echo "=== S3 Bucket Status ==="
S3_BUCKET="ca-a2a-documents-$(aws sts get-caller-identity --query Account --output text)"
aws s3 ls "s3://${S3_BUCKET}" 2>/dev/null && echo "✓ Bucket exists: ${S3_BUCKET}" || echo "✗ Bucket not found: ${S3_BUCKET}"

echo ""
echo "=== RDS Status ==="
aws rds describe-db-clusters \
    --region ${AWS_REGION} \
    --query 'DBClusters[?contains(DBClusterIdentifier, `ca-a2a`)].{ID:DBClusterIdentifier,Status:Status,Endpoint:Endpoint}' \
    --output table 2>/dev/null || echo "No RDS clusters found"

aws rds describe-db-subnet-groups \
    --region ${AWS_REGION} \
    --query 'DBSubnetGroups[?contains(DBSubnetGroupName, `ca-a2a`)].{Name:DBSubnetGroupName,VpcId:VpcId,Subnets:length(Subnets)}' \
    --output table 2>/dev/null || echo "No DB subnet groups found"

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║  Diagnostic Complete                                                  ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

