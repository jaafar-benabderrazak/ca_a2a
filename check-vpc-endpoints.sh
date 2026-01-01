#!/bin/bash
# Check status of VPC endpoints

export AWS_REGION="${AWS_REGION:-eu-west-3}"
export VPC_ID="${VPC_ID:-vpc-086392a3eed899f72}"

echo "Checking VPC endpoints status..."
echo ""

aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --region $AWS_REGION \
    --query 'VpcEndpoints[*].[VpcEndpointId,ServiceName,State,VpcEndpointType]' \
    --output table

echo ""
echo "All endpoints should be in 'available' state before restarting ECS services."

