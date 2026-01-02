#!/bin/bash
# Fix Lambda Creation - Find Correct Security Group and Create Lambda

REGION="eu-west-3"
LAMBDA_NAME="ca-a2a-s3-processor"
ORCHESTRATOR_URL="http://orchestrator.ca-a2a.local:8001"
ROLE_ARN="arn:aws:iam::555043101106:role/ca-a2a-lambda-s3-processor-role"
VPC_ID="vpc-086392a3eed899f72"
SUBNET_IDS="subnet-0aef6b4fcce7748a9,subnet-07484aca0e473e3d0"

echo "============================================================="
echo "  FIXING LAMBDA CREATION"
echo "============================================================="
echo ""

# Find the correct security group
echo "Step 1: Finding correct security group..."

# Try to find ECS tasks security group
SG_ID=$(aws ec2 describe-security-groups \
  --region ${REGION} \
  --filters "Name=vpc-id,Values=${VPC_ID}" "Name=group-name,Values=*task*" \
  --query 'SecurityGroups[0].GroupId' \
  --output text 2>/dev/null)

if [ "$SG_ID" == "None" ] || [ -z "$SG_ID" ]; then
  echo "Task SG not found, trying default SG..."
  SG_ID=$(aws ec2 describe-security-groups \
    --region ${REGION} \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=group-name,Values=default" \
    --query 'SecurityGroups[0].GroupId' \
    --output text)
fi

echo "✓ Security Group: ${SG_ID}"
echo ""

# Create Lambda function
echo "Step 2: Creating Lambda function..."

LAMBDA_ARN=$(aws lambda create-function \
  --function-name ${LAMBDA_NAME} \
  --runtime python3.11 \
  --role ${ROLE_ARN} \
  --handler lambda_s3_processor.lambda_handler \
  --zip-file fileb://lambda_s3_processor.zip \
  --timeout 300 \
  --memory-size 256 \
  --region ${REGION} \
  --vpc-config SubnetIds=${SUBNET_IDS},SecurityGroupIds=${SG_ID} \
  --environment "Variables={ORCHESTRATOR_URL=${ORCHESTRATOR_URL}}" \
  --query 'FunctionArn' \
  --output text)

echo "✓ Lambda created: ${LAMBDA_ARN}"
echo ""
echo "Waiting 15 seconds for Lambda to be ready..."
sleep 15

# Add SQS trigger
echo ""
echo "Step 3: Adding SQS trigger..."

QUEUE_NAME="ca-a2a-document-uploads"
QUEUE_URL=$(aws sqs get-queue-url --queue-name ${QUEUE_NAME} --region ${REGION} --query 'QueueUrl' --output text)
QUEUE_ARN=$(aws sqs get-queue-attributes --queue-url ${QUEUE_URL} --attribute-names QueueArn --region ${REGION} --query 'Attributes.QueueArn' --output text)

aws lambda create-event-source-mapping \
  --function-name ${LAMBDA_NAME} \
  --event-source-arn ${QUEUE_ARN} \
  --batch-size 10 \
  --region ${REGION}

echo "✓ SQS trigger configured"
echo ""

# Test
echo "Step 4: Testing..."
echo "Test - $(date)" > test_lambda.txt
aws s3 cp test_lambda.txt s3://ca-a2a-documents-555043101106/invoices/2026/01/test_lambda_$(date +%s).txt --region ${REGION}
echo "✓ Test file uploaded"
echo ""
echo "Waiting 20 seconds for processing..."
sleep 20

echo ""
echo "Lambda logs:"
aws logs tail /aws/lambda/${LAMBDA_NAME} --since 1m --region ${REGION} 2>/dev/null | tail -30 || echo "(No logs yet - check in a minute)"

echo ""
echo "============================================================="
echo "  LAMBDA FIX COMPLETE!"
echo "============================================================="
echo ""

rm -f test_lambda.txt

