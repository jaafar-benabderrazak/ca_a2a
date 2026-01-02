#!/bin/bash
# Lambda Setup - Steps 4-9 for S3 Event Pipeline

set -e

REGION="eu-west-3"
ACCOUNT_ID="555043101106"
S3_BUCKET="ca-a2a-documents-555043101106"
QUEUE_NAME="ca-a2a-document-uploads"
LAMBDA_NAME="ca-a2a-s3-processor"
ORCHESTRATOR_URL="http://orchestrator.ca-a2a.local:8001"

echo "============================================================="
echo "  LAMBDA SETUP - Steps 4-9"
echo "============================================================="
echo ""

# Get queue info
QUEUE_URL=$(aws sqs get-queue-url --queue-name ${QUEUE_NAME} --region ${REGION} --query 'QueueUrl' --output text)
QUEUE_ARN=$(aws sqs get-queue-attributes --queue-url ${QUEUE_URL} --attribute-names QueueArn --region ${REGION} --query 'Attributes.QueueArn' --output text)

# ==============================================================
# STEP 4: Create Lambda Execution Role
# ==============================================================
echo "Step 4: Creating Lambda execution role..."

ROLE_NAME="ca-a2a-lambda-s3-processor-role"
ROLE_ARN=$(aws iam get-role --role-name ${ROLE_NAME} --query 'Role.Arn' --output text 2>/dev/null || echo "")

if [ -z "$ROLE_ARN" ]; then
  echo "Creating new IAM role..."
  
  cat > /tmp/lambda-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF
  
  aws iam create-role \
    --role-name ${ROLE_NAME} \
    --assume-role-policy-document file:///tmp/lambda-trust-policy.json
  
  # Attach policies
  aws iam attach-role-policy \
    --role-name ${ROLE_NAME} \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  
  aws iam attach-role-policy \
    --role-name ${ROLE_NAME} \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole
  
  aws iam attach-role-policy \
    --role-name ${ROLE_NAME} \
    --policy-arn arn:aws:iam::aws:policy/AmazonSQSFullAccess
  
  aws iam attach-role-policy \
    --role-name ${ROLE_NAME} \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
  
  echo "Waiting 15 seconds for IAM role to propagate..."
  sleep 15
  
  ROLE_ARN=$(aws iam get-role --role-name ${ROLE_NAME} --query 'Role.Arn' --output text)
else
  echo "Using existing IAM role"
fi

echo "✓ Lambda role ready: ${ROLE_ARN}"
echo ""

# ==============================================================
# STEP 5: Create Lambda Function Code
# ==============================================================
echo "Step 5: Creating Lambda function code..."

cat > lambda_s3_processor.py << 'LAMBDA_EOF'
import json
import boto3
import urllib3
import os
from urllib.parse import unquote_plus

http = urllib3.PoolManager()
orchestrator_url = os.environ.get('ORCHESTRATOR_URL', 'http://orchestrator.ca-a2a.local:8001')

def lambda_handler(event, context):
    """
    Process S3 events from SQS and trigger orchestrator
    """
    print(f"Received event with {len(event.get('Records', []))} records")
    
    processed = 0
    errors = []
    
    for record in event.get('Records', []):
        try:
            # Parse SQS message
            message_body = json.loads(record['body'])
            
            # Extract S3 event
            for s3_record in message_body.get('Records', []):
                bucket = s3_record['s3']['bucket']['name']
                key = unquote_plus(s3_record['s3']['object']['key'])
                
                print(f"Processing: s3://{bucket}/{key}")
                
                # Call orchestrator API
                payload = {
                    "jsonrpc": "2.0",
                    "method": "process_document",
                    "params": {
                        "s3_key": key,
                        "priority": "normal"
                    },
                    "id": f"lambda-{context.request_id}"
                }
                
                response = http.request(
                    'POST',
                    f"{orchestrator_url}/a2a",
                    body=json.dumps(payload).encode('utf-8'),
                    headers={'Content-Type': 'application/json'},
                    timeout=30.0
                )
                
                if response.status == 200:
                    result = json.loads(response.data.decode('utf-8'))
                    print(f"✓ Processing started: {result}")
                    processed += 1
                else:
                    error_msg = f"Orchestrator returned {response.status}: {response.data}"
                    print(f"✗ Error: {error_msg}")
                    errors.append(error_msg)
                    
        except Exception as e:
            error_msg = f"Failed to process record: {str(e)}"
            print(f"✗ Error: {error_msg}")
            errors.append(error_msg)
    
    return {
        'statusCode': 200 if not errors else 207,
        'body': json.dumps({
            'processed': processed,
            'errors': errors
        })
    }
LAMBDA_EOF

# Package Lambda function
zip -q lambda_s3_processor.zip lambda_s3_processor.py

echo "✓ Lambda function code packaged"
echo ""

# ==============================================================
# STEP 6: Get VPC Configuration for Lambda
# ==============================================================
echo "Step 6: Getting VPC configuration..."

# Get VPC ID
VPC_ID=$(aws ec2 describe-vpcs \
  --region ${REGION} \
  --filters "Name=tag:Name,Values=*ca-a2a*" \
  --query 'Vpcs[0].VpcId' \
  --output text 2>/dev/null || \
  aws ec2 describe-vpcs --region ${REGION} --query 'Vpcs[0].VpcId' --output text)

# Get private subnet IDs
SUBNET_IDS=$(aws ec2 describe-subnets \
  --region ${REGION} \
  --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Name,Values=*private*" \
  --query 'Subnets[*].SubnetId' \
  --output text 2>/dev/null || \
  aws ec2 describe-subnets \
    --region ${REGION} \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'Subnets[0:2].SubnetId' \
    --output text)

# Get security group for ECS tasks
SECURITY_GROUP_ID=$(aws ec2 describe-security-groups \
  --region ${REGION} \
  --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Name,Values=*ca-a2a*task*" \
  --query 'SecurityGroups[0].GroupId' \
  --output text 2>/dev/null || \
  aws ec2 describe-security-groups \
    --region ${REGION} \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query 'SecurityGroups[0].GroupId' \
    --output text)

echo "✓ VPC Configuration:"
echo "  VPC ID: ${VPC_ID}"
echo "  Subnets: ${SUBNET_IDS}"
echo "  Security Group: ${SECURITY_GROUP_ID}"
echo ""

# ==============================================================
# STEP 7: Create/Update Lambda Function
# ==============================================================
echo "Step 7: Creating/updating Lambda function..."

LAMBDA_ARN=$(aws lambda get-function \
  --function-name ${LAMBDA_NAME} \
  --region ${REGION} \
  --query 'Configuration.FunctionArn' \
  --output text 2>/dev/null || echo "")

if [ -z "$LAMBDA_ARN" ]; then
  echo "Creating new Lambda function..."
  
  LAMBDA_ARN=$(aws lambda create-function \
    --function-name ${LAMBDA_NAME} \
    --runtime python3.11 \
    --role ${ROLE_ARN} \
    --handler lambda_s3_processor.lambda_handler \
    --zip-file fileb://lambda_s3_processor.zip \
    --timeout 300 \
    --memory-size 256 \
    --region ${REGION} \
    --vpc-config SubnetIds=${SUBNET_IDS// /,},SecurityGroupIds=${SECURITY_GROUP_ID} \
    --environment "Variables={ORCHESTRATOR_URL=${ORCHESTRATOR_URL}}" \
    --query 'FunctionArn' \
    --output text)
  
  echo "Waiting 10 seconds for Lambda to be ready..."
  sleep 10
else
  echo "Updating existing Lambda function..."
  
  aws lambda update-function-code \
    --function-name ${LAMBDA_NAME} \
    --zip-file fileb://lambda_s3_processor.zip \
    --region ${REGION}
  
  aws lambda update-function-configuration \
    --function-name ${LAMBDA_NAME} \
    --vpc-config SubnetIds=${SUBNET_IDS// /,},SecurityGroupIds=${SECURITY_GROUP_ID} \
    --environment "Variables={ORCHESTRATOR_URL=${ORCHESTRATOR_URL}}" \
    --region ${REGION}
  
  sleep 5
fi

echo "✓ Lambda function ready: ${LAMBDA_ARN}"
echo ""

# ==============================================================
# STEP 8: Add SQS Trigger to Lambda
# ==============================================================
echo "Step 8: Configuring SQS trigger for Lambda..."

# Check if mapping already exists
MAPPING_UUID=$(aws lambda list-event-source-mappings \
  --function-name ${LAMBDA_NAME} \
  --region ${REGION} \
  --query "EventSourceMappings[?EventSourceArn=='${QUEUE_ARN}'].UUID" \
  --output text 2>/dev/null || echo "")

if [ -z "$MAPPING_UUID" ]; then
  echo "Creating event source mapping..."
  
  aws lambda create-event-source-mapping \
    --function-name ${LAMBDA_NAME} \
    --event-source-arn ${QUEUE_ARN} \
    --batch-size 10 \
    --region ${REGION}
else
  echo "Event source mapping already exists: ${MAPPING_UUID}"
fi

echo "✓ Lambda trigger configured"
echo ""

# ==============================================================
# STEP 9: Test the Pipeline
# ==============================================================
echo "Step 9: Testing the pipeline..."
echo ""
echo "Creating test file and uploading to S3..."

echo "Test invoice from automated pipeline setup - $(date)" > test_pipeline_invoice.txt

aws s3 cp test_pipeline_invoice.txt \
  s3://${S3_BUCKET}/invoices/2026/01/test_pipeline_invoice_$(date +%s).txt \
  --region ${REGION}

echo "✓ Test file uploaded"
echo ""
echo "Waiting 15 seconds for event processing..."
sleep 15

# Check SQS for messages
echo ""
echo "Checking SQS queue status..."
aws sqs get-queue-attributes \
  --queue-url ${QUEUE_URL} \
  --attribute-names ApproximateNumberOfMessages,ApproximateNumberOfMessagesNotVisible \
  --region ${REGION} \
  --output table

echo ""
echo "Checking Lambda logs..."
aws logs tail /aws/lambda/${LAMBDA_NAME} --since 2m --region ${REGION} 2>/dev/null | tail -20 || echo "(No logs yet - Lambda may not have been triggered)"

echo ""
echo "Checking orchestrator logs for processing..."
aws logs tail /ecs/ca-a2a-orchestrator --since 2m --region ${REGION} 2>/dev/null \
  | grep -E "process_document|task_id|test_pipeline" | tail -10 || echo "(No processing logs yet)"

echo ""
echo "============================================================="
echo "  S3 EVENT PIPELINE SETUP COMPLETE!"
echo "============================================================="
echo ""
echo "Summary:"
echo "  ✓ SQS Queue: ${QUEUE_NAME}"
echo "  ✓ S3 Notifications: Configured for invoices/*.pdf"
echo "  ✓ Lambda Function: ${LAMBDA_NAME}"
echo "  ✓ Lambda Trigger: SQS → Lambda"
echo "  ✓ Pipeline: S3 → SQS → Lambda → Orchestrator"
echo ""
echo "Next Steps:"
echo "  1. Upload a PDF to test:"
echo "     aws s3 cp facture_acme_dec2025.pdf s3://${S3_BUCKET}/invoices/2026/01/ --region ${REGION}"
echo ""
echo "  2. Monitor processing:"
echo "     aws logs tail /aws/lambda/${LAMBDA_NAME} --follow --region ${REGION}"
echo "     aws logs tail /ecs/ca-a2a-orchestrator --follow --region ${REGION}"
echo ""
echo "  3. Check SQS queue:"
echo "     aws sqs get-queue-attributes --queue-url ${QUEUE_URL} --attribute-names All --region ${REGION}"
echo ""
echo "Cleanup temporary files..."
rm -f lambda_s3_processor.py lambda_s3_processor.zip test_pipeline_invoice.txt

echo ""
echo "✓ Complete! Your automated document processing pipeline is ready! 🚀"

