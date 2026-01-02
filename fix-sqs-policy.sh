#!/bin/bash
# Simple fix - just update Step 2 to use file-based attributes

echo "Fixing Step 2 in setup-s3-event-pipeline.sh..."

# Get the queue URL and ARN (should already exist from Step 1)
REGION="eu-west-3"
QUEUE_NAME="ca-a2a-document-uploads"
S3_BUCKET="ca-a2a-documents-555043101106"

QUEUE_URL=$(aws sqs get-queue-url --queue-name ${QUEUE_NAME} --region ${REGION} --query 'QueueUrl' --output text)
QUEUE_ARN=$(aws sqs get-queue-attributes --queue-url ${QUEUE_URL} --attribute-names QueueArn --region ${REGION} --query 'Attributes.QueueArn' --output text)

echo "Queue URL: ${QUEUE_URL}"
echo "Queue ARN: ${QUEUE_ARN}"

# Create the policy JSON file
cat > /tmp/sqs-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "s3.amazonaws.com"},
    "Action": "SQS:SendMessage",
    "Resource": "${QUEUE_ARN}",
    "Condition": {
      "ArnEquals": {
        "aws:SourceArn": "arn:aws:s3:::${S3_BUCKET}"
      }
    }
  }]
}
EOF

echo "Policy JSON created:"
cat /tmp/sqs-policy.json

# Compact the JSON and properly escape it
POLICY_JSON=$(cat /tmp/sqs-policy.json | jq -c .)

echo ""
echo "Setting SQS policy..."

# Use a temp file for attributes
cat > /tmp/sqs-attributes.json << ATTREOF
{
  "Policy": $(echo "$POLICY_JSON" | jq -R .)
}
ATTREOF

echo "Attributes JSON:"
cat /tmp/sqs-attributes.json

# Apply the policy
aws sqs set-queue-attributes \
  --queue-url "${QUEUE_URL}" \
  --attributes file:///tmp/sqs-attributes.json \
  --region ${REGION}

echo "✓ SQS policy updated"

# Now continue with S3 notification
echo ""
echo "Configuring S3 bucket notification..."

cat > /tmp/s3-notification.json << EOF
{
  "QueueConfigurations": [{
    "QueueArn": "${QUEUE_ARN}",
    "Events": ["s3:ObjectCreated:*"],
    "Filter": {
      "Key": {
        "FilterRules": [{
          "Name": "prefix",
          "Value": "invoices/"
        }, {
          "Name": "suffix",
          "Value": ".pdf"
        }]
      }
    }
  }]
}
EOF

aws s3api put-bucket-notification-configuration \
  --bucket ${S3_BUCKET} \
  --region ${REGION} \
  --notification-configuration file:///tmp/s3-notification.json

echo "✓ S3 event notification configured"
echo ""
echo "✓ Setup complete! You can now continue with the rest of the pipeline setup."

