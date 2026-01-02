# Quick SQS Policy Fix

## Issue
The `aws sqs set-queue-attributes` command is failing due to JSON escaping issues.

## ✅ Quick Fix (Run in CloudShell)

```bash
# Set variables
REGION="eu-west-3"
QUEUE_NAME="ca-a2a-document-uploads"
S3_BUCKET="ca-a2a-documents-555043101106"

# Get queue info
QUEUE_URL=$(aws sqs get-queue-url --queue-name ${QUEUE_NAME} --region ${REGION} --query 'QueueUrl' --output text)
QUEUE_ARN=$(aws sqs get-queue-attributes --queue-url ${QUEUE_URL} --attribute-names QueueArn --region ${REGION} --query 'Attributes.QueueArn' --output text)

# Create policy file
cat > /tmp/sqs-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "s3.amazonaws.com"},
    "Action": "SQS:SendMessage",
    "Resource": "QUEUE_ARN_REPLACE",
    "Condition": {
      "ArnEquals": {
        "aws:SourceArn": "arn:aws:s3:::BUCKET_REPLACE"
      }
    }
  }]
}
EOF

# Replace placeholders
sed -i "s|QUEUE_ARN_REPLACE|${QUEUE_ARN}|g" /tmp/sqs-policy.json
sed -i "s|BUCKET_REPLACE|${S3_BUCKET}|g" /tmp/sqs-policy.json

# Get the policy as a properly escaped string for JSON
POLICY=$(cat /tmp/sqs-policy.json | jq -c . | jq -R .)

# Create attributes file
echo "{\"Policy\":${POLICY}}" > /tmp/sqs-attributes.json

# Apply policy
aws sqs set-queue-attributes \
  --queue-url "${QUEUE_URL}" \
  --attributes file:///tmp/sqs-attributes.json \
  --region ${REGION}

echo "✓ SQS policy updated!"

# Now configure S3 notification
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

echo "✓ S3 notification configured!"
```

## 🎯 Or Run the Fix Script

```bash
chmod +x fix-sqs-policy.sh
./fix-sqs-policy.sh
```

Then continue with the Lambda setup manually or wait for the updated full script.

