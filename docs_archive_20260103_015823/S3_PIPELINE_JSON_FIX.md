# Quick Fix for S3 Pipeline Script - JSON Escaping

## 🎯 Quick Fix (Run in CloudShell)

The issue is with JSON escaping in embedded quotes. Here's the quickest fix:

### Option 1: Re-create the script (Fastest)

```bash
# Backup current script
mv setup-s3-event-pipeline.sh setup-s3-event-pipeline.sh.backup

# Download and run the fix script
cat update-s3-pipeline-script.sh | bash

# Or manually download from Cursor and upload the updated version
```

### Option 2: Manual Fix (Line 72 and 108)

The problem is that `jq` needs to properly escape the JSON. Fix these two sections:

**Fix #1 - Line ~72 (SQS Policy):**

Replace the `aws sqs set-queue-attributes` section with:
```bash
# Create policy in temp file
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

POLICY_STRING=$(cat /tmp/sqs-policy.json | jq -c . | jq -Rs .)

aws sqs set-queue-attributes \
  --queue-url ${QUEUE_URL} \
  --region ${REGION} \
  --attributes "{\"Policy\":${POLICY_STRING}}"
```

**Fix #2 - Line ~108 (S3 Notification):**

Already using `file://` which is good, just make sure it uses temp file:
```bash
# Create notification config in temp file
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
```

### Option 3: Upload Updated File from Cursor

The file `setup-s3-event-pipeline.sh` in Cursor has been updated with the fixes.

1. In CloudShell, click **Actions** → **Upload file**
2. Select `setup-s3-event-pipeline.sh` (will overwrite)
3. Run:
```bash
chmod +x setup-s3-event-pipeline.sh
./setup-s3-event-pipeline.sh
```

## 🚀 Recommended: Use the Update Script

```bash
# Run the auto-fixer
bash update-s3-pipeline-script.sh

# Then run the fixed script
./setup-s3-event-pipeline.sh
```

This will handle all JSON escaping issues automatically!

