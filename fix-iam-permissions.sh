#!/bin/bash
# Fix IAM permissions for ECS Execution Role to access Secrets Manager

export AWS_REGION="${AWS_REGION:-eu-west-3}"
export AWS_PROFILE="${AWS_PROFILE:-reply-sso}"
export EXECUTION_ROLE="ca-a2a-ecs-execution-role"
export SECRET_ARN="arn:aws:secretsmanager:${AWS_REGION}:555043101106:secret:ca-a2a/db-password"

echo "=========================================="
echo "Fix ECS Execution Role Permissions"
echo "=========================================="
echo ""

# Step 1: Check if secret exists
echo "[1/3] Checking if secret exists..."
SECRET_CHECK=$(aws secretsmanager describe-secret \
    --secret-id ca-a2a/db-password \
    --region $AWS_REGION \
    --profile $AWS_PROFILE \
    --query 'ARN' \
    --output text 2>&1)

if [[ $SECRET_CHECK == *"ResourceNotFoundException"* ]]; then
    echo "  ✗ Secret does not exist. Creating it..."
    aws secretsmanager create-secret \
        --name ca-a2a/db-password \
        --secret-string "benabderrazak" \
        --region $AWS_REGION \
        --profile $AWS_PROFILE
    echo "  ✓ Secret created"
else
    echo "  ✓ Secret exists: $SECRET_CHECK"
fi

echo ""

# Step 2: Create IAM policy for Secrets Manager access
echo "[2/3] Creating IAM policy for Secrets Manager access..."

POLICY_NAME="ca-a2a-secrets-manager-policy"

# Check if policy already exists
POLICY_ARN=$(aws iam list-policies \
    --scope Local \
    --profile $AWS_PROFILE \
    --query "Policies[?PolicyName=='${POLICY_NAME}'].Arn" \
    --output text 2>&1)

if [ -z "$POLICY_ARN" ] || [ "$POLICY_ARN" == "None" ]; then
    echo "  Creating policy..."
    
    POLICY_DOCUMENT=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:${AWS_REGION}:555043101106:secret:ca-a2a/*"
      ]
    }
  ]
}
EOF
)
    
    POLICY_ARN=$(aws iam create-policy \
        --policy-name $POLICY_NAME \
        --policy-document "$POLICY_DOCUMENT" \
        --profile $AWS_PROFILE \
        --query 'Policy.Arn' \
        --output text)
    
    echo "  ✓ Policy created: $POLICY_ARN"
else
    echo "  ✓ Policy already exists: $POLICY_ARN"
fi

echo ""

# Step 3: Attach policy to execution role
echo "[3/3] Attaching policy to ECS execution role..."

aws iam attach-role-policy \
    --role-name $EXECUTION_ROLE \
    --policy-arn $POLICY_ARN \
    --profile $AWS_PROFILE 2>&1 || echo "  (Policy may already be attached)"

echo "  ✓ Policy attached to role: $EXECUTION_ROLE"

echo ""
echo "=========================================="
echo "Permissions Fixed!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Wait 10-15 seconds for IAM changes to propagate"
echo "2. Restart ECS services:"
echo "   aws ecs update-service --cluster ca-a2a-cluster --service extractor --force-new-deployment --region $AWS_REGION --profile $AWS_PROFILE"
echo "   aws ecs update-service --cluster ca-a2a-cluster --service validator --force-new-deployment --region $AWS_REGION --profile $AWS_PROFILE"
echo "   aws ecs update-service --cluster ca-a2a-cluster --service archivist --force-new-deployment --region $AWS_REGION --profile $AWS_PROFILE"
echo ""

