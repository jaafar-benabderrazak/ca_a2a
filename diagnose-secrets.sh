#!/bin/bash

# Diagnostic script to identify Secrets Manager issues

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

echo "=== Secrets Manager Diagnostic ==="
echo ""

echo "Step 1: Check if secret already exists (including deleted secrets)"
aws secretsmanager describe-secret \
    --secret-id ${PROJECT_NAME}/db-password \
    --region ${AWS_REGION} 2>&1 || echo "Secret does not exist (this is good for fresh deployment)"

echo ""
echo "Step 2: List all secrets with 'ca-a2a' in name"
aws secretsmanager list-secrets \
    --region ${AWS_REGION} \
    --query 'SecretList[?contains(Name, `ca-a2a`)].{Name:Name,Status:DeletedDate}' \
    --output table

echo ""
echo "Step 3: Test secret creation with minimal parameters"
TEST_SECRET_NAME="${PROJECT_NAME}/test-secret-$(date +%s)"
echo "Creating test secret: $TEST_SECRET_NAME"
aws secretsmanager create-secret \
    --name ${TEST_SECRET_NAME} \
    --secret-string "test-value" \
    --region ${AWS_REGION} 2>&1

if [ $? -eq 0 ]; then
    echo "✓ Basic secret creation works"
    echo "  Cleaning up test secret..."
    aws secretsmanager delete-secret \
        --secret-id ${TEST_SECRET_NAME} \
        --force-delete-without-recovery \
        --region ${AWS_REGION} >/dev/null 2>&1
else
    echo "✗ Basic secret creation failed - check AWS permissions"
fi

echo ""
echo "Step 4: Test secret creation with tags"
TEST_SECRET_NAME="${PROJECT_NAME}/test-secret-with-tags-$(date +%s)"
echo "Creating test secret with tags: $TEST_SECRET_NAME"
aws secretsmanager create-secret \
    --name ${TEST_SECRET_NAME} \
    --secret-string "test-value" \
    --tags Key=Project,Value=ca-a2a Key=Test,Value=diagnostic \
    --region ${AWS_REGION} 2>&1

if [ $? -eq 0 ]; then
    echo "✓ Secret creation with tags works"
    echo "  Cleaning up test secret..."
    aws secretsmanager delete-secret \
        --secret-id ${TEST_SECRET_NAME} \
        --force-delete-without-recovery \
        --region ${AWS_REGION} >/dev/null 2>&1
else
    echo "✗ Secret creation with tags failed"
fi

echo ""
echo "Step 5: Check IAM permissions"
aws sts get-caller-identity --region ${AWS_REGION}

echo ""
echo "=== Diagnostic Complete ==="

