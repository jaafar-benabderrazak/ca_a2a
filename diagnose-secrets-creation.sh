#!/bin/bash

# Detailed diagnostic for the exact secrets creation issue

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

# Source the same tag variables
TAG_PROJECT="ca-a2a"
TAG_ENV="prod"
TAG_MANAGED_BY="cloudshell-complete-deploy"
TAG_VERSION="5.1.0"
TAG_SECURITY="full-implementation"
TAG_OWNER="Jaafar Benabderrazak"

# Replicate the create_tags function
create_tags() {
    local resource_name="${1:-resource}"
    echo "Key=Name,Value=${PROJECT_NAME}-${resource_name} Key=Project,Value=${TAG_PROJECT} Key=Environment,Value=${TAG_ENV} Key=ManagedBy,Value=${TAG_MANAGED_BY} Key=Version,Value=${TAG_VERSION} Key=Security,Value=${TAG_SECURITY} Key=Owner,Value=${TAG_OWNER}"
}

echo "=== Secrets Creation Diagnostic ==="
echo ""

# Test 1: Generate password
echo "Test 1: Generate password"
DB_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=')
echo "  Generated password length: ${#DB_PASSWORD}"
echo "  First 10 chars: ${DB_PASSWORD:0:10}..."
echo ""

# Test 2: Check create_tags output
echo "Test 2: Check create_tags function output"
TAGS_OUTPUT=$(create_tags "db-password")
echo "  Tags: $TAGS_OUTPUT"
echo ""

# Test 3: Try creating secret with verbose output
echo "Test 3: Create secret WITH output (to see what's happening)"
TEST_SECRET_NAME="${PROJECT_NAME}/diagnostic-test-$(date +%s)"
echo "  Creating: $TEST_SECRET_NAME"

set -x  # Enable command tracing
aws secretsmanager create-secret \
    --name ${TEST_SECRET_NAME} \
    --secret-string "${DB_PASSWORD}" \
    --tags $(create_tags "diagnostic-test") \
    --region ${AWS_REGION}
EXIT_CODE=$?
set +x  # Disable command tracing

echo ""
echo "  Exit code: $EXIT_CODE"

if [ $EXIT_CODE -eq 0 ]; then
    echo "  ✓ Creation succeeded!"
    echo "  Cleaning up..."
    aws secretsmanager delete-secret \
        --secret-id ${TEST_SECRET_NAME} \
        --force-delete-without-recovery \
        --region ${AWS_REGION} >/dev/null 2>&1
else
    echo "  ✗ Creation failed with exit code: $EXIT_CODE"
fi

echo ""
echo "Test 4: Try with output redirected (as in deployment script)"
TEST_SECRET_NAME="${PROJECT_NAME}/diagnostic-test-2-$(date +%s)"
echo "  Creating: $TEST_SECRET_NAME with output suppressed"

aws secretsmanager create-secret \
    --name ${TEST_SECRET_NAME} \
    --secret-string "${DB_PASSWORD}" \
    --tags $(create_tags "diagnostic-test-2") \
    --region ${AWS_REGION} >/dev/null 2>&1
EXIT_CODE=$?

echo "  Exit code: $EXIT_CODE"
if [ $EXIT_CODE -eq 0 ]; then
    echo "  ✓ Creation succeeded (silent)!"
    aws secretsmanager delete-secret \
        --secret-id ${TEST_SECRET_NAME} \
        --force-delete-without-recovery \
        --region ${AWS_REGION} >/dev/null 2>&1
else
    echo "  ✗ Creation failed silently with exit code: $EXIT_CODE"
fi

echo ""
echo "Test 5: Check if the actual secret was created during deployment"
aws secretsmanager describe-secret \
    --secret-id ca-a2a/db-password \
    --region ${AWS_REGION} 2>&1

echo ""
echo "=== Diagnostic Complete ==="
echo ""
echo "If Test 3 succeeded but Test 5 shows the secret doesn't exist,"
echo "then the issue is with the || fallback logic in the deployment script."

