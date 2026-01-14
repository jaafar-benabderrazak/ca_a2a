#!/bin/bash
# Keycloak Deployment for Git Bash on Windows
# This wrapper handles AWS SSO authentication and runs the deployment

set -e

PROFILE="AWSAdministratorAccess-555043101106"
REGION="eu-west-3"

echo "============================================"
echo "KEYCLOAK DEPLOYMENT (Git Bash)"
echo "============================================"
echo ""

# Check if AWS CLI is available
if ! command -v aws &> /dev/null; then
    echo "ERROR: AWS CLI not found. Please install it first."
    exit 1
fi

# Step 1: Login to AWS SSO
echo "[INFO] Logging in to AWS SSO..."
echo "A browser window will open for authentication."
echo ""
aws sso login --profile $PROFILE

# Step 2: Verify authentication
echo ""
echo "[INFO] Verifying AWS credentials..."
aws sts get-caller-identity --profile $PROFILE --region $REGION

if [ $? -ne 0 ]; then
    echo "[ERROR] AWS authentication failed. Please try again."
    exit 1
fi

echo ""
echo "[INFO] AWS authentication successful!"
echo ""

# Step 3: Run the Keycloak deployment script with the profile
echo "[INFO] Starting Keycloak deployment..."
echo ""

# Export AWS profile for the deployment script
export AWS_PROFILE=$PROFILE
export AWS_DEFAULT_REGION=$REGION

# Run the actual deployment script
bash deploy-keycloak.sh

echo ""
echo "============================================"
echo "DEPLOYMENT COMPLETE"
echo "============================================"
