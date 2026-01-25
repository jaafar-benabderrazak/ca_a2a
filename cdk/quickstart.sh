#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
# CA-A2A CDK Quick Start for AWS Cloud Shell
# ══════════════════════════════════════════════════════════════════════════════

set -e

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                        ║"
echo "║       CA-A2A AWS CDK Deployment - Quick Start                         ║"
echo "║                                                                        ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

cd "$(dirname "$0")"

# Check if CDK is installed
if ! command -v cdk &> /dev/null; then
    echo "✗ AWS CDK not found!"
    echo "  Please install: npm install -g aws-cdk"
    exit 1
fi

echo "✓ AWS CDK version: $(cdk --version)"
echo ""

# Install Python dependencies
echo "▸ Installing Python dependencies..."
python3 -m pip install -r requirements.txt --user --quiet
echo "✓ Dependencies installed"
echo ""

# Check if CDK is bootstrapped
echo "▸ Checking CDK bootstrap status..."
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=${AWS_REGION:-us-east-1}

echo "  Account: $ACCOUNT_ID"
echo "  Region: $REGION"
echo ""

# Try to check if bootstrap stack exists
BOOTSTRAP_STACK=$(aws cloudformation describe-stacks \
    --stack-name CDKToolkit \
    --region $REGION \
    --query 'Stacks[0].StackStatus' \
    --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$BOOTSTRAP_STACK" == "NOT_FOUND" ]; then
    echo "⚠  CDK not bootstrapped for this account/region"
    echo ""
    read -p "Bootstrap CDK now? (yes/no): " CONFIRM
    if [ "$CONFIRM" == "yes" ]; then
        echo "▸ Bootstrapping CDK..."
        cdk bootstrap aws://$ACCOUNT_ID/$REGION
        echo "✓ CDK bootstrapped"
    else
        echo "✗ Bootstrap required before deployment"
        echo "  Run: cdk bootstrap"
        exit 1
    fi
else
    echo "✓ CDK already bootstrapped"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo ""
echo "Ready to deploy! Choose an option:"
echo ""
echo "  1. Preview changes:  cdk diff"
echo "  2. Deploy stack:     cdk deploy"
echo "  3. Destroy stack:    cdk destroy"
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

read -p "Deploy now? (yes/no): " DEPLOY
if [ "$DEPLOY" == "yes" ]; then
    echo ""
    echo "▸ Starting deployment..."
    echo "  (This will take 15-20 minutes)"
    echo ""
    cdk deploy --require-approval never
    
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                        ║"
    echo "║                    ✅ Deployment Complete!                            ║"
    echo "║                                                                        ║"
    echo "╚═══════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Next steps:"
    echo "  1. Check stack outputs: cdk deploy --outputs-file outputs.json"
    echo "  2. View resources: aws cloudformation describe-stack-resources --stack-name ca-a2a-prod"
    echo "  3. Deploy ECS services (Docker containers)"
    echo ""
else
    echo ""
    echo "To deploy later, run:"
    echo "  cd cdk && cdk deploy"
    echo ""
fi

