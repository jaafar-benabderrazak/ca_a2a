#!/bin/bash
# Rebuild extractor in ECS using existing tools (no local Docker needed)
# Run this in AWS CloudShell

set -e

REGION="${REGION:-eu-west-3}"
CLUSTER="ca-a2a-cluster"
SERVICE="extractor"

echo "============================================"
echo "UPDATE EXTRACTOR CODE IN ECS"
echo "============================================"
echo ""

echo "Since we can't build Docker images in CloudShell, we'll:"
echo "1. Download the updated extractor code from your repo"
echo "2. Force a new deployment with environment variable to bypass cache"
echo "3. Or manually update the extractor agent code on running tasks"
echo ""

# Option 1: Force restart to pickup latest code (if image pulls from latest tag)
echo "Option 1: Force ECS to restart with fresh deployment"
echo ""

read -p "Do you want to force-restart the extractor service? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Forcing new deployment..."
    aws ecs update-service \
        --cluster "${CLUSTER}" \
        --service "${SERVICE}" \
        --force-new-deployment \
        --region "${REGION}" > /dev/null
    
    echo "✓ Deployment initiated"
    echo ""
    echo "Wait 60 seconds for new tasks to start..."
    sleep 60
    
    echo "Testing pipeline..."
    ./test-complete-pipeline-simple.sh
fi

echo ""
echo "============================================"
echo "ALTERNATIVE: Manual Code Update"
echo "============================================"
echo ""
echo "If the extractor is still using old code, you need to:"
echo ""
echo "1. On your LOCAL machine with Docker:"
echo "   - Configure AWS: aws configure"
echo "   - Run: ./deploy-fixed-extractor.sh"
echo ""
echo "2. Or build Docker image elsewhere and push to ECR"
echo ""
echo "3. Or temporarily skip PDF extraction for testing:"
echo "   We can test validator and archivist with mock data"
echo ""

read -p "Do you want to test validator/archivist with mock data? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Creating test script for validator/archivist..."
    
    # Create a test that directly calls validator with mock extracted data
    cat > test-validator-archivist.sh << 'TEST_EOF'
#!/bin/bash
# Test validator and archivist directly with mock data

REGION="${REGION:-eu-west-3}"

echo "============================================"
echo "TEST VALIDATOR & ARCHIVIST DIRECTLY"
echo "============================================"
echo ""

# Get orchestrator IP
TASK_ARN=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --region "${REGION}" \
  --desired-status RUNNING \
  --query 'taskArns[0]' \
  --output text)

ORCH_IP=$(aws ecs describe-tasks \
  --cluster ca-a2a-cluster \
  --tasks "${TASK_ARN}" \
  --region "${REGION}" \
  --query 'tasks[0].attachments[0].details[?name==`privateIPv4Address`].value' \
  --output text)

echo "Orchestrator IP: ${ORCH_IP}"

# Get Lambda API key
API_KEY=$(aws lambda get-function-configuration \
  --function-name ca-a2a-s3-processor \
  --region "${REGION}" \
  --query 'Environment.Variables.A2A_API_KEY' \
  --output text)

echo "API Key configured: Yes"
echo ""

# Create mock extracted data (simulating successful extraction)
cat > mock_request.json << 'JSON_EOF'
{
  "jsonrpc": "2.0",
  "method": "validate_document",
  "params": {
    "s3_key": "invoices/2026/01/mock_test.pdf",
    "document_type": "invoice",
    "extracted_data": {
      "invoice_number": "FAC-2026-001",
      "invoice_date": "2026-01-02",
      "customer_name": "ACME Corporation",
      "total_amount": 12000.00,
      "currency": "EUR",
      "items": [
        {"description": "Services", "amount": 10000.00},
        {"description": "VAT 20%", "amount": 2000.00}
      ]
    }
  },
  "id": "test-validator-001"
}
JSON_EOF

echo "Testing validator with mock data..."
echo ""

# Call validator directly through orchestrator (need to get validator IP first)
VALIDATOR_TASK=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name validator \
  --region "${REGION}" \
  --desired-status RUNNING \
  --query 'taskArns[0]' \
  --output text)

if [ -z "$VALIDATOR_TASK" ] || [ "$VALIDATOR_TASK" = "None" ]; then
    echo "❌ Validator not running"
    exit 1
fi

echo "✅ Validator is running"
echo ""
echo "Note: Direct testing requires exec into tasks or using the orchestrator API"
echo "For now, the full pipeline needs the extractor fix deployed."

rm -f mock_request.json
TEST_EOF

    chmod +x test-validator-archivist.sh
    echo "✓ Created test-validator-archivist.sh"
    echo ""
    echo "This requires more complex setup. The best path forward is:"
    echo "  1. Configure AWS credentials on your local machine"
    echo "  2. Run ./deploy-fixed-extractor.sh locally"
    echo "  3. Then test the complete pipeline"
fi

echo ""
echo "============================================"
echo "SUMMARY"
echo "============================================"
echo ""
echo "To fix PDF extraction and enable full pipeline:"
echo ""
echo "1. ON YOUR LOCAL MACHINE (Git Bash):"
echo "   aws configure  # Enter your AWS credentials"
echo "   cd /c/Users/Utilisateur/Desktop/projects/ca_a2a"
echo "   ./deploy-fixed-extractor.sh"
echo ""
echo "2. THEN IN CLOUDSHELL:"
echo "   ./test-complete-pipeline-simple.sh"
echo ""
echo "This will enable the complete 4-agent pipeline:"
echo "  Orchestrator → Extractor → Validator → Archivist"

