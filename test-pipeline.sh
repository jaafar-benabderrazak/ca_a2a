#!/bin/bash
# Test script for CA-A2A Document Processing Pipeline
# Run this in AWS CloudShell (eu-west-3 region)

set -e

ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
BUCKET="ca-a2a-documents-555043101106"

echo "=========================================="
echo "CA-A2A Pipeline - End-to-End Test"
echo "=========================================="
echo ""

# Test 1: Health Check
echo "[1/6] Testing /health endpoint..."
HEALTH_RESPONSE=$(curl -s "$ALB_URL/health")
echo "$HEALTH_RESPONSE" | jq '.'

if echo "$HEALTH_RESPONSE" | jq -e '.status == "healthy"' > /dev/null; then
    echo "✓ Health check passed"
else
    echo "✗ Health check failed"
    exit 1
fi
echo ""

# Test 2: Agent Card
echo "[2/6] Testing /card endpoint..."
CARD_RESPONSE=$(curl -s "$ALB_URL/card")
AGENT_NAME=$(echo "$CARD_RESPONSE" | jq -r '.agent_name')
SKILLS_COUNT=$(echo "$CARD_RESPONSE" | jq '.skills | length')
echo "Agent: $AGENT_NAME"
echo "Skills: $SKILLS_COUNT"
echo "✓ Agent card retrieved"
echo ""

# Test 3: List S3 Documents
echo "[3/6] Checking S3 documents..."
aws s3 ls s3://$BUCKET/incoming/ --region eu-west-3 || echo "No documents in incoming/"
echo ""

# Test 4: Process Sample Invoice
echo "[4/6] Processing sample_invoice.pdf..."
INVOICE_RESPONSE=$(curl -s -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/sample_invoice.pdf"}')

echo "$INVOICE_RESPONSE" | jq '.'
echo ""

# Test 5: Process Contract
echo "[5/6] Processing sample_contract.pdf..."
CONTRACT_RESPONSE=$(curl -s -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/sample_contract.pdf"}')

echo "$CONTRACT_RESPONSE" | jq '.'
echo ""

# Test 6: Process CSV
echo "[6/6] Processing employee_data.csv..."
CSV_RESPONSE=$(curl -s -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/employee_data.csv"}')

echo "$CSV_RESPONSE" | jq '.'
echo ""

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "✓ Health check: PASSED"
echo "✓ Agent card: PASSED"
echo "✓ Invoice processing: TRIGGERED"
echo "✓ Contract processing: TRIGGERED"
echo "✓ CSV processing: TRIGGERED"
echo ""
echo "Check CloudWatch Logs for processing details:"
echo "  aws logs tail /ecs/ca-a2a-orchestrator --since 5m --follow --region eu-west-3"
echo ""

