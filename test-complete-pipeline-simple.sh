#!/bin/bash
# Test complete pipeline with real invoice (no Docker build needed)

set -e

REGION="${REGION:-eu-west-3}"

echo "============================================"
echo "TEST COMPLETE PIPELINE WITH REAL INVOICE"
echo "============================================"
echo ""

# Check if facture_acme_dec2025.pdf exists
if [ ! -f "facture_acme_dec2025.pdf" ]; then
  echo "Creating a simple but valid invoice PDF..."
  
  # Create a minimal but valid PDF
  cat > test_invoice.pdf << 'EOF'
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources <<
/Font <<
/F1 5 0 R
>>
>>
>>
endobj
4 0 obj
<<
/Length 500
>>
stream
BT
/F1 16 Tf
50 750 Td
(FACTURE) Tj
/F1 12 Tf
50 720 Td
(Numero: FAC-2026-001) Tj
50 700 Td
(Date: 02 janvier 2026) Tj
50 670 Td
(Client: ACME Corporation) Tj
50 650 Td
(Adresse: 123 rue de Paris, 75001 Paris) Tj
50 620 Td
(Description:) Tj
50 600 Td
(  - Services de consultation: 5,000.00 EUR) Tj
50 580 Td
(  - Developpement logiciel: 3,000.00 EUR) Tj
50 560 Td
(  - Formation equipe: 2,000.00 EUR) Tj
50 530 Td
(Sous-total HT: 10,000.00 EUR) Tj
50 510 Td
(TVA 20%: 2,000.00 EUR) Tj
50 490 Td
(TOTAL TTC: 12,000.00 EUR) Tj
50 460 Td
(Date d'echeance: 01 fevrier 2026) Tj
ET
endstream
endobj
5 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000270 00000 n
0000000819 00000 n
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
896
%%EOF
EOF
  
  TEST_FILE="test_invoice.pdf"
else
  TEST_FILE="facture_acme_dec2025.pdf"
  echo "Using existing invoice: $TEST_FILE"
fi

TIMESTAMP=$(date +%s)
S3_KEY="invoices/2026/01/test_pipeline_${TIMESTAMP}.pdf"

echo ""
echo "============================================"
echo "UPLOAD TEST INVOICE"
echo "============================================"
echo ""

echo "Uploading: ${S3_KEY}"
aws s3 cp "${TEST_FILE}" \
  "s3://ca-a2a-documents-555043101106/${S3_KEY}" \
  --region "${REGION}"

echo "✓ Uploaded to s3://ca-a2a-documents-555043101106/${S3_KEY}"

echo ""
echo "Waiting 35 seconds for complete pipeline processing..."
sleep 35

echo ""
echo "============================================"
echo "LAMBDA LOGS"
echo "============================================"
aws logs tail /aws/lambda/ca-a2a-s3-processor \
  --since 2m \
  --region "${REGION}" \
  --format short 2>/dev/null \
  | grep -E "Processing|Orchestrator response|Success|Error|task_id" \
  | tail -8

echo ""
echo "============================================"
echo "ORCHESTRATOR LOGS - PIPELINE STAGES"
echo "============================================"
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 2m \
  --region "${REGION}" \
  --format short 2>/dev/null \
  | grep -E "Starting document processing|Starting extraction|Extraction completed|Starting validation|Validation completed|Starting archiving|Archiving completed|Pipeline completed|Pipeline failed" \
  | tail -20

echo ""
echo "============================================"
echo "EXTRACTOR LOGS"
echo "============================================"
aws logs tail /ecs/ca-a2a-extractor \
  --since 2m \
  --region "${REGION}" \
  --format short 2>/dev/null \
  | grep -E "Extracting document|extraction completed|extraction failed|pages|Fallback|PyPDF2" \
  | tail -10

echo ""
echo "============================================"
echo "VALIDATOR LOGS"
echo "============================================"
VALIDATOR_LOGS=$(aws logs tail /ecs/ca-a2a-validator \
  --since 2m \
  --region "${REGION}" \
  --format short 2>/dev/null \
  | grep -v "GET /health" \
  | tail -8)

if [ -z "$VALIDATOR_LOGS" ]; then
  echo "No validator activity (may not have reached this stage)"
else
  echo "$VALIDATOR_LOGS"
fi

echo ""
echo "============================================"
echo "ARCHIVIST LOGS"
echo "============================================"
ARCHIVIST_LOGS=$(aws logs tail /ecs/ca-a2a-archivist \
  --since 2m \
  --region "${REGION}" \
  --format short 2>/dev/null \
  | grep -v "GET /health" \
  | tail -8)

if [ -z "$ARCHIVIST_LOGS" ]; then
  echo "No archivist activity (may not have reached this stage)"
else
  echo "$ARCHIVIST_LOGS"
fi

echo ""
echo "============================================"
echo "PIPELINE ANALYSIS"
echo "============================================"
echo ""

# Check what stages were reached
ORCH_LOGS=$(aws logs tail /ecs/ca-a2a-orchestrator --since 2m --region "${REGION}" 2>/dev/null)

if echo "$ORCH_LOGS" | grep -q "Pipeline completed successfully"; then
  echo "🎉 🎉 🎉 COMPLETE PIPELINE SUCCESS! 🎉 🎉 🎉"
  echo ""
  echo "✅ Orchestrator coordinated all agents"
  echo "✅ Extractor parsed the PDF"
  echo "✅ Validator validated the data"
  echo "✅ Archivist stored to database"
  echo ""
  echo "All 4 agents working together successfully!"
  
elif echo "$ORCH_LOGS" | grep -q "Starting validation"; then
  echo "✅ Extraction COMPLETED - Validator called!"
  echo ""
  if echo "$ORCH_LOGS" | grep -q "Starting archiving"; then
    echo "✅ Validation COMPLETED - Archivist called!"
    echo "✅ Pipeline reached all 3 stages"
  else
    echo "⚠️  Validation in progress or failed"
    echo "Check validator logs above for details"
  fi
  
elif echo "$ORCH_LOGS" | grep -q "Starting extraction"; then
  echo "⚠️  Pipeline started but extraction may have failed"
  echo ""
  if echo "$ORCH_LOGS" | grep -q "Pipeline failed"; then
    echo "❌ Pipeline failed at extraction stage"
    echo ""
    echo "Error details:"
    echo "$ORCH_LOGS" | grep -A 2 "Pipeline failed" | tail -3
  fi
  
else
  echo "⚠️  Pipeline may not have started"
  echo "Check Lambda logs above for trigger status"
fi

# Cleanup
rm -f test_invoice.pdf

echo ""
echo "============================================"
echo "NEXT STEPS"
echo "============================================"
echo ""

if echo "$ORCH_LOGS" | grep -q "Pipeline completed successfully"; then
  echo "🎉 System is fully operational!"
  echo ""
  echo "You can now:"
  echo "  1. Query database for processed documents"
  echo "  2. Upload more invoices for processing"
  echo "  3. Scale agents based on workload"
  echo ""
  echo "To check database:"
  echo "  SELECT * FROM documents ORDER BY processing_date DESC LIMIT 5;"
  
elif echo "$ORCH_LOGS" | grep -q "PDF extraction.*failed"; then
  echo "The extractor needs the code update deployed to ECS."
  echo ""
  echo "To deploy from your local machine:"
  echo "  1. cd c:/Users/Utilisateur/Desktop/projects/ca_a2a"
  echo "  2. Build: docker build -t ca-a2a-extractor:fixed -f Dockerfile.extractor ."
  echo "  3. Push to ECR and update ECS service"
  echo ""
  echo "Or wait for the next ECS deployment cycle to pick up the changes."
  
else
  echo "Check the logs above to diagnose any issues."
  echo ""
  echo "Common issues:"
  echo "  - Extraction errors: Check extractor logs"
  echo "  - Network issues: Check security groups"
  echo "  - Auth issues: Check API keys and RBAC"
fi

