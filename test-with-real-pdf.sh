#!/bin/bash
# Test with a REAL invoice PDF
# Run this in CloudShell

set -e

REGION="eu-west-3"
BUCKET="ca-a2a-documents-555043101106"

echo "============================================"
echo "TEST WITH REAL INVOICE PDF"
echo "============================================"
echo ""

# Check if we have facture_acme_dec2025.pdf
if [ -f "facture_acme_dec2025.pdf" ]; then
    echo "✓ Found facture_acme_dec2025.pdf locally"
    PDF_FILE="facture_acme_dec2025.pdf"
elif [ -f "demo/documents/facture_acme_dec2025.pdf" ]; then
    echo "✓ Found facture_acme_dec2025.pdf in demo/documents/"
    PDF_FILE="demo/documents/facture_acme_dec2025.pdf"
else
    echo "⚠ Creating a proper test invoice PDF..."
    
    # Create a proper PDF with all required structure
    cat > test_real_invoice.pdf << 'PDFEOF'
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
/Resources <<
/Font <<
/F1 <<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
>>
>>
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 280
>>
stream
BT
/F1 24 Tf
50 700 Td
(FACTURE TEST) Tj
/F1 12 Tf
50 650 Td
(Numero: INV-2026-001) Tj
50 630 Td
(Date: 02 janvier 2026) Tj
50 610 Td
(Client: ACME Corp) Tj
50 590 Td
(Montant HT: 1000.00 EUR) Tj
50 570 Td
(TVA 20%: 200.00 EUR) Tj
50 550 Td
(Total TTC: 1200.00 EUR) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000317 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
647
%%EOF
PDFEOF
    
    PDF_FILE="test_real_invoice.pdf"
    echo "✓ Created test_real_invoice.pdf"
fi

# Upload to S3
echo ""
echo "1. Uploading PDF to S3..."
TIMESTAMP=$(date +%s)
S3_KEY="invoices/2026/01/test_real_${TIMESTAMP}.pdf"

aws s3 cp "${PDF_FILE}" \
  "s3://${BUCKET}/${S3_KEY}" \
  --region ${REGION}

echo "   ✓ Uploaded: ${S3_KEY}"

# Wait for processing
echo ""
echo "2. Waiting 40 seconds for pipeline processing..."
sleep 40

# Check all logs
echo ""
echo "============================================"
echo "PIPELINE LOGS"
echo "============================================"

echo ""
echo "=== LAMBDA LOGS ==="
aws logs tail /aws/lambda/ca-a2a-s3-processor --since 2m --region ${REGION} | grep -E "Processing|Success|Error|status" | tail -10

echo ""
echo "=== ORCHESTRATOR LOGS ==="
aws logs tail /ecs/ca-a2a-orchestrator --since 2m --region ${REGION} | grep -v "GET /health" | grep -E "Starting|extraction|validation|archiving|completed|ERROR|failed" | tail -15

echo ""
echo "=== EXTRACTOR LOGS (KEY) ==="
aws logs tail /ecs/ca-a2a-extractor --since 2m --region ${REGION} | grep -v "GET /health" | grep -E "Request|Extracting|Downloaded|pages|ERROR|failed|Extracted" | tail -15

echo ""
echo "=== VALIDATOR LOGS ==="
aws logs tail /ecs/ca-a2a-validator --since 2m --region ${REGION} | grep -v "GET /health" | grep -E "Request|Processing|validate|ERROR|Success" | tail -10

echo ""
echo "=== ARCHIVIST LOGS ==="
aws logs tail /ecs/ca-a2a-archivist --since 2m --region ${REGION} | grep -v "GET /health" | grep -E "Request|Processing|archive|ERROR|Success" | tail -10

echo ""
echo "============================================"
echo "ANALYSIS"
echo "============================================"
echo ""

# Check for success indicators
EXTRACTOR_SUCCESS=$(aws logs tail /ecs/ca-a2a-extractor --since 2m --region ${REGION} 2>/dev/null | grep -c "Extracted content from PDF" || echo "0")
VALIDATOR_CALLED=$(aws logs tail /ecs/ca-a2a-validator --since 2m --region ${REGION} 2>/dev/null | grep -c "Processing message" || echo "0")
ARCHIVIST_CALLED=$(aws logs tail /ecs/ca-a2a-archivist --since 2m --region ${REGION} 2>/dev/null | grep -c "Processing message" || echo "0")

if [ "$EXTRACTOR_SUCCESS" -gt "0" ]; then
    echo "✅ EXTRACTOR: Successfully extracted PDF content"
else
    echo "❌ EXTRACTOR: Failed to extract PDF"
fi

if [ "$VALIDATOR_CALLED" -gt "0" ]; then
    echo "✅ VALIDATOR: Called and processing"
else
    echo "❌ VALIDATOR: Not called (extraction may have failed)"
fi

if [ "$ARCHIVIST_CALLED" -gt "0" ]; then
    echo "✅ ARCHIVIST: Called and processing"
else
    echo "❌ ARCHIVIST: Not called (validation may have failed)"
fi

echo ""
if [ "$EXTRACTOR_SUCCESS" -gt "0" ] && [ "$VALIDATOR_CALLED" -gt "0" ] && [ "$ARCHIVIST_CALLED" -gt "0" ]; then
    echo "🎉 FULL PIPELINE SUCCESS!"
    echo ""
    echo "All agents executed successfully:"
    echo "  Orchestrator → Extractor → Validator → Archivist"
else
    echo "⚠ Pipeline incomplete. Check logs above for errors."
fi

echo ""

