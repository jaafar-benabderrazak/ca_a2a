#!/bin/bash
REGION="eu-west-3"

echo "============================================"
echo "COMPLETE PIPELINE TEST"
echo "============================================"
echo ""

# First, check service status
echo "1. Checking extractor service status..."
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services extractor \
    --region ${REGION} \
    --query 'services[0].{Running:runningCount,Desired:desiredCount,Status:status}' \
    --output table

echo ""
echo "2. Checking recent logs (last 3 minutes, all messages)..."
aws logs tail /ecs/ca-a2a-extractor --since 3m --region ${REGION} | tail -50

echo ""
echo "3. Checking if any tasks are stopped..."
STOPPED_TASK=$(aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name extractor \
    --region ${REGION} \
    --desired-status STOPPED \
    --query 'taskArns[0]' \
    --output text)

if [ "$STOPPED_TASK" != "None" ] && [ ! -z "$STOPPED_TASK" ]; then
    echo ""
    echo "   Found stopped task, checking reason:"
    aws ecs describe-tasks \
        --cluster ca-a2a-cluster \
        --tasks ${STOPPED_TASK} \
        --region ${REGION} \
        --query 'tasks[0].{StoppedReason:stoppedReason,Container:containers[0].{Reason:reason,ExitCode:exitCode}}' \
        --output json
fi

echo ""
echo "============================================"
echo "4. CREATING VALID TEST PDF"
echo "============================================"

# Create a properly structured PDF with invoice data
cat > test_real_invoice.pdf << 'PDFEOF'
%PDF-1.4
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Count 1/Kids[3 0 R]>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>
endobj
4 0 obj
<</Length 450>>
stream
BT
/F1 18 Tf
50 750 Td
(FACTURE / INVOICE) Tj
/F1 12 Tf
50 720 Td
(Date: 02 janvier 2026) Tj
50 700 Td
(Numero: INV-2026-001) Tj
50 680 Td
(Client: ACME Corporation) Tj
50 660 Td
(Adresse: 123 rue de la Paix, 75001 Paris) Tj
50 630 Td
(Description des services:) Tj
/F1 10 Tf
50 610 Td
(- Consultation technique: 1,500.00 EUR) Tj
50 595 Td
(- Support maintenance: 800.00 EUR) Tj
50 580 Td
(- Formation equipe: 1,200.00 EUR) Tj
/F1 12 Tf
50 550 Td
(Sous-total: 3,500.00 EUR) Tj
50 530 Td
(TVA 20%: 700.00 EUR) Tj
/F1 14 Tf
50 500 Td
(MONTANT TOTAL: 4,200.00 EUR) Tj
ET
endstream
endobj
5 0 obj
<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>
endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000056 00000 n
0000000115 00000 n
0000000244 00000 n
0000000746 00000 n
trailer
<</Size 6/Root 1 0 R>>
startxref
814
%%EOF
PDFEOF

echo "   ✓ Created test_real_invoice.pdf (valid PDF with invoice data)"

# Upload to S3
TIMESTAMP=$(date +%s)
S3_KEY="invoices/2026/01/test_${TIMESTAMP}.pdf"

echo ""
echo "5. Uploading to S3..."
aws s3 cp test_real_invoice.pdf \
    s3://ca-a2a-documents-555043101106/${S3_KEY} \
    --region ${REGION}

echo "   ✓ Uploaded: s3://ca-a2a-documents-555043101106/${S3_KEY}"

echo ""
echo "6. Waiting 45 seconds for complete pipeline processing..."
sleep 45

echo ""
echo "============================================"
echo "PIPELINE RESULTS"
echo "============================================"
echo ""

echo "Lambda logs (S3 trigger):"
aws logs tail /aws/lambda/ca-a2a-s3-processor --since 2m --region ${REGION} | grep -E "Processing|Success|Error|Status" | tail -10

echo ""
echo "Orchestrator logs (coordination):"
aws logs tail /ecs/ca-a2a-orchestrator --since 2m --region ${REGION} | grep -v "GET /health" | grep -E "process_document|extraction|validation|archiving|completed|ERROR" | tail -15

echo ""
echo "Extractor logs (KEY - PDF processing):"
aws logs tail /ecs/ca-a2a-extractor --since 2m --region ${REGION} | grep -E "Request|extract|Extracted|pages|completed|ERROR|IndentationError|native MCP" | tail -15

echo ""
echo "Validator logs:"
aws logs tail /ecs/ca-a2a-validator --since 2m --region ${REGION} | grep -E "Request|validate|Validated|completed|ERROR" | tail -10

echo ""
echo "Archivist logs:"
aws logs tail /ecs/ca-a2a-archivist --since 2m --region ${REGION} | grep -E "Request|archive|Archived|completed|ERROR" | tail -10

echo ""
echo "============================================"
echo "✓ TEST COMPLETE"
echo "============================================"

rm -f test_real_invoice.pdf

