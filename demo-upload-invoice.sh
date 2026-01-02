#!/bin/bash
# Demo Helper Script - Upload Invoice to S3 and Monitor Processing
# Usage: ./demo-upload-invoice.sh

set -e

echo "=================================================="
echo "  CA A2A Demo - Invoice Upload & Processing"
echo "=================================================="
echo ""

# Configuration
BUCKET="ca-a2a-documents"
PREFIX="invoices/2026/01"
PDF_FILE="demo/documents/facture_acme_dec2025.pdf"
TIMESTAMP=$(date +%s)

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if PDF exists
if [ ! -f "$PDF_FILE" ]; then
    echo -e "${RED}Error: $PDF_FILE not found${NC}"
    echo "Creating sample PDF..."
    mkdir -p demo/documents
    
    cat > "$PDF_FILE" << 'EOF'
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj
4 0 obj<</Length 55>>stream
BT /F1 12 Tf 100 700 Td (FACTURE ACME INV-2026-001) Tj ET
endstream endobj
xref
0 5
trailer<</Size 5/Root 1 0 R>>
startxref
240
%%EOF
EOF
    echo -e "${GREEN}✓ Sample PDF created${NC}"
fi

# Step 1: Upload to S3
echo -e "${YELLOW}[1/5] Uploading invoice to S3...${NC}"
aws s3 cp "$PDF_FILE" "s3://$BUCKET/$PREFIX/" \
  --metadata uploaded-by=marie.dubois@reply.com,timestamp=$TIMESTAMP

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Upload successful${NC}"
else
    echo -e "${RED}✗ Upload failed${NC}"
    exit 1
fi

# Step 2: Verify upload
echo -e "\n${YELLOW}[2/5] Verifying upload...${NC}"
aws s3 ls "s3://$BUCKET/$PREFIX/" | grep facture_acme_dec2025.pdf
echo -e "${GREEN}✓ File verified in S3${NC}"

# Step 3: Check encryption
echo -e "\n${YELLOW}[3/5] Checking encryption...${NC}"
ENCRYPTION=$(aws s3api head-object \
  --bucket "$BUCKET" \
  --key "$PREFIX/facture_acme_dec2025.pdf" \
  --query 'ServerSideEncryption' \
  --output text 2>/dev/null || echo "NONE")

if [ "$ENCRYPTION" = "AES256" ]; then
    echo -e "${GREEN}✓ Server-side encryption: $ENCRYPTION${NC}"
else
    echo -e "${RED}⚠ Encryption status: $ENCRYPTION${NC}"
fi

# Step 4: Wait for processing
echo -e "\n${YELLOW}[4/5] Waiting for processing (10 seconds)...${NC}"
for i in {10..1}; do
    echo -n "$i... "
    sleep 1
done
echo ""

# Step 5: Check logs
echo -e "\n${YELLOW}[5/5] Checking orchestrator logs...${NC}"
echo "Recent activity:"
aws logs tail /ecs/ca-a2a-orchestrator --since 1m --region eu-west-3 2>/dev/null | \
  grep -E "(document|facture|acme)" | tail -10 || echo "No recent logs (service may be idle)"

echo ""
echo "=================================================="
echo -e "${GREEN}✓ Demo upload complete!${NC}"
echo "=================================================="
echo ""
echo "Next steps:"
echo "  1. Monitor logs: aws logs tail /ecs/ca-a2a-orchestrator --follow"
echo "  2. Check database: psql -c 'SELECT * FROM documents ORDER BY created_at DESC LIMIT 1;'"
echo "  3. View in S3: aws s3 ls s3://$BUCKET/$PREFIX/ --recursive"
echo ""

