#!/bin/bash
# Deploy fixed extractor and test with real invoice

set -e

REGION="${REGION:-eu-west-3}"
CLUSTER="ca-a2a-cluster"

echo "============================================"
echo "DEPLOY FIXED EXTRACTOR & TEST FULL PIPELINE"
echo "============================================"
echo ""

# Build and push extractor image
echo "1. Building extractor Docker image..."
docker build -t ca-a2a-extractor:fixed -f Dockerfile.extractor .

echo ""
echo "2. Tagging for ECR..."
AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
ECR_REPO="${AWS_ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a-extractor"

aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${ECR_REPO}"

docker tag ca-a2a-extractor:fixed "${ECR_REPO}:fixed"
docker push "${ECR_REPO}:fixed"

echo "✓ Image pushed to ECR"

echo ""
echo "3. Updating ECS service..."
# Get current task definition
TASK_DEF_ARN=$(aws ecs describe-services \
  --cluster "${CLUSTER}" \
  --services extractor \
  --region "${REGION}" \
  --query 'services[0].taskDefinition' \
  --output text)

# Download and update
aws ecs describe-task-definition \
  --task-definition "${TASK_DEF_ARN}" \
  --region "${REGION}" \
  --query 'taskDefinition' > extractor_taskdef.json

# Update image tag
jq --arg image "${ECR_REPO}:fixed" '
  .containerDefinitions[0].image = $image |
  del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)
' extractor_taskdef.json > extractor_taskdef_updated.json

# Register new task definition
NEW_TASK_DEF=$(aws ecs register-task-definition \
  --cli-input-json file://extractor_taskdef_updated.json \
  --region "${REGION}" \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)

echo "New task definition: ${NEW_TASK_DEF}"

# Update service
aws ecs update-service \
  --cluster "${CLUSTER}" \
  --service extractor \
  --task-definition "${NEW_TASK_DEF}" \
  --force-new-deployment \
  --region "${REGION}" > /dev/null

echo "✓ Extractor service updated"

# Cleanup
rm -f extractor_taskdef.json extractor_taskdef_updated.json

echo ""
echo "Waiting 60 seconds for deployment..."
sleep 60

echo ""
echo "============================================"
echo "CREATE PROPER TEST INVOICE"
echo "============================================"
echo ""

# Create a well-formed invoice PDF
cat > proper_invoice.txt << 'EOF'
FACTURE

Numéro: FAC-2026-001
Date: 02 janvier 2026

Client:
ACME Corporation
123 rue de Paris
75001 Paris
FRANCE

Fournisseur:
Services Consulting SARL
456 avenue des Champs
75008 Paris
FRANCE

Description des services:
- Consultation stratégique: 5,000.00 EUR
- Développement logiciel: 3,000.00 EUR  
- Formation équipe: 2,000.00 EUR

Sous-total HT: 10,000.00 EUR
TVA (20%): 2,000.00 EUR
TOTAL TTC: 12,000.00 EUR

Conditions de paiement: 30 jours
Date d'échéance: 01 février 2026

Mentions légales:
SIRET: 123 456 789 00012
TVA: FR 12 123456789
EOF

# Convert to PDF using Python (if available) or upload text
python3 << 'PYTHON_EOF'
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    
    pdf = canvas.Canvas("proper_invoice.pdf", pagesize=letter)
    width, height = letter
    
    # Title
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(1*inch, height - 1*inch, "FACTURE")
    
    # Invoice details
    pdf.setFont("Helvetica", 10)
    y = height - 1.5*inch
    
    with open("proper_invoice.txt", "r") as f:
        for line in f:
            pdf.drawString(1*inch, y, line.strip())
            y -= 0.2*inch
            if y < 1*inch:
                break
    
    pdf.save()
    print("✓ PDF created with reportlab")
    
except ImportError:
    print("reportlab not available, using existing PDF")
PYTHON_EOF

echo ""
echo "============================================"
echo "TEST WITH REAL INVOICE"
echo "============================================"
echo ""

# Use existing invoice if reportlab not available
if [ ! -f "proper_invoice.pdf" ]; then
  echo "Using existing facture_acme_dec2025.pdf"
  cp facture_acme_dec2025.pdf proper_invoice.pdf
fi

TIMESTAMP=$(date +%s)
TEST_KEY="invoices/2026/01/proper_invoice_${TIMESTAMP}.pdf"

echo "Uploading: ${TEST_KEY}"
aws s3 cp proper_invoice.pdf \
  "s3://ca-a2a-documents-555043101106/${TEST_KEY}" \
  --region "${REGION}"

rm -f proper_invoice.pdf proper_invoice.txt

echo "✓ Uploaded"
echo ""
echo "Waiting 30 seconds for processing..."
sleep 30

echo ""
echo "============================================"
echo "CHECK COMPLETE PIPELINE"
echo "============================================"
echo ""

echo "Lambda logs:"
aws logs tail /aws/lambda/ca-a2a-s3-processor \
  --since 2m \
  --region "${REGION}" \
  --format short \
  | grep -E "Processing|Success|task_id" \
  | tail -5

echo ""
echo "Orchestrator logs:"
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 2m \
  --region "${REGION}" \
  --format short \
  | grep -E "Starting|extraction|validation|archiving|completed|failed" \
  | tail -15

echo ""
echo "Extractor logs:"
aws logs tail /ecs/ca-a2a-extractor \
  --since 2m \
  --region "${REGION}" \
  --format short \
  | grep -E "Extracting|extraction|completed|failed|pages|tables" \
  | tail -10

echo ""
echo "Validator logs:"
aws logs tail /ecs/ca-a2a-validator \
  --since 2m \
  --region "${REGION}" \
  --format short \
  | grep -v "GET /health" \
  | tail -10

echo ""
echo "Archivist logs:"
aws logs tail /ecs/ca-a2a-archivist \
  --since 2m \
  --region "${REGION}" \
  --format short \
  | grep -v "GET /health" \
  | tail -10

echo ""
echo "============================================"
echo "ANALYSIS"
echo "============================================"
echo ""

# Check for validation and archiving
if aws logs tail /ecs/ca-a2a-orchestrator --since 2m --region "${REGION}" | grep -q "Starting validation"; then
  echo "✅ Pipeline reached VALIDATION stage!"
else
  echo "❌ Pipeline did not reach validation"
fi

if aws logs tail /ecs/ca-a2a-orchestrator --since 2m --region "${REGION}" | grep -q "Starting archiving"; then
  echo "✅ Pipeline reached ARCHIVING stage!"
else
  echo "❌ Pipeline did not reach archiving"
fi

if aws logs tail /ecs/ca-a2a-orchestrator --since 2m --region "${REGION}" | grep -q "Pipeline completed successfully"; then
  echo "✅ ✅ ✅ COMPLETE PIPELINE SUCCESS! ✅ ✅ ✅"
  echo ""
  echo "All 4 agents worked together:"
  echo "  Orchestrator → Extractor → Validator → Archivist"
else
  echo ""
  echo "Check logs above for detailed status"
fi

echo ""
echo "To check database:"
echo "  SELECT * FROM documents ORDER BY processing_date DESC LIMIT 5;"

