# Test Fixed PDF Pipeline

## Status: ✅ DEPLOYED

The fixed extractor with robust PDF parsing has been deployed to ECS.

## What Was Fixed

### 1. **Extractor Agent (`extractor_agent.py`)**
- Added `strict=False` to `PyPDF2.PdfReader` for lenient PDF parsing
- Implemented comprehensive error handling for metadata extraction
- Added per-page error handling for text extraction
- Implemented fallback to `pdfplumber` if PyPDF2 fails completely
- All changes maintain backward compatibility with CSV extraction

### 2. **Key Improvements**
```python
# Before (would crash on malformed PDFs)
pdf_reader = PyPDF2.PdfReader(pdf_file)

# After (handles malformed PDFs gracefully)
pdf_reader = PyPDF2.PdfReader(pdf_file, strict=False)
# + try-except around metadata
# + try-except around each page
# + fallback to pdfplumber if critical error
```

## Testing in CloudShell

### Quick Test (Recommended)

```bash
cd ~/ca_a2a

# Make script executable
chmod +x test-complete-pipeline-simple.sh

# Run test
./test-complete-pipeline-simple.sh
```

**Expected Output:**
```
✅ PDF extraction completed
✅ Starting validation  
✅ Starting archiving
✅ Pipeline completed successfully
```

### Manual Test (If you want more control)

```bash
cd ~/ca_a2a

# 1. Upload a test invoice
TIMESTAMP=$(date +%s)
aws s3 cp facture_acme_dec2025.pdf \
  s3://ca-a2a-documents-555043101106/invoices/2026/01/test_${TIMESTAMP}.pdf \
  --region eu-west-3

echo "Uploaded: test_${TIMESTAMP}.pdf"

# 2. Wait 30 seconds
echo "Waiting 30 seconds for processing..."
sleep 30

# 3. Check Lambda logs
echo ""
echo "=== Lambda Logs ==="
aws logs tail /aws/lambda/ca-a2a-s3-processor --since 2m --region eu-west-3 | tail -20

# 4. Check Orchestrator logs
echo ""
echo "=== Orchestrator Logs ==="
aws logs tail /ecs/ca-a2a-orchestrator --since 2m --region eu-west-3 | grep -v "GET /health" | tail -20

# 5. Check Extractor logs (THE KEY ONE!)
echo ""
echo "=== Extractor Logs ==="
aws logs tail /ecs/ca-a2a-extractor --since 2m --region eu-west-3 | tail -30

# 6. Check Validator logs
echo ""
echo "=== Validator Logs ==="
aws logs tail /ecs/ca-a2a-validator --since 2m --region eu-west-3 | tail -20

# 7. Check Archivist logs
echo ""
echo "=== Archivist Logs ==="
aws logs tail /ecs/ca-a2a-archivist --since 2m --region eu-west-3 | tail -20
```

## What to Look For

### ✅ Success Indicators

**In Extractor Logs:**
```
Extracted content from PDF: 1 pages
✓ Extraction successful
```

**In Validator Logs:**
```
Processing message: validate_invoice
✓ Validation successful
```

**In Archivist Logs:**
```
Processing message: archive_invoice
Successfully archived invoice
```

### ❌ Previous Error (Now Fixed)

**Before (would see this error):**
```
invalid literal for int() with base 10: b''
PDF extraction failed
```

**After (no more errors):**
```
Extracted content from PDF: 1 pages
✓ Extraction successful
```

## Full Pipeline Flow

```
S3 Upload
   ↓
Lambda Trigger (ca-a2a-s3-processor)
   ↓
Orchestrator (process_document)
   ↓
Extractor (extract_invoice) ← FIXED HERE
   ↓
Validator (validate_invoice)
   ↓
Archivist (archive_invoice)
   ↓
✅ Complete
```

## Deployment Details

- **Fixed Image:** `555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a-extractor:fixed`
- **Task Definition:** `ca-a2a-extractor:8`
- **Deployed:** 2026-01-02 22:15 UTC
- **Running Tasks:** 2/2 healthy

## Local Deployment Scripts

If you need to rebuild/redeploy locally:

### PowerShell (Windows)
```powershell
.\Deploy-WithCredentials.ps1
```

### Git Bash / WSL (Windows)
```bash
./deploy-with-credentials.sh
```

**Note:** Requires AWS credentials to be set as environment variables.

## Troubleshooting

### If extractor still fails:

1. **Check extractor is running:**
   ```bash
   aws ecs describe-services \
     --cluster ca-a2a-cluster \
     --services extractor \
     --region eu-west-3 \
     --query 'services[0].deployments[*].{Status:status,Running:runningCount,TaskDef:taskDefinition}'
   ```

2. **Check task definition image:**
   ```bash
   aws ecs describe-task-definition \
     --task-definition ca-a2a-extractor \
     --region eu-west-3 \
     --query 'taskDefinition.containerDefinitions[0].image'
   ```
   
   Should show: `555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a-extractor:fixed`

3. **Force restart if needed:**
   ```bash
   aws ecs update-service \
     --cluster ca-a2a-cluster \
     --service extractor \
     --force-new-deployment \
     --region eu-west-3
   ```

## Next Steps

After confirming the pipeline works:

1. ✅ Test with various PDF formats (complex invoices, scanned PDFs, etc.)
2. ✅ Monitor for any edge cases in production
3. ✅ Consider adding PDF validation metrics to CloudWatch
4. ✅ Document any new PDF formats that need special handling

## Summary

**Status:** ✅ **READY TO TEST**

The PDF extraction has been fixed with:
- Lenient PDF parsing (`strict=False`)
- Comprehensive error handling
- Fallback to alternative library (pdfplumber)
- Full pipeline integration maintained

**Run this command in CloudShell to test:**
```bash
./test-complete-pipeline-simple.sh
```

---
**Last Updated:** 2026-01-02 22:20 UTC  
**Author:** Jaafar Benabderrazak

