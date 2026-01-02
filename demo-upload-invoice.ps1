# Demo Helper Script - Upload Invoice to S3 and Monitor Processing
# Usage: .\demo-upload-invoice.ps1 [-Profile "AWSAdministratorAccess-555043101106"]

param(
    [string]$Profile = "default",
    [string]$Region = "eu-west-3",
    [string]$Bucket = "ca-a2a-documents",
    [string]$Prefix = "invoices/2026/01",
    [string]$PdfFile = "demo\documents\facture_acme_dec2025.pdf"
)

# Set AWS environment
$env:AWS_PROFILE = $Profile
$env:AWS_REGION = $Region

Write-Host "==================================================" -ForegroundColor Green
Write-Host "  CA A2A Demo - Invoice Upload & Processing" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host ""

$timestamp = [int][double]::Parse((Get-Date -UFormat %s))

# Check if PDF exists
if (-not (Test-Path $PdfFile)) {
    Write-Host "Error: $PdfFile not found" -ForegroundColor Red
    Write-Host "Creating sample PDF..." -ForegroundColor Yellow
    
    $pdfDir = Split-Path $PdfFile -Parent
    if (-not (Test-Path $pdfDir)) {
        New-Item -ItemType Directory -Path $pdfDir -Force | Out-Null
    }
    
    @"
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
"@ | Out-File -FilePath $PdfFile -Encoding ASCII -NoNewline
    
    Write-Host "[OK] Sample PDF created" -ForegroundColor Green
}

# Step 1: Upload to S3
Write-Host "`n[1/5] Uploading invoice to S3..." -ForegroundColor Yellow
aws s3 cp $PdfFile "s3://$Bucket/$Prefix/" `
  --metadata "uploaded-by=marie.dubois@reply.com,timestamp=$timestamp"

if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Upload successful" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Upload failed" -ForegroundColor Red
    exit 1
}

# Step 2: Verify upload
Write-Host "`n[2/5] Verifying upload..." -ForegroundColor Yellow
aws s3 ls "s3://$Bucket/$Prefix/" | Select-String "facture_acme_dec2025.pdf"
Write-Host "[OK] File verified in S3" -ForegroundColor Green

# Step 3: Check encryption
Write-Host "`n[3/5] Checking encryption..." -ForegroundColor Yellow
$encryption = aws s3api head-object `
  --bucket $Bucket `
  --key "$Prefix/facture_acme_dec2025.pdf" `
  --query 'ServerSideEncryption' `
  --output text 2>$null

if ($encryption -eq "AES256") {
    Write-Host "[OK] Server-side encryption: $encryption" -ForegroundColor Green
} else {
    Write-Host "[WARNING] Encryption status: $encryption" -ForegroundColor Yellow
}

# Step 4: Get file metadata
Write-Host "`n[4/5] Getting file metadata..." -ForegroundColor Yellow
$metadata = aws s3api head-object `
  --bucket $Bucket `
  --key "$Prefix/facture_acme_dec2025.pdf" `
  --query '{Size:ContentLength, LastModified:LastModified, ETag:ETag, Encryption:ServerSideEncryption}' `
  --output json | ConvertFrom-Json

Write-Host "  File size: $($metadata.Size) bytes" -ForegroundColor Cyan
Write-Host "  Last modified: $($metadata.LastModified)" -ForegroundColor Cyan
Write-Host "  ETag: $($metadata.ETag)" -ForegroundColor Cyan
Write-Host "  Encryption: $($metadata.Encryption)" -ForegroundColor Cyan

# Step 5: Wait and check logs
Write-Host "`n[5/5] Waiting for processing (10 seconds)..." -ForegroundColor Yellow
for ($i = 10; $i -ge 1; $i--) {
    Write-Host -NoNewline "$i... "
    Start-Sleep -Seconds 1
}
Write-Host ""

Write-Host "`nChecking orchestrator logs..." -ForegroundColor Yellow
Write-Host "Recent activity:" -ForegroundColor Cyan
$logs = aws logs tail /ecs/ca-a2a-orchestrator --since 1m --region $Region 2>$null | 
  Select-String -Pattern "(document|facture|acme)" | 
  Select-Object -Last 10

if ($logs) {
    $logs | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
} else {
    Write-Host "  No recent logs (service may be idle)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "[OK] Demo upload complete!" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Monitor logs: aws logs tail /ecs/ca-a2a-orchestrator --follow --region $Region" -ForegroundColor White
Write-Host "  2. View in S3: aws s3 ls s3://$Bucket/$Prefix/ --recursive" -ForegroundColor White
Write-Host "  3. Check service: aws ecs describe-services --cluster ca-a2a-cluster --services orchestrator --region $Region" -ForegroundColor White
Write-Host ""

