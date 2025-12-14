# CA A2A Demo Setup Script
# This script prepares your demo environment

$ErrorActionPreference = "Stop"

$bucketName = "ca-a2a-documents-555043101106"
$region = "eu-west-3"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CA A2A Demo Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check AWS credentials
Write-Host "[1/5] Checking AWS credentials..." -ForegroundColor Green
try {
    $caller = aws sts get-caller-identity 2>&1 | ConvertFrom-Json
    Write-Host "  Logged in as: $($caller.Arn)" -ForegroundColor White
} catch {
    Write-Host "  ERROR: Not logged into AWS" -ForegroundColor Red
    Write-Host "  Run: aws sso login --profile AWSAdministratorAccess-555043101106" -ForegroundColor Yellow
    exit 1
}

# Create demo directories
Write-Host ""
Write-Host "[2/5] Creating demo directories..." -ForegroundColor Green
$demoDir = "demo\documents"
if (-not (Test-Path $demoDir)) {
    New-Item -ItemType Directory -Path $demoDir | Out-Null
    Write-Host "  Created: $demoDir" -ForegroundColor White
}

$subDirs = @("good", "bad", "batch")
foreach ($dir in $subDirs) {
    $path = Join-Path $demoDir $dir
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
        Write-Host "  Created: $path" -ForegroundColor White
    }
}

# Create sample documents
Write-Host ""
Write-Host "[3/5] Creating sample documents..." -ForegroundColor Green

# Good document
$goodDoc = @"
FINANCIAL REPORT Q4 2024

Company: Acme Corporation
Period: Q4 2024
Report Date: December 31, 2024

EXECUTIVE SUMMARY
=================
Total Revenue: $2,500,000
Total Expenses: $1,800,000
Net Profit: $700,000
Profit Margin: 28%

REVENUE BREAKDOWN
=================
Product Sales: $1,500,000
Service Revenue: $800,000
Consulting: $200,000

EXPENSE BREAKDOWN
=================
Salaries: $1,000,000
Operations: $500,000
Marketing: $200,000
Other: $100,000

QUARTERLY COMPARISON
====================
Q4 2024: $2,500,000 (+15% YoY)
Q3 2024: $2,300,000
Q2 2024: $2,100,000
Q1 2024: $2,000,000

NOTES
=====
- Strong performance in product sales
- Service revenue exceeded expectations
- Operating expenses within budget
- Positive outlook for Q1 2025
"@

$goodDoc | Out-File -FilePath "$demoDir\good\financial-report-q4-2024.txt" -Encoding UTF8
Write-Host "  Created: financial-report-q4-2024.txt" -ForegroundColor White

# Bad document (incomplete)
$badDoc = @"
INCOMPLETE REPORT

Company: Unknown
Period: 

SUMMARY
Revenue: [DATA MISSING]
Expenses: 
Net Profit: ERROR

Some data here but mostly incomplete...
"@

$badDoc | Out-File -FilePath "$demoDir\bad\incomplete-report.txt" -Encoding UTF8
Write-Host "  Created: incomplete-report.txt" -ForegroundColor White

# Batch documents
for ($i = 1; $i -le 3; $i++) {
    $batchDoc = @"
REPORT $i

Company: Demo Corp $i
Revenue: $(1000000 * $i)
Expenses: $(800000 * $i)
Status: Complete
"@
    $batchDoc | Out-File -FilePath "$demoDir\batch\report-0$i.txt" -Encoding UTF8
    Write-Host "  Created: report-0$i.txt" -ForegroundColor White
}

# Upload to S3
Write-Host ""
Write-Host "[4/5] Uploading documents to S3..." -ForegroundColor Green
try {
    aws s3 sync "$demoDir" "s3://$bucketName/demo/" --region $region
    Write-Host "  Uploaded to s3://$bucketName/demo/" -ForegroundColor White
} catch {
    Write-Host "  ERROR: Failed to upload to S3" -ForegroundColor Red
    Write-Host "  $_" -ForegroundColor Yellow
}

# Verify uploads
Write-Host ""
Write-Host "[5/5] Verifying uploads..." -ForegroundColor Green
$files = aws s3 ls "s3://$bucketName/demo/" --recursive --region $region
$fileCount = ($files | Measure-Object -Line).Lines
Write-Host "  Found $fileCount files in S3" -ForegroundColor White

# Create demo script
Write-Host ""
Write-Host "Creating quick demo script..." -ForegroundColor Green
$demoScript = @"
# CA A2A Quick Demo Script
# Copy and paste these commands during your demo

# 1. Check agent health
python client.py health

# 2. Discover agents
python discover_agents.py

# 3. Get agent card (show capabilities)
curl http://localhost:8001/card | python -m json.tool

# 4. Process good document
python client.py process "demo/good/financial-report-q4-2024.txt"

# 5. Process bad document (shows validation)
python client.py process "demo/bad/incomplete-report.txt"

# 6. Batch processing
python client.py batch --prefix "demo/batch/" --extension ".txt"

# 7. Check status (replace with actual task_id)
python client.py status <task_id>

# 8. Query database (in psql)
SELECT * FROM documents ORDER BY created_at DESC LIMIT 5;

# 9. Check AWS deployment
.\scripts\check-deployment-status.ps1
"@

$demoScript | Out-File -FilePath "demo\demo-commands.txt" -Encoding UTF8
Write-Host "  Created: demo\demo-commands.txt" -ForegroundColor White

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Demo Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Demo files created in: $demoDir" -ForegroundColor White
Write-Host "S3 location: s3://$bucketName/demo/" -ForegroundColor White
Write-Host "Demo commands: demo\demo-commands.txt" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Start agents: python run_agents.py" -ForegroundColor Yellow
Write-Host "2. Open demo guide: demo\DEMO_GUIDE.md" -ForegroundColor Yellow
Write-Host "3. Run test: python client.py health" -ForegroundColor Yellow
Write-Host ""
Write-Host "Good luck with your demo! 🎬" -ForegroundColor Green

