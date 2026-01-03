# Documentation Cleanup Script
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "DOCUMENTATION CLEANUP" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Files to REMOVE (legacy/redundant/outdated)
$REMOVE_FILES = @(
    "ARCHIVIST_FIX_AND_S3_STATUS.md",
    "DEPLOYMENT_SUCCESS.md",
    "E2E_TEST_SUCCESS_REPORT.md",
    "ETAT_DU_PROJET.md",
    "FINAL_STATUS_ORCHESTRATOR_DEMO.md",
    "ORCHESTRATOR_FIX_COMPLETE.md",
    "ORCHESTRATOR_STATUS_QUICK.md",
    "PIPELINE_SUCCESS_SUMMARY.md",
    "DEMO_2H_ACTUAL_RESULTS.md",
    "DEMO_2H_CLOUDSHELL_ACTUAL_RESULTS.md",
    "DEMO_2H_COMPLETE_PACKAGE.md",
    "DEMO_2H_POST_FIX_REPORT.md",
    "DEMO_2H_QUICK_REFERENCE.md",
    "DEMO_2H_TEST_RESULTS.md",
    "DEMO_2H_TEST_SUMMARY.md",
    "README_DEMO_2H.md",
    "AWS_DEPLOYMENT.md",
    "COMPLETE_DEPLOYMENT_GUIDE.md",
    "DEPLOYMENT_QUICK_REF.md",
    "RUN_DEPLOYMENT.md",
    "CRITICAL_ISSUE_MCP_CONFIGURATION.md",
    "FIX_SUMMARY.md",
    "NAMED_PORT_FIX.md",
    "S3_EVENT_PROCESSING_STATUS.md",
    "S3_PIPELINE_JSON_FIX.md",
    "SQS_POLICY_QUICK_FIX.md",
    "TEST_FIXED_PIPELINE.md",
    "AWS_ARCHITECTURE.md",
    "AWS_ARCHITECTURE_MERMAID.md",
    "MCP_MIGRATION_GUIDE.md",
    "MCP_SERVER_GUIDE.md",
    "QUICK_REFERENCE_COMMANDS.md",
    "SECURITY_IMPLEMENTATION.md",
    "TROUBLESHOOTING.md",
    "UPLOAD_VIA_ALB_GUIDE.md",
    "WHY_NO_ALB_UPLOAD.md"
)

# Create archive directory
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$ARCHIVE_DIR = "docs_archive_$timestamp"
New-Item -ItemType Directory -Path $ARCHIVE_DIR -Force | Out-Null
Write-Host "Created archive directory: $ARCHIVE_DIR" -ForegroundColor Cyan
Write-Host ""

# Move files to archive
$removed = 0
$notFound = 0

foreach ($file in $REMOVE_FILES) {
    if (Test-Path $file) {
        Move-Item -Path $file -Destination $ARCHIVE_DIR -Force
        Write-Host "Archived: $file" -ForegroundColor Gray
        $removed++
    } else {
        $notFound++
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "CLEANUP SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Archived: $removed files" -ForegroundColor Green
Write-Host "Not found: $notFound files" -ForegroundColor Yellow
Write-Host ""
Write-Host "Archive location: $ARCHIVE_DIR" -ForegroundColor Cyan
Write-Host ""
Write-Host "Remaining documentation:" -ForegroundColor Green
Get-ChildItem *.md | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor White }
Write-Host ""
Write-Host "Next: git add -A && git commit -m 'Clean up legacy documentation' && git push" -ForegroundColor Yellow

