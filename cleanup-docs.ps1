# Documentation Cleanup Script
# Removes legacy, outdated, and redundant documentation files

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "DOCUMENTATION CLEANUP" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Define files to KEEP (essential documentation)
$KEEP_FILES = @(
    "README.md",                                    # Main project overview
    "FINAL_STATUS_REPORT.md",                       # Current system status
    "QUICK_START_GUIDE.md",                         # Essential commands
    "TEST_SUITE_EXPLAINED.md",                      # Test documentation
    "COMPLETE_TECHNICAL_DOCUMENTATION.md",          # Full technical guide
    "SYSTEM_ARCHITECTURE.md",                       # Architecture details
    "SECURITY_GUIDE.md",                            # Security documentation
    "AWS_ARCHITECTURE_DIAGRAM.md",                  # Visual architecture
    "DEMO_HISTOIRE_2H.md",                          # Demo narrative
    "COMPLETE_DEMO_GUIDE.md",                       # Complete demo (English)
    "GUIDE_DEMO_COMPLET.md",                        # Complete demo (French)
    "LINKEDIN_ARTICLE.md"                           # Professional article
)

# Files to REMOVE (legacy/redundant/outdated)
$REMOVE_FILES = @(
    # Old status reports (superseded by FINAL_STATUS_REPORT.md)
    "ARCHIVIST_FIX_AND_S3_STATUS.md",
    "DEPLOYMENT_SUCCESS.md",
    "E2E_TEST_SUCCESS_REPORT.md",
    "ETAT_DU_PROJET.md",
    "FINAL_STATUS_ORCHESTRATOR_DEMO.md",
    "ORCHESTRATOR_FIX_COMPLETE.md",
    "ORCHESTRATOR_STATUS_QUICK.md",
    "PIPELINE_SUCCESS_SUMMARY.md",
    
    # Redundant demo docs (kept only DEMO_HISTOIRE_2H.md and complete guides)
    "DEMO_2H_ACTUAL_RESULTS.md",
    "DEMO_2H_CLOUDSHELL_ACTUAL_RESULTS.md",
    "DEMO_2H_COMPLETE_PACKAGE.md",
    "DEMO_2H_POST_FIX_REPORT.md",
    "DEMO_2H_QUICK_REFERENCE.md",
    "DEMO_2H_TEST_RESULTS.md",
    "DEMO_2H_TEST_SUMMARY.md",
    "README_DEMO_2H.md",
    
    # Old deployment guides (superseded by QUICK_START_GUIDE.md)
    "AWS_DEPLOYMENT.md",
    "COMPLETE_DEPLOYMENT_GUIDE.md",
    "DEPLOYMENT_QUICK_REF.md",
    "RUN_DEPLOYMENT.md",
    
    # Specific fix documentation (no longer relevant)
    "CRITICAL_ISSUE_MCP_CONFIGURATION.md",
    "FIX_SUMMARY.md",
    "NAMED_PORT_FIX.md",
    "S3_EVENT_PROCESSING_STATUS.md",
    "S3_PIPELINE_JSON_FIX.md",
    "SQS_POLICY_QUICK_FIX.md",
    "TEST_FIXED_PIPELINE.md",
    
    # Redundant architecture docs (kept AWS_ARCHITECTURE_DIAGRAM.md)
    "AWS_ARCHITECTURE.md",
    "AWS_ARCHITECTURE_MERMAID.md",
    
    # Old guides (superseded)
    "MCP_MIGRATION_GUIDE.md",
    "MCP_SERVER_GUIDE.md",
    "QUICK_REFERENCE_COMMANDS.md",
    "SECURITY_IMPLEMENTATION.md",
    "TROUBLESHOOTING.md",
    "UPLOAD_VIA_ALB_GUIDE.md",
    "WHY_NO_ALB_UPLOAD.md"
)

Write-Host "Files to keep: $($KEEP_FILES.Count)" -ForegroundColor Green
Write-Host "Files to remove: $($REMOVE_FILES.Count)" -ForegroundColor Yellow
Write-Host ""

# Create archive directory
$ARCHIVE_DIR = "docs_archive_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $ARCHIVE_DIR -Force | Out-Null
Write-Host "Created archive directory: $ARCHIVE_DIR" -ForegroundColor Cyan
Write-Host ""

# Move files to archive
$removed = 0
$notFound = 0

foreach ($file in $REMOVE_FILES) {
    if (Test-Path $file) {
        Move-Item -Path $file -Destination $ARCHIVE_DIR -Force
        Write-Host "✓ Archived: $file" -ForegroundColor Gray
        $removed++
    } else {
        Write-Host "⚠ Not found: $file" -ForegroundColor DarkGray
        $notFound++
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "CLEANUP SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Archived: $removed files" -ForegroundColor Green
Write-Host "Not found: $notFound files" -ForegroundColor Yellow
Write-Host "Kept: $($KEEP_FILES.Count) files" -ForegroundColor Green
Write-Host ""
Write-Host "Archive location: $ARCHIVE_DIR" -ForegroundColor Cyan
Write-Host ""

# Show remaining documentation
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "CURRENT DOCUMENTATION STRUCTURE" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$categories = @{
    "Core Documentation" = @("README.md", "FINAL_STATUS_REPORT.md", "QUICK_START_GUIDE.md")
    "Technical Guides" = @("COMPLETE_TECHNICAL_DOCUMENTATION.md", "SYSTEM_ARCHITECTURE.md", "AWS_ARCHITECTURE_DIAGRAM.md")
    "Security" = @("SECURITY_GUIDE.md")
    "Testing" = @("TEST_SUITE_EXPLAINED.md")
    "Demos" = @("DEMO_HISTOIRE_2H.md", "COMPLETE_DEMO_GUIDE.md", "GUIDE_DEMO_COMPLET.md")
    "Professional" = @("LINKEDIN_ARTICLE.md")
}

$sortedCategories = $categories.Keys | Sort-Object
foreach ($category in $sortedCategories) {
    Write-Host "$category" -ForegroundColor Yellow
    foreach ($file in $categories[$category]) {
        if (Test-Path $file) {
            $size = (Get-Item $file).Length / 1KB
            $roundedSize = [math]::Round($size, 1)
            Write-Host "  ✓ $file ($roundedSize KB)" -ForegroundColor Green
        } else {
            Write-Host "  ✗ $file (missing)" -ForegroundColor Red
        }
    }
    Write-Host ""
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "✅ CLEANUP COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Review archived files in: $ARCHIVE_DIR" -ForegroundColor White
Write-Host "2. If satisfied, commit changes:" -ForegroundColor White
Write-Host "   git add -A" -ForegroundColor Gray
Write-Host "   git commit -m 'Clean up legacy documentation'" -ForegroundColor Gray
Write-Host "   git push" -ForegroundColor Gray
Write-Host "3. To restore, move files back from archive" -ForegroundColor White
Write-Host ""

