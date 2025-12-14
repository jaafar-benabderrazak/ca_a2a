# AWS Resource Tagging Script for CA A2A Project
# This script applies consistent tags to all AWS resources

# Project-specific tags
$tags = @(
    "Key=Project,Value=CA-A2A"
    "Key=Environment,Value=Production"
    "Key=Owner,Value=j.benabderrazak@reply.com"
    "Key=ManagedBy,Value=Terraform"
    "Key=CostCenter,Value=CA-Reply"
    "Key=Application,Value=Agent-Based-Architecture"
    "Key=Version,Value=1.0.0"
    "Key=DeploymentDate,Value=$(Get-Date -Format 'yyyy-MM-dd')"
)

$tagsString = $tags -join " "
$region = "eu-west-3"

Write-Host "Starting AWS resource tagging for CA A2A project..." -ForegroundColor Green
Write-Host "Region: $region" -ForegroundColor Cyan
Write-Host "Tags to apply: $tagsString" -ForegroundColor Cyan

# Function to tag resources
function Tag-Resource {
    param(
        [string]$ResourceArn,
        [string]$ResourceType
    )
    
    try {
        Write-Host "Tagging $ResourceType : $ResourceArn" -ForegroundColor Yellow
        aws resourcegroupstaggingapi tag-resources `
            --region $region `
            --resource-arn-list $ResourceArn `
            --tags $tagsString
        Write-Host "✓ Successfully tagged $ResourceType" -ForegroundColor Green
    }
    catch {
        Write-Host "✗ Failed to tag $ResourceType : $_" -ForegroundColor Red
    }
}

# Get all resources in the account for the region
Write-Host "`nFetching all resources in region $region..." -ForegroundColor Cyan
$allResources = aws resourcegroupstaggingapi get-resources --region $region | ConvertFrom-Json

if ($allResources.ResourceTagMappingList.Count -eq 0) {
    Write-Host "No resources found in region $region" -ForegroundColor Yellow
    Write-Host "This is expected if you haven't deployed yet." -ForegroundColor Yellow
    Write-Host "`nYou can use this script after deploying resources." -ForegroundColor Cyan
    exit 0
}

Write-Host "Found $($allResources.ResourceTagMappingList.Count) resources" -ForegroundColor Cyan

# Tag all resources
foreach ($resource in $allResources.ResourceTagMappingList) {
    $arn = $resource.ResourceARN
    
    # Determine resource type from ARN
    if ($arn -match "arn:aws:([^:]+):") {
        $resourceType = $matches[1]
    } else {
        $resourceType = "Unknown"
    }
    
    Tag-Resource -ResourceArn $arn -ResourceType $resourceType
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Tagging Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# Verify tags were applied
Write-Host "`nVerifying tags..." -ForegroundColor Cyan
$verifyResources = aws resourcegroupstaggingapi get-resources `
    --region $region `
    --tag-filters "Key=Project,Values=CA-A2A" | ConvertFrom-Json

Write-Host "Resources tagged with Project=CA-A2A: $($verifyResources.ResourceTagMappingList.Count)" -ForegroundColor Green

