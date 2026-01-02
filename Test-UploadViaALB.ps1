# Test Upload via ALB
param(
    [string]$AblUrl = "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com",
    [string]$FilePath = "test_upload_alb.pdf",
    [string]$Folder = "test_via_alb"
)

Write-Host "========================================" -ForegroundColor Green
Write-Host "  Testing Upload via ALB" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "ALB URL: $AblUrl" -ForegroundColor Cyan
Write-Host "File: $FilePath" -ForegroundColor Cyan
Write-Host "Folder: $Folder" -ForegroundColor Cyan
Write-Host ""

# Check if file exists
if (-not (Test-Path $FilePath)) {
    Write-Host "[ERROR] File not found: $FilePath" -ForegroundColor Red
    exit 1
}

$fileSize = (Get-Item $FilePath).Length
Write-Host "[INFO] File size: $fileSize bytes" -ForegroundColor Yellow

# Read file as bytes
$fileBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $FilePath))
$fileContent = [System.Text.Encoding]::GetEncoding('iso-8859-1').GetString($fileBytes)

# Create boundary
$boundary = [System.Guid]::NewGuid().ToString()

# Build multipart body
$LF = "`r`n"
$bodyLines = (
    "--$boundary",
    "Content-Disposition: form-data; name=`"file`"; filename=`"$(Split-Path $FilePath -Leaf)`"",
    "Content-Type: application/pdf$LF",
    $fileContent,
    "--$boundary",
    "Content-Disposition: form-data; name=`"folder`"$LF",
    $Folder,
    "--$boundary--$LF"
) -join $LF

# Convert to bytes
$bodyBytes = [System.Text.Encoding]::GetEncoding('iso-8859-1').GetBytes($bodyLines)

Write-Host "[INFO] Uploading..." -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri "$AblUrl/upload" `
        -Method Post `
        -ContentType "multipart/form-data; boundary=$boundary" `
        -Body $bodyBytes `
        -TimeoutSec 60 `
        -UseBasicParsing
    
    Write-Host ""
    Write-Host "[SUCCESS] Upload completed!" -ForegroundColor Green
    Write-Host "Status Code: $($response.StatusCode)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Response:" -ForegroundColor Yellow
    $response.Content | ConvertFrom-Json | ConvertTo-Json -Depth 10
    
} catch {
    Write-Host ""
    Write-Host "[ERROR] Upload failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($_.Exception.Response) {
        $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Host "Response Body: $responseBody" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green

