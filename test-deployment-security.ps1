# CA A2A - Deployment and Security Test Script
# Tests all deployed services and security features
# Usage: .\test-deployment-security.ps1 [-Region us-east-1] [-AlbDns <alb-dns>]

param(
    [string]$Region = "us-east-1",
    [string]$AlbDns = "ca-a2a-alb-1063189579.us-east-1.elb.amazonaws.com",
    [string]$Profile = "AWSAdministratorAccess-555043101106"
)

$ErrorActionPreference = "Continue"
$env:AWS_PROFILE = $Profile

# Output functions
function Write-TestHeader { 
    param($msg) 
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host " $msg" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}
function Write-Pass { param($msg) Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Write-Fail { param($msg) Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Write-Warn { param($msg) Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Info { param($msg) Write-Host "  [INFO] $msg" -ForegroundColor Gray }

$BaseUrl = "http://$AlbDns"
$TestResults = @{
    Passed = 0
    Failed = 0
    Warnings = 0
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Blue
Write-Host "  CA A2A Deployment & Security Tests" -ForegroundColor Blue
Write-Host "======================================" -ForegroundColor Blue
Write-Host "  Region: $Region"
Write-Host "  ALB: $AlbDns"
Write-Host ""

###############################################################################
# 1. ECS Service Health Tests
###############################################################################

Write-TestHeader "1. ECS Services Health Check"

$services = @("orchestrator", "extractor", "validator", "archivist", "keycloak", "mcp-server")

foreach ($service in $services) {
    try {
        $result = aws ecs describe-services --cluster ca-a2a-cluster --services $service --region $Region --query "services[0].[runningCount,desiredCount]" --output text 2>$null
        
        if ($result) {
            $counts = $result -split "`t"
            $running = [int]$counts[0]
            $desired = [int]$counts[1]
            
            if ($running -eq $desired -and $running -gt 0) {
                Write-Pass "$service : $running/$desired tasks running"
                $TestResults.Passed++
            } else {
                Write-Fail "$service : $running/$desired tasks running"
                $TestResults.Failed++
            }
        } else {
            Write-Fail "$service : Unable to query service"
            $TestResults.Failed++
        }
    } catch {
        Write-Fail "$service : Error - $($_.Exception.Message)"
        $TestResults.Failed++
    }
}

###############################################################################
# 2. ALB Health Endpoint Tests
###############################################################################

Write-TestHeader "2. ALB Endpoint Accessibility"

# Test health endpoint
try {
    $response = Invoke-WebRequest -Uri "$BaseUrl/health" -Method GET -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
    Write-Pass "Orchestrator Health : HTTP $($response.StatusCode)"
    $TestResults.Passed++
} catch {
    $errorStatus = $_.Exception.Response.StatusCode.value__
    if ($errorStatus) {
        Write-Fail "Orchestrator Health : HTTP $errorStatus"
    } else {
        Write-Fail "Orchestrator Health : $($_.Exception.Message)"
    }
    $TestResults.Failed++
}

# Test agent card
try {
    $response = Invoke-WebRequest -Uri "$BaseUrl/.well-known/agent.json" -Method GET -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
    Write-Pass "Agent Card : HTTP $($response.StatusCode)"
    $TestResults.Passed++
} catch {
    $errorStatus = $_.Exception.Response.StatusCode.value__
    Write-Fail "Agent Card : HTTP $errorStatus"
    $TestResults.Failed++
}

###############################################################################
# 3. Security Header Tests
###############################################################################

Write-TestHeader "3. Security Headers Validation"

try {
    $response = Invoke-WebRequest -Uri "$BaseUrl/health" -Method GET -TimeoutSec 10 -UseBasicParsing
    $headers = $response.Headers
    
    # Check X-Content-Type-Options
    if ($headers["X-Content-Type-Options"] -eq "nosniff") {
        Write-Pass "X-Content-Type-Options : nosniff"
        $TestResults.Passed++
    } elseif ($headers["X-Content-Type-Options"]) {
        Write-Warn "X-Content-Type-Options : $($headers['X-Content-Type-Options'])"
        $TestResults.Warnings++
    } else {
        Write-Warn "X-Content-Type-Options : Not present"
        $TestResults.Warnings++
    }
    
    # Check X-Frame-Options
    if ($headers["X-Frame-Options"]) {
        Write-Pass "X-Frame-Options : $($headers['X-Frame-Options'])"
        $TestResults.Passed++
    } else {
        Write-Warn "X-Frame-Options : Not present"
        $TestResults.Warnings++
    }
    
    # Check Content-Type
    if ($headers["Content-Type"] -match "application/json") {
        Write-Pass "Content-Type : JSON response"
        $TestResults.Passed++
    }
} catch {
    Write-Fail "Could not retrieve headers: $($_.Exception.Message)"
    $TestResults.Failed++
}

###############################################################################
# 4. Input Validation Tests
###############################################################################

Write-TestHeader "4. Input Validation & Injection Prevention"

$maliciousPayloads = @(
    @{ Name = "SQL Injection"; Payload = "'; DROP TABLE documents; --" },
    @{ Name = "XSS Script"; Payload = "<script>alert(1)</script>" },
    @{ Name = "Path Traversal"; Payload = "../../../etc/passwd" }
)

foreach ($test in $maliciousPayloads) {
    try {
        $body = @{ document_id = $test.Payload } | ConvertTo-Json
        $params = @{
            Uri = "$BaseUrl/a2a"
            Method = "POST"
            ContentType = "application/json"
            Body = $body
            TimeoutSec = 10
            UseBasicParsing = $true
            ErrorAction = "Stop"
        }
        $response = Invoke-WebRequest @params
        
        if ($response.Content -match [regex]::Escape($test.Payload)) {
            Write-Fail "$($test.Name) : Payload reflected in response"
            $TestResults.Failed++
        } else {
            Write-Pass "$($test.Name) : Payload not reflected"
            $TestResults.Passed++
        }
    } catch {
        $errorStatus = $_.Exception.Response.StatusCode.value__
        if ($errorStatus -in @(400, 401, 403, 422)) {
            Write-Pass "$($test.Name) : Rejected with HTTP $errorStatus"
            $TestResults.Passed++
        } else {
            Write-Info "$($test.Name) : HTTP $errorStatus"
        }
    }
}

###############################################################################
# 5. Rate Limiting Tests
###############################################################################

Write-TestHeader "5. Rate Limiting (Basic Check)"

Write-Info "Sending 30 rapid requests..."

$rateLimited = $false
$successCount = 0

for ($i = 0; $i -lt 30; $i++) {
    try {
        $null = Invoke-WebRequest -Uri "$BaseUrl/health" -Method GET -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        $successCount++
    } catch {
        $errorStatus = $_.Exception.Response.StatusCode.value__
        if ($errorStatus -eq 429) {
            $rateLimited = $true
        }
    }
}

if ($rateLimited) {
    Write-Pass "Rate limiting active (429 received)"
    $TestResults.Passed++
} else {
    Write-Warn "Rate limiting not detected: $successCount/30 succeeded"
    $TestResults.Warnings++
}

###############################################################################
# 6. AWS Infrastructure Security
###############################################################################

Write-TestHeader "6. AWS Infrastructure Security"

# Check RDS configuration
Write-Info "Checking RDS configuration..."
try {
    $rdsJson = aws rds describe-db-instances --region $Region --query "DBInstances[?contains(DBInstanceIdentifier, ``ca-a2a``)].{ID:DBInstanceIdentifier,Public:PubliclyAccessible,Encrypted:StorageEncrypted}" --output json 2>$null
    $rdsResult = $rdsJson | ConvertFrom-Json
    
    foreach ($db in $rdsResult) {
        if ($db.Public -eq $false) {
            Write-Pass "RDS $($db.ID) is not publicly accessible"
            $TestResults.Passed++
        } else {
            Write-Fail "RDS $($db.ID) is publicly accessible"
            $TestResults.Failed++
        }
        
        if ($db.Encrypted -eq $true) {
            Write-Pass "RDS $($db.ID) storage is encrypted"
            $TestResults.Passed++
        } else {
            Write-Fail "RDS $($db.ID) storage is NOT encrypted"
            $TestResults.Failed++
        }
    }
} catch {
    Write-Warn "Could not check RDS: $($_.Exception.Message)"
    $TestResults.Warnings++
}

# Check S3 bucket
Write-Info "Checking S3 bucket configuration..."
try {
    $bucketsJson = aws s3api list-buckets --query "Buckets[?contains(Name, ``ca-a2a``)].Name" --output json 2>$null
    $buckets = $bucketsJson | ConvertFrom-Json
    
    foreach ($bucket in $buckets) {
        try {
            $publicJson = aws s3api get-public-access-block --bucket $bucket --query "PublicAccessBlockConfiguration" --output json 2>$null
            $publicAccess = $publicJson | ConvertFrom-Json
            
            if ($publicAccess.BlockPublicAcls -eq $true -and $publicAccess.BlockPublicPolicy -eq $true) {
                Write-Pass "S3 $bucket : Public access blocked"
                $TestResults.Passed++
            } else {
                Write-Fail "S3 $bucket : Public access NOT fully blocked"
                $TestResults.Failed++
            }
        } catch {
            Write-Warn "S3 $bucket : Could not check public access"
            $TestResults.Warnings++
        }
    }
} catch {
    Write-Warn "Could not check S3: $($_.Exception.Message)"
    $TestResults.Warnings++
}

# Check Secrets Manager
Write-Info "Checking Secrets Manager..."
try {
    $secretsJson = aws secretsmanager list-secrets --region $Region --output json 2>$null
    $secrets = ($secretsJson | ConvertFrom-Json).SecretList | Where-Object { $_.Name -match "ca-a2a|DbPassword|Keycloak" }
    
    if ($secrets.Count -gt 0) {
        Write-Pass "Secrets Manager: $($secrets.Count) secrets configured"
        $TestResults.Passed++
    } else {
        Write-Warn "No relevant secrets found"
        $TestResults.Warnings++
    }
} catch {
    Write-Warn "Could not check Secrets Manager"
    $TestResults.Warnings++
}

###############################################################################
# 7. End-to-End Workflow Test
###############################################################################

Write-TestHeader "7. End-to-End Workflow Test"

Write-Info "Testing document processing workflow..."

$testDocument = @{
    jsonrpc = "2.0"
    id = [guid]::NewGuid().ToString()
    method = "process_document"
    params = @{
        document_name = "test_security.txt"
        content = "Test document for security validation."
        document_type = "test"
    }
} | ConvertTo-Json -Depth 5

try {
    $params = @{
        Uri = "$BaseUrl/a2a"
        Method = "POST"
        ContentType = "application/json"
        Body = $testDocument
        TimeoutSec = 30
        UseBasicParsing = $true
        ErrorAction = "Stop"
    }
    $response = Invoke-WebRequest @params
    $result = $response.Content | ConvertFrom-Json
    
    if ($result.result -or $result.id) {
        Write-Pass "Document processing accepted"
        $TestResults.Passed++
    } elseif ($result.error) {
        Write-Info "Document processing returned error: $($result.error.message)"
    }
} catch {
    $errorStatus = $_.Exception.Response.StatusCode.value__
    Write-Info "Document processing returned HTTP $errorStatus (may require auth)"
}

###############################################################################
# Summary
###############################################################################

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host " TEST RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""

$total = $TestResults.Passed + $TestResults.Failed + $TestResults.Warnings

Write-Host "  Total Tests:  $total" -ForegroundColor White
Write-Host "  Passed:       $($TestResults.Passed)" -ForegroundColor Green

if ($TestResults.Failed -gt 0) {
    Write-Host "  Failed:       $($TestResults.Failed)" -ForegroundColor Red
} else {
    Write-Host "  Failed:       $($TestResults.Failed)" -ForegroundColor Green
}

if ($TestResults.Warnings -gt 0) {
    Write-Host "  Warnings:     $($TestResults.Warnings)" -ForegroundColor Yellow
} else {
    Write-Host "  Warnings:     $($TestResults.Warnings)" -ForegroundColor Green
}

Write-Host ""

if ($total -gt 0) {
    $passRate = [math]::Round(($TestResults.Passed / $total) * 100, 1)
    if ($passRate -ge 80) {
        Write-Host "  Pass Rate:    $passRate%" -ForegroundColor Green
    } elseif ($passRate -ge 60) {
        Write-Host "  Pass Rate:    $passRate%" -ForegroundColor Yellow
    } else {
        Write-Host "  Pass Rate:    $passRate%" -ForegroundColor Red
    }
}

Write-Host ""

if ($TestResults.Failed -eq 0) {
    Write-Host "  [OK] All critical security tests passed!" -ForegroundColor Green
} else {
    Write-Host "  [!!] $($TestResults.Failed) critical issue(s) found" -ForegroundColor Red
}

if ($TestResults.Warnings -gt 0) {
    Write-Host "  [!] $($TestResults.Warnings) warning(s) - consider addressing" -ForegroundColor Yellow
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""

# Return exit code based on results
if ($TestResults.Failed -gt 0) {
    exit 1
} else {
    exit 0
}
