#
# Comprehensive A2A Security Test Suite (PowerShell)
# Tests all security features in the deployed AWS environment
#
# Usage:
#   .\Test-SecurityComprehensive.ps1
#   .\Test-SecurityComprehensive.ps1 -Region us-east-1
#   .\Test-SecurityComprehensive.ps1 -Verbose
#

param(
    [string]$Region = "us-east-1",
    [string]$Cluster = "ca-a2a-cluster",
    [switch]$Verbose
)

# Set AWS Profile if not already set
if (-not $env:AWS_PROFILE) {
    $env:AWS_PROFILE = "AWSAdministratorAccess-555043101106"
}

# Test counters
$script:Passed = 0
$script:Failed = 0
$script:Skipped = 0
$script:Warnings = 0

function Test-Pass {
    param([string]$Message)
    Write-Host "[PASS] " -ForegroundColor Green -NoNewline
    Write-Host $Message
    $script:Passed++
}

function Test-Fail {
    param([string]$Message)
    Write-Host "[FAIL] " -ForegroundColor Red -NoNewline
    Write-Host $Message
    $script:Failed++
}

function Test-Skip {
    param([string]$Message)
    Write-Host "[SKIP] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
    $script:Skipped++
}

function Test-Warn {
    param([string]$Message)
    Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
    $script:Warnings++
}

function Get-TaskEnv {
    param(
        [string]$TaskDef,
        [string]$EnvName
    )
    try {
        $result = aws ecs describe-task-definition `
            --task-definition "ca-a2a-$TaskDef" `
            --region $Region `
            --query "taskDefinition.containerDefinitions[0].environment[?name=='$EnvName'].value" `
            --output text 2>$null
        return $result
    } catch {
        return $null
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  COMPREHENSIVE A2A SECURITY TEST SUITE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Region: $Region"
Write-Host "Cluster: $Cluster"
Write-Host "Date: $(Get-Date)"
Write-Host ""

# ============================================================
# SECTION 1: INFRASTRUCTURE VERIFICATION
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "SECTION 1: Infrastructure Security Verification" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""

# Test 1.1: ECS Cluster
Write-Host "1.1 Checking ECS cluster..."
try {
    $clusterInfo = aws ecs describe-clusters --clusters $Cluster --region $Region --output json 2>$null | ConvertFrom-Json
    if ($clusterInfo.clusters -and $clusterInfo.clusters[0].status -eq "ACTIVE") {
        $runningTasks = $clusterInfo.clusters[0].runningTasksCount
        $services = $clusterInfo.clusters[0].activeServicesCount
        Test-Pass "ECS Cluster: ACTIVE ($services services, $runningTasks tasks)"
    } else {
        Test-Fail "ECS Cluster: Not found or inactive"
    }
} catch {
    Test-Fail "ECS Cluster: Error checking - $_"
}

# Test 1.2: Secrets Manager
Write-Host ""
Write-Host "1.2 Checking Secrets Manager..."
try {
    $secrets = aws secretsmanager list-secrets --region $Region --output json 2>$null | ConvertFrom-Json
    $a2aSecrets = $secrets.SecretList | Where-Object { $_.Name -like "*ca-a2a*" -or $_.Name -like "*database*" }
    if ($a2aSecrets.Count -gt 0) {
        Test-Pass "Secrets Manager: $($a2aSecrets.Count) secrets configured"
    } else {
        Test-Warn "Secrets Manager: No A2A secrets found"
    }
} catch {
    Test-Warn "Secrets Manager: Could not check - $_"
}

# Test 1.3: S3 Bucket Security
Write-Host ""
Write-Host "1.3 Checking S3 bucket security..."
try {
    $buckets = aws s3api list-buckets --output json 2>$null | ConvertFrom-Json
    $a2aBucket = $buckets.Buckets | Where-Object { $_.Name -like "*ca-a2a-documents*" } | Select-Object -First 1
    
    if ($a2aBucket) {
        $encryption = aws s3api get-bucket-encryption --bucket $a2aBucket.Name --region $Region --output json 2>$null | ConvertFrom-Json
        if ($encryption) {
            $algo = $encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
            Test-Pass "S3 Encryption: $algo enabled on $($a2aBucket.Name)"
        } else {
            Test-Fail "S3 Encryption: Not enabled"
        }
        
        $publicBlock = aws s3api get-public-access-block --bucket $a2aBucket.Name --region $Region --output json 2>$null | ConvertFrom-Json
        if ($publicBlock.PublicAccessBlockConfiguration.BlockPublicAcls) {
            Test-Pass "S3 Public Access: Blocked"
        } else {
            Test-Fail "S3 Public Access: Not blocked"
        }
    } else {
        Test-Skip "S3 Bucket: Not found"
    }
} catch {
    Test-Warn "S3 Bucket: Could not check - $_"
}

# ============================================================
# SECTION 2: AUTHENTICATION CONFIGURATION
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "SECTION 2: Authentication Configuration" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""

# Test 2.1: A2A_REQUIRE_AUTH
Write-Host "2.1 Checking authentication requirement..."
$authRequired = Get-TaskEnv -TaskDef "orchestrator" -EnvName "A2A_REQUIRE_AUTH"
if ($authRequired -eq "true") {
    Test-Pass "Authentication: Required (A2A_REQUIRE_AUTH=true)"
} else {
    Test-Warn "Authentication: Not required (A2A_REQUIRE_AUTH=$authRequired)"
}

# Test 2.2: Keycloak Configuration
Write-Host ""
Write-Host "2.2 Checking Keycloak configuration..."
$keycloakUrl = Get-TaskEnv -TaskDef "orchestrator" -EnvName "KEYCLOAK_URL"
$useKeycloak = Get-TaskEnv -TaskDef "orchestrator" -EnvName "A2A_USE_KEYCLOAK"

if ($useKeycloak -eq "true" -and $keycloakUrl) {
    Test-Pass "Keycloak: Enabled (URL: $keycloakUrl)"
} elseif ($keycloakUrl) {
    Test-Warn "Keycloak: URL configured but not enabled"
} else {
    Test-Warn "Keycloak: Not configured"
}

# Test 2.3: API Key Configuration
Write-Host ""
Write-Host "2.3 Checking API key configuration..."
$apiKeysJson = Get-TaskEnv -TaskDef "orchestrator" -EnvName "A2A_API_KEYS_JSON"

if ($apiKeysJson -and $apiKeysJson -ne "None") {
    try {
        $apiKeys = $apiKeysJson | ConvertFrom-Json
        $keyCount = ($apiKeys.PSObject.Properties | Measure-Object).Count
        if ($keyCount -gt 0) {
            Test-Pass "API Keys: $keyCount configured"
        } else {
            Test-Warn "API Keys: Empty configuration"
        }
    } catch {
        Test-Warn "API Keys: Invalid JSON"
    }
} else {
    Test-Warn "API Keys: Not configured"
}

# ============================================================
# SECTION 3: RBAC AUTHORIZATION
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "SECTION 3: RBAC Authorization" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""

# Test 3.1: RBAC Policy
Write-Host "3.1 Checking RBAC policy configuration..."
$rbacPolicy = Get-TaskEnv -TaskDef "orchestrator" -EnvName "A2A_RBAC_POLICY_JSON"

if ($rbacPolicy -and $rbacPolicy -ne "None") {
    try {
        $policy = $rbacPolicy | ConvertFrom-Json
        if ($policy.allow -and $policy.deny) {
            $principals = ($policy.allow.PSObject.Properties | Measure-Object).Count
            Test-Pass "RBAC Policy: Valid ($principals principals defined)"
        } else {
            Test-Fail "RBAC Policy: Missing allow/deny rules"
        }
    } catch {
        Test-Fail "RBAC Policy: Invalid JSON"
    }
} else {
    Test-Warn "RBAC Policy: Not configured"
}

# ============================================================
# SECTION 4: RATE LIMITING
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "SECTION 4: Rate Limiting" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""

Write-Host "4.1 Checking rate limiting configuration..."
$rateLimitEnabled = Get-TaskEnv -TaskDef "orchestrator" -EnvName "A2A_ENABLE_RATE_LIMIT"
$rateLimitPerMin = Get-TaskEnv -TaskDef "orchestrator" -EnvName "A2A_RATE_LIMIT_PER_MINUTE"

if ($rateLimitEnabled -eq "true") {
    if ($rateLimitPerMin) {
        Test-Pass "Rate Limiting: Enabled ($rateLimitPerMin req/min)"
    } else {
        Test-Pass "Rate Limiting: Enabled (default 300 req/min)"
    }
} else {
    Test-Warn "Rate Limiting: Not enabled"
}

# ============================================================
# SECTION 5: REPLAY PROTECTION
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "SECTION 5: Replay Protection" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""

Write-Host "5.1 Checking replay protection configuration..."
$replayEnabled = Get-TaskEnv -TaskDef "orchestrator" -EnvName "A2A_ENABLE_REPLAY_PROTECTION"
$replayTtl = Get-TaskEnv -TaskDef "orchestrator" -EnvName "A2A_REPLAY_TTL_SECONDS"

if ($replayEnabled -eq "true") {
    if ($replayTtl) {
        Test-Pass "Replay Protection: Enabled (TTL: ${replayTtl}s)"
    } else {
        Test-Pass "Replay Protection: Enabled (default TTL: 120s)"
    }
} elseif ($replayEnabled -eq "false") {
    Test-Warn "Replay Protection: Explicitly disabled"
} else {
    Test-Pass "Replay Protection: Using default (enabled)"
}

# ============================================================
# SECTION 6: SCHEMA VALIDATION
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "SECTION 6: JSON Schema Validation" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""

Write-Host "6.1 Checking schema validation configuration..."
$schemaEnabled = Get-TaskEnv -TaskDef "orchestrator" -EnvName "A2A_ENABLE_SCHEMA_VALIDATION"

if ($schemaEnabled -eq "false") {
    Test-Warn "Schema Validation: Explicitly disabled"
} else {
    Test-Pass "Schema Validation: Enabled (default)"
}

# ============================================================
# SECTION 7: AUDIT LOGGING
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "SECTION 7: Audit Logging" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""

Write-Host "7.1 Checking CloudWatch log groups..."
try {
    $logGroups = aws logs describe-log-groups --region $Region --log-group-name-prefix "/ecs/ca-a2a" --output json 2>$null | ConvertFrom-Json
    if ($logGroups.logGroups.Count -gt 0) {
        Test-Pass "CloudWatch Logs: $($logGroups.logGroups.Count) log groups"
    } else {
        Test-Fail "CloudWatch Logs: No log groups found"
    }
} catch {
    Test-Warn "CloudWatch Logs: Could not check - $_"
}

# ============================================================
# SECTION 8: SERVICE STATUS
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Blue
Write-Host "SECTION 8: Service Status" -ForegroundColor Blue
Write-Host "============================================================" -ForegroundColor Blue
Write-Host ""

$services = @("orchestrator", "extractor", "validator", "archivist")
foreach ($service in $services) {
    Write-Host "8.x Checking $service service..."
    try {
        $svcInfo = aws ecs describe-services `
            --cluster $Cluster `
            --services $service `
            --region $Region `
            --output json 2>$null | ConvertFrom-Json
        
        if ($svcInfo.services -and $svcInfo.services[0]) {
            $running = $svcInfo.services[0].runningCount
            $desired = $svcInfo.services[0].desiredCount
            if ($running -eq $desired -and $running -gt 0) {
                Test-Pass "$service`: $running/$desired tasks running"
            } else {
                Test-Fail "$service`: $running/$desired tasks (unhealthy)"
            }
        } else {
            Test-Skip "$service`: Service not found"
        }
    } catch {
        Test-Skip "$service`: Could not check"
    }
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SECURITY TEST SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Passed:   " -ForegroundColor Green -NoNewline
Write-Host $script:Passed
Write-Host "Failed:   " -ForegroundColor Red -NoNewline
Write-Host $script:Failed
Write-Host "Skipped:  " -ForegroundColor Yellow -NoNewline
Write-Host $script:Skipped
Write-Host "Warnings: " -ForegroundColor Yellow -NoNewline
Write-Host $script:Warnings
Write-Host ""

$total = $script:Passed + $script:Failed
if ($total -gt 0) {
    $successRate = [math]::Round(($script:Passed / $total) * 100)
    Write-Host "Success Rate: ${successRate}%"
}

# Security Score
$securityScore = 0
if ($authRequired -eq "true") { $securityScore += 15 }
if ($useKeycloak -eq "true") { $securityScore += 20 }
if ($apiKeysJson -and $apiKeysJson -ne "None") { $securityScore += 10 }
if ($rbacPolicy -and $rbacPolicy -ne "None") { $securityScore += 15 }
if ($rateLimitEnabled -eq "true") { $securityScore += 10 }
if ($replayEnabled -ne "false") { $securityScore += 10 }
if ($schemaEnabled -ne "false") { $securityScore += 10 }
if ($a2aSecrets -and $a2aSecrets.Count -gt 0) { $securityScore += 10 }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SECURITY SCORE: $securityScore/100" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($securityScore -ge 80) {
    Write-Host "Security Level: EXCELLENT" -ForegroundColor Green
} elseif ($securityScore -ge 60) {
    Write-Host "Security Level: GOOD" -ForegroundColor Yellow
} elseif ($securityScore -ge 40) {
    Write-Host "Security Level: MODERATE" -ForegroundColor Yellow
} else {
    Write-Host "Security Level: NEEDS IMPROVEMENT" -ForegroundColor Red
}

Write-Host ""
if ($script:Failed -eq 0) {
    Write-Host "All critical security tests passed." -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some security tests failed. Review and remediate." -ForegroundColor Red
    exit 1
}

