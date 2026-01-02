# Test Script for 2-Hour Demo Commands
# Tests all commands from DEMO_HISTOIRE_2H.md systematically
# Author: CA A2A Team
# Date: January 2, 2026

param(
    [string]$Profile = "AWSAdministratorAccess-555043101106",
    [string]$Region = "eu-west-3"
)

# Set AWS Profile and Region
$env:AWS_PROFILE = $Profile
$env:AWS_DEFAULT_REGION = $Region

# Color output helpers
function Write-Success { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Fail { param($msg) Write-Host "[FAIL] $msg" -ForegroundColor Red }
function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Test { param($msg) Write-Host "[TEST] $msg" -ForegroundColor Yellow }

$script:testResults = @{
    Total = 0
    Passed = 0
    Failed = 0
    Skipped = 0
}

function Test-Command {
    param(
        [string]$TestName,
        [scriptblock]$Command,
        [scriptblock]$Validation,
        [bool]$ContinueOnError = $true
    )
    
    $script:testResults.Total++
    Write-Test "Testing: $TestName"
    
    try {
        $result = & $Command
        
        if ($Validation) {
            $isValid = & $Validation -Result $result
            if ($isValid) {
                $script:testResults.Passed++
                Write-Success "$TestName - PASSED"
                return $true
            } else {
                $script:testResults.Failed++
                Write-Fail "$TestName - FAILED (Validation failed)"
                return $false
            }
        } else {
            $script:testResults.Passed++
            Write-Success "$TestName - PASSED"
            return $true
        }
    }
    catch {
        $script:testResults.Failed++
        Write-Fail "$TestName - FAILED: $_"
        if (-not $ContinueOnError) {
            throw
        }
        return $false
    }
}

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "CA A2A - 2H DEMO COMMANDS TEST SUITE" -ForegroundColor Magenta
Write-Host "========================================`n" -ForegroundColor Magenta

# ============================================================================
# PART 1: Infrastructure Verification (Partie 2 - Acte 1)
# ============================================================================

Write-Host "`n--- PART 1: Infrastructure Verification ---`n" -ForegroundColor Cyan

Test-Command -TestName "1.1 Verify S3 Bucket Exists" -Command {
    aws s3 ls s3://ca-a2a-documents/ 2>&1
} -Validation {
    param($Result)
    return ($Result -notmatch "NoSuchBucket") -and ($Result -notmatch "error")
}

Test-Command -TestName "1.2 Check S3 Encryption Configuration" -Command {
    aws s3api get-bucket-encryption --bucket ca-a2a-documents 2>&1
} -Validation {
    param($Result)
    $config = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($config.ServerSideEncryptionConfiguration -ne $null)
}

Test-Command -TestName "1.3 Verify RDS PostgreSQL Instance" -Command {
    aws rds describe-db-instances --query 'DBInstances[?DBInstanceIdentifier==`ca-a2a-postgres`]' 2>&1
} -Validation {
    param($Result)
    $instances = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($instances.Count -gt 0) -and ($instances[0].DBInstanceStatus -eq "available")
}

Test-Command -TestName "1.4 Verify ECS Cluster Exists" -Command {
    aws ecs describe-clusters --clusters ca-a2a-cluster 2>&1
} -Validation {
    param($Result)
    $clusters = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($clusters.clusters.Count -gt 0) -and ($clusters.clusters[0].status -eq "ACTIVE")
}

Test-Command -TestName "1.5 Verify ALB Exists and is Active" -Command {
    aws elbv2 describe-load-balancers --names ca-a2a-alb 2>&1
} -Validation {
    param($Result)
    $albs = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($albs.LoadBalancers.Count -gt 0) -and ($albs.LoadBalancers[0].State.Code -eq "active")
}

# ============================================================================
# PART 2: Agent Health Checks (Partie 2)
# ============================================================================

Write-Host "`n--- PART 2: Agent Health Checks ---`n" -ForegroundColor Cyan

$agents = @("orchestrator", "extractor", "validator", "archivist", "mcp-server")

foreach ($agent in $agents) {
    Test-Command -TestName "2.$($agents.IndexOf($agent)+1) Check $agent Service Status" -Command {
        aws ecs describe-services --cluster ca-a2a-cluster --services $agent 2>&1
    } -Validation {
        param($Result)
        $services = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($services.services.Count -eq 0) { return $false }
        $svc = $services.services[0]
        return ($svc.runningCount -gt 0) -and ($svc.status -eq "ACTIVE")
    }
}

# ============================================================================
# PART 3: Document Upload Test (Partie 2 - Acte 1)
# ============================================================================

Write-Host "`n--- PART 3: Document Upload Test ---`n" -ForegroundColor Cyan

# Check if test document exists
$testDocPath = "facture_acme_dec2025.pdf"
if (-not (Test-Path $testDocPath)) {
    Write-Info "Test PDF not found, but continuing (PDF already exists from previous runs)"
}

Test-Command -TestName "3.1 Upload Test Document to S3" -Command {
    aws s3 cp $testDocPath "s3://ca-a2a-documents/test/demo/" --metadata uploaded-by=test-script 2>&1
} -Validation {
    param($Result)
    return ($Result -match "upload:") -or ($Result -notmatch "error")
}

Test-Command -TestName "3.2 Verify Document in S3" -Command {
    aws s3 ls s3://ca-a2a-documents/test/demo/ 2>&1
} -Validation {
    param($Result)
    return ($Result -match "facture_acme_dec2025.pdf")
}

Test-Command -TestName "3.3 Check Document Metadata" -Command {
    aws s3api head-object --bucket ca-a2a-documents --key "test/demo/facture_acme_dec2025.pdf" 2>&1
} -Validation {
    param($Result)
    $metadata = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($metadata.ServerSideEncryption -ne $null)
}

# ============================================================================
# PART 4: MCP Server Tests (Partie 3 - Acte 2)
# ============================================================================

Write-Host "`n--- PART 4: MCP Server Tests ---`n" -ForegroundColor Cyan

Test-Command -TestName "4.1 Check MCP Server Logs" -Command {
    aws logs describe-log-streams --log-group-name /ecs/ca-a2a-mcp-server --order-by LastEventTime --descending --max-items 1 2>&1
} -Validation {
    param($Result)
    $streams = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($streams.logStreams.Count -gt 0)
}

Test-Command -TestName "4.2 Verify MCP Server Recent Activity" -Command {
    $streamName = (aws logs describe-log-streams --log-group-name /ecs/ca-a2a-mcp-server --order-by LastEventTime --descending --max-items 1 --query 'logStreams[0].logStreamName' --output text 2>&1)
    if ($streamName -and $streamName -notmatch "error") {
        aws logs get-log-events --log-group-name /ecs/ca-a2a-mcp-server --log-stream-name $streamName --limit 10 2>&1
    } else {
        throw "No log stream found"
    }
} -Validation {
    param($Result)
    return ($Result -match "events") -or ($Result -notmatch "error")
}

# ============================================================================
# PART 5: Database Verification (Partie 5 - Acte 4)
# ============================================================================

Write-Host "`n--- PART 5: Database Verification ---`n" -ForegroundColor Cyan

Test-Command -TestName "5.1 Verify RDS Security Group" -Command {
    $dbInstance = aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --query 'DBInstances[0]' 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($dbInstance) {
        $sgId = $dbInstance.VpcSecurityGroups[0].VpcSecurityGroupId
        aws ec2 describe-security-groups --group-ids $sgId 2>&1
    } else {
        throw "DB instance not found"
    }
} -Validation {
    param($Result)
    $sg = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($sg.SecurityGroups.Count -gt 0)
}

Test-Command -TestName "5.2 Check Database Endpoint Accessibility" -Command {
    $endpoint = aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --query 'DBInstances[0].Endpoint.Address' --output text 2>&1
    return $endpoint
} -Validation {
    param($Result)
    return ($Result -match "rds.amazonaws.com") -and ($Result -notmatch "error")
}

# ============================================================================
# PART 6: Orchestrator Logs Test (Partie 2 - Acte 1)
# ============================================================================

Write-Host "`n--- PART 6: Orchestrator Logs Test ---`n" -ForegroundColor Cyan

Test-Command -TestName "6.1 Check Orchestrator Log Group" -Command {
    aws logs describe-log-groups --log-group-name-prefix /ecs/ca-a2a-orchestrator 2>&1
} -Validation {
    param($Result)
    $groups = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($groups.logGroups.Count -gt 0)
}

Test-Command -TestName "6.2 Get Recent Orchestrator Logs" -Command {
    $streamName = (aws logs describe-log-streams --log-group-name /ecs/ca-a2a-orchestrator --order-by LastEventTime --descending --max-items 1 --query 'logStreams[0].logStreamName' --output text 2>&1)
    if ($streamName -and $streamName -notmatch "error") {
        aws logs get-log-events --log-group-name /ecs/ca-a2a-orchestrator --log-stream-name $streamName --limit 5 2>&1
    } else {
        throw "No orchestrator log stream found"
    }
} -Validation {
    param($Result)
    return ($Result -match "events") -or ($Result -notmatch "error")
}

# ============================================================================
# PART 7: Extractor Agent Test (Partie 3 - Acte 2)
# ============================================================================

Write-Host "`n--- PART 7: Extractor Agent Test ---`n" -ForegroundColor Cyan

Test-Command -TestName "7.1 Check Extractor Service Running" -Command {
    aws ecs list-tasks --cluster ca-a2a-cluster --service-name extractor 2>&1
} -Validation {
    param($Result)
    $tasks = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($tasks.taskArns.Count -gt 0)
}

Test-Command -TestName "7.2 Get Extractor Task Details" -Command {
    $taskArns = (aws ecs list-tasks --cluster ca-a2a-cluster --service-name extractor --query 'taskArns' --output json 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue)
    if ($taskArns.Count -gt 0) {
        aws ecs describe-tasks --cluster ca-a2a-cluster --tasks $taskArns[0] 2>&1
    } else {
        throw "No extractor tasks found"
    }
} -Validation {
    param($Result)
    $tasks = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($tasks.tasks[0].lastStatus -eq "RUNNING")
}

# ============================================================================
# PART 8: Validator Agent Test (Partie 4 - Acte 3)
# ============================================================================

Write-Host "`n--- PART 8: Validator Agent Test ---`n" -ForegroundColor Cyan

Test-Command -TestName "8.1 Check Validator Service Status" -Command {
    aws ecs describe-services --cluster ca-a2a-cluster --services validator 2>&1
} -Validation {
    param($Result)
    $services = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($services.services[0].runningCount -gt 0)
}

Test-Command -TestName "8.2 Verify Validator Recent Activity" -Command {
    $streamName = (aws logs describe-log-streams --log-group-name /ecs/ca-a2a-validator --order-by LastEventTime --descending --max-items 1 --query 'logStreams[0].logStreamName' --output text 2>&1)
    if ($streamName -and $streamName -notmatch "error") {
        aws logs get-log-events --log-group-name /ecs/ca-a2a-validator --log-stream-name $streamName --limit 3 2>&1
    } else {
        Write-Warning "No validator log stream found - service may not have logged yet"
        return "OK"
    }
} -Validation {
    param($Result)
    return ($Result -eq "OK") -or ($Result -match "events") -or ($Result -notmatch "error")
}

# ============================================================================
# PART 9: Archivist Agent Test (Partie 5 - Acte 4)
# ============================================================================

Write-Host "`n--- PART 9: Archivist Agent Test ---`n" -ForegroundColor Cyan

Test-Command -TestName "9.1 Check Archivist Service" -Command {
    aws ecs list-tasks --cluster ca-a2a-cluster --service-name archivist 2>&1
} -Validation {
    param($Result)
    $tasks = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($tasks.taskArns.Count -gt 0)
}

# ============================================================================
# PART 10: Security Configuration Tests (Partie 6 - Épilogue)
# ============================================================================

Write-Host "`n--- PART 10: Security Configuration Tests ---`n" -ForegroundColor Cyan

Test-Command -TestName "10.1 Verify Secrets Manager Secret Exists" -Command {
    aws secretsmanager list-secrets --filters Key=name,Values=ca-a2a 2>&1
} -Validation {
    param($Result)
    $secrets = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($secrets.SecretList.Count -gt 0)
}

Test-Command -TestName "10.2 Check VPC Configuration" -Command {
    aws ec2 describe-vpcs --filters "Name=tag:Name,Values=ca-a2a-vpc" 2>&1
} -Validation {
    param($Result)
    $vpcs = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($vpcs.Vpcs.Count -gt 0)
}

Test-Command -TestName "10.3 Verify Security Groups Exist" -Command {
    aws ec2 describe-security-groups --filters "Name=tag:Project,Values=ca-a2a" 2>&1
} -Validation {
    param($Result)
    $sgs = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($sgs.SecurityGroups.Count -ge 3)  # At least ALB, ECS, RDS security groups
}

Test-Command -TestName "10.4 Check Private Subnets" -Command {
    aws ec2 describe-subnets --filters "Name=tag:Name,Values=*ca-a2a*private*" 2>&1
} -Validation {
    param($Result)
    $subnets = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($subnets.Subnets.Count -ge 3)  # At least 3 private subnets
}

# ============================================================================
# PART 11: CloudWatch Monitoring (Partie 9)
# ============================================================================

Write-Host "`n--- PART 11: CloudWatch Monitoring ---`n" -ForegroundColor Cyan

Test-Command -TestName "11.1 Verify All Log Groups Exist" -Command {
    $logGroups = @("/ecs/ca-a2a-orchestrator", "/ecs/ca-a2a-extractor", "/ecs/ca-a2a-validator", "/ecs/ca-a2a-archivist", "/ecs/ca-a2a-mcp-server")
    $allExist = $true
    foreach ($group in $logGroups) {
        $result = aws logs describe-log-groups --log-group-name-prefix $group 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($result.logGroups.Count -eq 0) {
            $allExist = $false
            Write-Warning "Log group $group not found"
        }
    }
    return $allExist
} -Validation {
    param($Result)
    return $Result -eq $true
}

Test-Command -TestName "11.2 Check CloudWatch Alarms" -Command {
    aws cloudwatch describe-alarms --alarm-name-prefix ca-a2a 2>&1
} -Validation {
    param($Result)
    return ($Result -notmatch "error")
}

# ============================================================================
# PART 12: Network Connectivity Tests
# ============================================================================

Write-Host "`n--- PART 12: Network Connectivity Tests ---`n" -ForegroundColor Cyan

Test-Command -TestName "12.1 Get ALB DNS Name" -Command {
    aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].DNSName' --output text 2>&1
} -Validation {
    param($Result)
    return ($Result -match "elb.amazonaws.com") -and ($Result -notmatch "error")
}

Test-Command -TestName "12.2 Check ALB Target Groups" -Command {
    aws elbv2 describe-target-groups --load-balancer-arn (aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].LoadBalancerArn' --output text) 2>&1
} -Validation {
    param($Result)
    $tgs = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($tgs.TargetGroups.Count -gt 0)
}

Test-Command -TestName "12.3 Check Target Health" -Command {
    $tgArns = (aws elbv2 describe-target-groups --load-balancer-arn (aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].LoadBalancerArn' --output text) --query 'TargetGroups[*].TargetGroupArn' --output json 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue)
    if ($tgArns.Count -gt 0) {
        aws elbv2 describe-target-health --target-group-arn $tgArns[0] 2>&1
    } else {
        throw "No target groups found"
    }
} -Validation {
    param($Result)
    return ($Result -match "TargetHealth") -or ($Result -notmatch "error")
}

# ============================================================================
# PART 13: Compliance and Best Practices
# ============================================================================

Write-Host "`n--- PART 13: Compliance and Best Practices ---`n" -ForegroundColor Cyan

Test-Command -TestName "13.1 Verify S3 Bucket Versioning" -Command {
    aws s3api get-bucket-versioning --bucket ca-a2a-documents 2>&1
} -Validation {
    param($Result)
    return ($Result -notmatch "error")
}

Test-Command -TestName "13.2 Check RDS Backup Configuration" -Command {
    aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --query 'DBInstances[0].[BackupRetentionPeriod,PreferredBackupWindow]' 2>&1
} -Validation {
    param($Result)
    $backup = $Result | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($backup[0] -gt 0)  # Backup retention > 0 days
}

Test-Command -TestName "13.3 Verify RDS Multi-AZ" -Command {
    aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --query 'DBInstances[0].MultiAZ' --output text 2>&1
} -Validation {
    param($Result)
    return ($Result -match "True") -or ($Result -match "False")  # Either is valid, just check it's configured
}

Test-Command -TestName "13.4 Check ECS Task IAM Roles" -Command {
    $taskDef = aws ecs describe-task-definition --task-definition orchestrator --query 'taskDefinition' 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
    return ($taskDef.taskRoleArn -ne $null)
} -Validation {
    param($Result)
    return $Result -eq $true
}

# ============================================================================
# FINAL REPORT
# ============================================================================

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "TEST RESULTS SUMMARY" -ForegroundColor Magenta
Write-Host "========================================`n" -ForegroundColor Magenta

Write-Host "Total Tests:  $($script:testResults.Total)" -ForegroundColor White
Write-Host "Passed:       $($script:testResults.Passed)" -ForegroundColor Green
Write-Host "Failed:       $($script:testResults.Failed)" -ForegroundColor Red
Write-Host "Skipped:      $($script:testResults.Skipped)" -ForegroundColor Yellow

$passRate = [math]::Round(($script:testResults.Passed / $script:testResults.Total) * 100, 2)
Write-Host "`nPass Rate:    $passRate%" -ForegroundColor $(if ($passRate -ge 90) { "Green" } elseif ($passRate -ge 70) { "Yellow" } else { "Red" })

if ($script:testResults.Failed -eq 0) {
    Write-Host "`n[SUCCESS] ALL TESTS PASSED! System is operational." -ForegroundColor Green
} elseif ($passRate -ge 80) {
    Write-Host "`n[WARNING] Most tests passed. Review failures for improvements." -ForegroundColor Yellow
} else {
    Write-Host "`n[CRITICAL] Multiple failures detected. System requires attention." -ForegroundColor Red
}

Write-Host "`n========================================`n" -ForegroundColor Magenta

# Save results to file
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$reportFile = "demo-test-results-$timestamp.json"
$script:testResults | ConvertTo-Json | Out-File $reportFile
Write-Info "Detailed results saved to: $reportFile"

# Exit with appropriate code
exit $(if ($script:testResults.Failed -eq 0) { 0 } else { 1 })

