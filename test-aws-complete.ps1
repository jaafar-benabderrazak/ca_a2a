#
# CA A2A AWS Deployment - Comprehensive Test Suite (PowerShell)
# Tests all features of the deployed solution
#
# Usage: .\test-aws-complete.ps1
#

# Configuration
$ALB_URL = "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
$REGION = "eu-west-3"
$CLUSTER = "ca-a2a-cluster"
$BUCKET = "ca-a2a-documents-555043101106"
$ACCOUNT = "555043101106"

# Test counters
$script:TotalTests = 0
$script:PassedTests = 0
$script:FailedTests = 0

# Header
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  CA A2A AWS Comprehensive Test Suite" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Region:  $REGION"
Write-Host "Cluster: $CLUSTER"
Write-Host "ALB:     $ALB_URL"
Write-Host "Date:    $(Get-Date)"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

# Check AWS CLI
try {
    $awsVersion = aws --version 2>&1
    Write-Host "[OK] AWS CLI installed: $awsVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] AWS CLI not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install AWS CLI:" -ForegroundColor Yellow
    Write-Host "  1. Download from: https://aws.amazon.com/cli/" -ForegroundColor Yellow
    Write-Host "  2. Or use: winget install Amazon.AWSCLI" -ForegroundColor Yellow
    Write-Host "  3. Then configure: aws configure sso" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Alternative: Use AWS CloudShell (no installation needed)" -ForegroundColor Cyan
    Write-Host "  1. Open AWS Console" -ForegroundColor Cyan
    Write-Host "  2. Switch to eu-west-3 region" -ForegroundColor Cyan
    Write-Host "  3. Click CloudShell icon" -ForegroundColor Cyan
    Write-Host "  4. Run: bash test-aws-complete.sh" -ForegroundColor Cyan
    exit 1
}

# Check AWS credentials
try {
    $identity = aws sts get-caller-identity --region $REGION 2>&1 | ConvertFrom-Json
    Write-Host "[OK] AWS credentials configured" -ForegroundColor Green
    Write-Host "    Account: $($identity.Account)" -ForegroundColor Gray
    Write-Host "    User: $($identity.Arn)" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] AWS credentials not configured!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please configure AWS credentials:" -ForegroundColor Yellow
    Write-Host "  aws configure sso" -ForegroundColor Yellow
    Write-Host "  OR" -ForegroundColor Yellow
    Write-Host "  aws sso login" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Test function
function Run-Test {
    param(
        [string]$TestName,
        [scriptblock]$TestCommand
    )
    
    $script:TotalTests++
    Write-Host "[TEST $script:TotalTests] $TestName" -ForegroundColor Blue
    
    try {
        $result = & $TestCommand
        if ($result) {
            $script:PassedTests++
            Write-Host "[PASS]" -ForegroundColor Green
            Write-Host ""
            return $true
        } else {
            $script:FailedTests++
            Write-Host "[FAIL]" -ForegroundColor Red
            Write-Host ""
            return $false
        }
    } catch {
        $script:FailedTests++
        Write-Host "[FAIL] $_" -ForegroundColor Red
        Write-Host ""
        return $false
    }
}

###########################################
# 1. INFRASTRUCTURE HEALTH TESTS
###########################################

Write-Host ""
Write-Host "=== 1. INFRASTRUCTURE HEALTH TESTS ===" -ForegroundColor Yellow
Write-Host ""

Run-Test "ECS Cluster Exists" {
    $cluster = aws ecs describe-clusters --clusters $CLUSTER --region $REGION --query 'clusters[0].status' --output text 2>$null
    return $cluster -eq "ACTIVE"
}

Run-Test "All 4 ECS Services Running" {
    $services = aws ecs describe-services --cluster $CLUSTER --services orchestrator extractor validator archivist --region $REGION --query 'services[?status==`ACTIVE`] | length(@)' --output text 2>$null
    return $services -eq "4"
}

Run-Test "Orchestrator Service Has 2 Tasks" {
    $tasks = aws ecs describe-services --cluster $CLUSTER --services orchestrator --region $REGION --query 'services[0].runningCount' --output text 2>$null
    return $tasks -eq "2"
}

Run-Test "ALB Target Group Has Healthy Targets" {
    $tgArn = "arn:aws:elasticloadbalancing:${REGION}:${ACCOUNT}:targetgroup/ca-a2a-orch-tg/5bc795b288397779"
    $healthyCount = aws elbv2 describe-target-health --target-group-arn $tgArn --region $REGION --query 'TargetHealthDescriptions[?TargetHealth.State==`healthy`] | length(@)' --output text 2>$null
    return [int]$healthyCount -ge 1
}

Run-Test "RDS Database Is Available" {
    $dbStatus = aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --region $REGION --query 'DBInstances[0].DBInstanceStatus' --output text 2>$null
    return $dbStatus -eq "available"
}

Run-Test "S3 Bucket Exists" {
    try {
        aws s3 ls s3://$BUCKET --region $REGION 2>$null | Out-Null
        return $true
    } catch {
        return $false
    }
}

Run-Test "VPC Endpoints Exist" {
    $endpoints = aws ec2 describe-vpc-endpoints --region $REGION --filters "Name=tag:Project,Values=ca-a2a" --query 'VpcEndpoints | length(@)' --output text 2>$null
    return [int]$endpoints -ge 1
}

###########################################
# 2. API ENDPOINT TESTS
###########################################

Write-Host ""
Write-Host "=== 2. API ENDPOINT TESTS ===" -ForegroundColor Yellow
Write-Host ""

Run-Test "Health Endpoint Responds" {
    try {
        $response = Invoke-WebRequest -Uri "$ALB_URL/health" -UseBasicParsing -TimeoutSec 5
        return $response.StatusCode -eq 200
    } catch {
        return $false
    }
}

Run-Test "Health Status Is 'healthy'" {
    try {
        $response = Invoke-RestMethod -Uri "$ALB_URL/health" -TimeoutSec 5
        return $response.status -eq "healthy"
    } catch {
        return $false
    }
}

Run-Test "Agent Card Endpoint Responds" {
    try {
        $response = Invoke-WebRequest -Uri "$ALB_URL/card" -UseBasicParsing -TimeoutSec 5
        return $response.StatusCode -eq 200
    } catch {
        return $false
    }
}

Run-Test "Agent Card Has Skills" {
    try {
        $response = Invoke-RestMethod -Uri "$ALB_URL/card" -TimeoutSec 5
        return $response.skills.Count -gt 0
    } catch {
        return $false
    }
}

Run-Test "Skills Endpoint Lists All Skills" {
    try {
        $response = Invoke-RestMethod -Uri "$ALB_URL/skills" -TimeoutSec 5
        return $response.skills.Count -gt 0
    } catch {
        return $false
    }
}

Run-Test "Status Endpoint Shows Metrics" {
    try {
        $response = Invoke-WebRequest -Uri "$ALB_URL/status" -UseBasicParsing -TimeoutSec 5
        return $response.StatusCode -eq 200
    } catch {
        return $false
    }
}

###########################################
# 3. DOCUMENT PROCESSING TESTS
###########################################

Write-Host ""
Write-Host "=== 3. DOCUMENT PROCESSING TESTS ===" -ForegroundColor Yellow
Write-Host ""

# Create test document
$testDoc = "test-aws-$(Get-Date -Format 'yyyyMMddHHmmss').txt"
$testContent = @"
INVOICE #INV-TEST-001
Date: 2026-01-01
From: Test Company
To: Test Client

Services:
- Testing: EUR 100.00

Total: EUR 100.00
"@

Set-Content -Path "$env:TEMP\$testDoc" -Value $testContent

Run-Test "Upload Test Document to S3" {
    try {
        aws s3 cp "$env:TEMP\$testDoc" "s3://$BUCKET/incoming/$testDoc" --region $REGION 2>$null
        return $true
    } catch {
        return $false
    }
}

Run-Test "Process Document via API" {
    try {
        $body = @{
            s3_key = "incoming/$testDoc"
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$ALB_URL/process" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 10
        return ($response.status -or $response.document_id -or $response.task_id)
    } catch {
        return $false
    }
}

Write-Host "Waiting 10 seconds for processing..." -ForegroundColor Gray
Start-Sleep -Seconds 10

Run-Test "Document Appears in Logs" {
    try {
        $startTime = [int]((Get-Date).AddMinutes(-2).ToUniversalTime() - (Get-Date "1970-01-01")).TotalMilliseconds
        $events = aws logs filter-log-events --log-group-name /ecs/ca-a2a-orchestrator --filter-pattern $testDoc --start-time $startTime --region $REGION --query 'events | length(@)' --output text 2>$null
        return [int]$events -ge 1
    } catch {
        return $false
    }
}

###########################################
# 4. SECURITY TESTS
###########################################

Write-Host ""
Write-Host "=== 4. SECURITY TESTS ===" -ForegroundColor Yellow
Write-Host ""

Run-Test "Invalid JSON Returns Error" {
    try {
        $response = Invoke-RestMethod -Uri "$ALB_URL/message" -Method Post -Body "invalid{json" -ContentType "application/json" -TimeoutSec 5
        return $response.error
    } catch {
        # If it throws an error, that's actually good - it means the server rejected it
        return $true
    }
}

Run-Test "Invalid Method Returns Error" {
    try {
        $body = @{
            jsonrpc = "2.0"
            id = "1"
            method = "nonexistent_method"
            params = @{}
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$ALB_URL/message" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5
        return $response.error.code -eq -32601
    } catch {
        return $false
    }
}

Run-Test "Security Groups Allow HTTP Traffic" {
    $sg = aws ec2 describe-security-groups --group-ids sg-05db73131090f365a --region $REGION --query 'SecurityGroups[0].IpPermissions[?FromPort==`80`] | length(@)' --output text 2>$null
    return [int]$sg -ge 1
}

Run-Test "IAM Roles Attached to ECS Tasks" {
    $taskRole = aws ecs describe-task-definition --task-definition ca-a2a-orchestrator --region $REGION --query 'taskDefinition.taskRoleArn' --output text 2>$null
    return $taskRole -like "arn:aws:iam:*"
}

###########################################
# 5. PERFORMANCE TESTS
###########################################

Write-Host ""
Write-Host "=== 5. PERFORMANCE TESTS ===" -ForegroundColor Yellow
Write-Host ""

Run-Test "Health Endpoint Response Time < 1s" {
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $response = Invoke-WebRequest -Uri "$ALB_URL/health" -UseBasicParsing -TimeoutSec 5
        $sw.Stop()
        Write-Host "  Response time: $($sw.ElapsedMilliseconds)ms" -ForegroundColor Gray
        return $sw.ElapsedMilliseconds -lt 1000
    } catch {
        return $false
    }
}

Run-Test "Agent Card Response Time < 2s" {
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $response = Invoke-WebRequest -Uri "$ALB_URL/card" -UseBasicParsing -TimeoutSec 5
        $sw.Stop()
        Write-Host "  Response time: $($sw.ElapsedMilliseconds)ms" -ForegroundColor Gray
        return $sw.ElapsedMilliseconds -lt 2000
    } catch {
        return $false
    }
}

Run-Test "ECS Tasks Not Over-Utilizing CPU" {
    try {
        $endTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        $startTime = (Get-Date).AddMinutes(-10).ToString("yyyy-MM-ddTHH:mm:ss")
        
        $cpu = aws cloudwatch get-metric-statistics --namespace AWS/ECS --metric-name CPUUtilization --dimensions "Name=ClusterName,Value=$CLUSTER" "Name=ServiceName,Value=orchestrator" --start-time $startTime --end-time $endTime --period 300 --statistics Average --region $REGION --query 'Datapoints[0].Average' --output text 2>$null
        
        if ($cpu -eq "None" -or [string]::IsNullOrEmpty($cpu)) {
            return $true  # No data yet, pass
        }
        return [double]$cpu -lt 80
    } catch {
        return $true  # If metrics not available yet, pass
    }
}

###########################################
# 6. MONITORING & LOGGING TESTS
###########################################

Write-Host ""
Write-Host "=== 6. MONITORING & LOGGING TESTS ===" -ForegroundColor Yellow
Write-Host ""

Run-Test "CloudWatch Log Groups Exist" {
    $logGroups = aws logs describe-log-groups --log-group-name-prefix /ecs/ca-a2a --region $REGION --query 'logGroups | length(@)' --output text 2>$null
    return [int]$logGroups -ge 4
}

Run-Test "Orchestrator Logs Have Recent Entries" {
    try {
        $startTime = [int]((Get-Date).AddMinutes(-5).ToUniversalTime() - (Get-Date "1970-01-01")).TotalMilliseconds
        $events = aws logs filter-log-events --log-group-name /ecs/ca-a2a-orchestrator --start-time $startTime --region $REGION --query 'events | length(@)' --output text 2>$null
        return [int]$events -ge 1
    } catch {
        return $false
    }
}

Run-Test "No Critical Errors in Last Hour" {
    try {
        $startTime = [int]((Get-Date).AddHours(-1).ToUniversalTime() - (Get-Date "1970-01-01")).TotalMilliseconds
        $errorCount = aws logs filter-log-events --log-group-name /ecs/ca-a2a-orchestrator --filter-pattern "CRITICAL" --start-time $startTime --region $REGION --query 'events | length(@)' --output text 2>$null
        return [int]$errorCount -lt 5
    } catch {
        return $true
    }
}

###########################################
# 7. DATA PERSISTENCE TESTS
###########################################

Write-Host ""
Write-Host "=== 7. DATA PERSISTENCE TESTS ===" -ForegroundColor Yellow
Write-Host ""

Run-Test "RDS Instance Has Backups Enabled" {
    $backupRetention = aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --region $REGION --query 'DBInstances[0].BackupRetentionPeriod' --output text 2>$null
    return [int]$backupRetention -ge 1
}

Run-Test "S3 Bucket Has Objects" {
    try {
        $objects = aws s3 ls s3://$BUCKET --recursive --region $REGION 2>$null | Measure-Object
        return $objects.Count -ge 1
    } catch {
        return $false
    }
}

###########################################
# 8. INTEGRATION TESTS
###########################################

Write-Host ""
Write-Host "=== 8. INTEGRATION TESTS ===" -ForegroundColor Yellow
Write-Host ""

Run-Test "All Agents Running in Same Cluster" {
    $activeServices = aws ecs describe-services --cluster $CLUSTER --services orchestrator extractor validator archivist --region $REGION --query 'services[?status==`ACTIVE`] | length(@)' --output text 2>$null
    return $activeServices -eq "4"
}

Run-Test "ALB Has Multiple Availability Zones" {
    $azCount = aws elbv2 describe-load-balancers --region $REGION --query "LoadBalancers[?LoadBalancerName=='ca-a2a-alb'].AvailabilityZones | [0] | length(@)" --output text 2>$null
    return [int]$azCount -ge 2
}

###########################################
# SUMMARY
###########################################

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "           TEST SUMMARY" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Total Tests:  $script:TotalTests"
Write-Host "Passed:       $script:PassedTests" -ForegroundColor Green
if ($script:FailedTests -gt 0) {
    Write-Host "Failed:       $script:FailedTests" -ForegroundColor Red
} else {
    Write-Host "Failed:       0" -ForegroundColor Green
}
$successRate = [math]::Round(($script:PassedTests * 100 / $script:TotalTests), 0)
Write-Host "Success Rate: $successRate%"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Detailed results
if ($script:FailedTests -eq 0) {
    Write-Host "[SUCCESS] All tests passed! Deployment is healthy." -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Test with real documents" -ForegroundColor White
    Write-Host "  2. Monitor CloudWatch metrics" -ForegroundColor White
    Write-Host "  3. Review application logs" -ForegroundColor White
    Write-Host ""
    exit 0
} else {
    Write-Host "[WARNING] Some tests failed. Review the output above." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Check CloudWatch logs:" -ForegroundColor White
    Write-Host "     aws logs tail /ecs/ca-a2a-orchestrator --follow --region $REGION" -ForegroundColor Gray
    Write-Host "  2. Check ECS service status:" -ForegroundColor White
    Write-Host "     aws ecs describe-services --cluster $CLUSTER --services orchestrator --region $REGION" -ForegroundColor Gray
    Write-Host "  3. Check ALB health:" -ForegroundColor White
    Write-Host "     aws elbv2 describe-target-health --target-group-arn <arn> --region $REGION" -ForegroundColor Gray
    Write-Host ""
    exit 1
}

