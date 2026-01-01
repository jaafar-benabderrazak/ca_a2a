# AWS Deployment Test Script
# Tests the deployed multi-agent system on AWS ECS Fargate

param(
    [Parameter(Mandatory=$false)]
    [string]$AlbDnsName,
    
    [Parameter(Mandatory=$false)]
    [string]$S3BucketName,
    
    [Parameter(Mandatory=$false)]
    [string]$AwsRegion = "us-east-1"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "AWS Deployment Testing Script" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Set AWS region
$env:AWS_DEFAULT_REGION = $AwsRegion

# Function to test API endpoint
function Test-Endpoint {
    param(
        [string]$Url,
        [string]$TestName,
        [hashtable]$Body = $null,
        [string]$Method = "GET"
    )
    
    Write-Host "Testing: $TestName" -ForegroundColor Yellow
    Write-Host "  URL: $Url" -ForegroundColor Gray
    
    try {
        if ($Method -eq "GET") {
            $response = Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 30
        } else {
            $jsonBody = $Body | ConvertTo-Json -Depth 10
            $response = Invoke-RestMethod -Uri $Url -Method Post -Body $jsonBody -ContentType "application/json" -TimeoutSec 30
        }
        
        Write-Host "  ✓ SUCCESS" -ForegroundColor Green
        return @{ Success = $true; Data = $response }
    }
    catch {
        Write-Host "  ✗ FAILED: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Get ALB DNS name if not provided
if (-not $AlbDnsName) {
    Write-Host "Getting ALB DNS name..." -ForegroundColor Yellow
    try {
        $albInfo = aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].DNSName' --output text 2>&1
        if ($LASTEXITCODE -eq 0 -and $albInfo -notlike "*error*") {
            $AlbDnsName = $albInfo
            Write-Host "  Found: $AlbDnsName" -ForegroundColor Green
        } else {
            Write-Host "  Could not find ALB. Please provide -AlbDnsName parameter." -ForegroundColor Red
            exit 1
        }
    }
    catch {
        Write-Host "  Error getting ALB DNS: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

$baseUrl = "http://$AlbDnsName"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Phase 1: Infrastructure Validation" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Test 1: Health Check
$test1 = Test-Endpoint -Url "$baseUrl/health" -TestName "Orchestrator Health Check"
if (-not $test1.Success) {
    Write-Host "`nCritical: Orchestrator health check failed. Cannot continue.`n" -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 1

# Test 2: Status Endpoint
$test2 = Test-Endpoint -Url "$baseUrl/status" -TestName "Orchestrator Status"

Start-Sleep -Seconds 1

# Test 3: Agent Card
$test3 = Test-Endpoint -Url "$baseUrl/card" -TestName "Orchestrator Agent Card"

Start-Sleep -Seconds 1

# Test 4: Skills List
$test4 = Test-Endpoint -Url "$baseUrl/skills" -TestName "Orchestrator Skills"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Phase 2: Agent Discovery" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Test 5: Discover Agents
$discoveryBody = @{
    jsonrpc = "2.0"
    id = "test-discover"
    method = "discover_agents"
    params = @{}
}

$test5 = Test-Endpoint -Url "$baseUrl/message" -TestName "Agent Discovery" -Body $discoveryBody -Method "POST"

if ($test5.Success) {
    $discovered = $test5.Data.result.discovered_agents
    $totalSkills = $test5.Data.result.total_skills
    Write-Host "  Discovered: $discovered agents, $totalSkills skills" -ForegroundColor Cyan
}

Start-Sleep -Seconds 1

# Test 6: Get Agent Registry
$registryBody = @{
    jsonrpc = "2.0"
    id = "test-registry"
    method = "get_agent_registry"
    params = @{}
}

$test6 = Test-Endpoint -Url "$baseUrl/message" -TestName "Agent Registry" -Body $registryBody -Method "POST"

if ($test6.Success) {
    $totalAgents = $test6.Data.result.total_agents
    $activeAgents = $test6.Data.result.active_agents
    Write-Host "  Total agents: $totalAgents, Active: $activeAgents" -ForegroundColor Cyan
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Phase 3: S3 Integration Test" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get S3 bucket if not provided
if (-not $S3BucketName) {
    Write-Host "Getting S3 bucket name..." -ForegroundColor Yellow
    try {
        $accountId = aws sts get-caller-identity --query Account --output text
        $S3BucketName = "ca-a2a-documents-$accountId"
        Write-Host "  Using: $S3BucketName" -ForegroundColor Green
    }
    catch {
        Write-Host "  Warning: Could not determine S3 bucket name" -ForegroundColor Yellow
    }
}

if ($S3BucketName) {
    # Create test file
    $testFile = "test-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    $testContent = "Test document for AWS deployment validation"
    $testContent | Out-File -FilePath $testFile -Encoding UTF8
    
    Write-Host "Uploading test file to S3..." -ForegroundColor Yellow
    try {
        aws s3 cp $testFile "s3://$S3BucketName/test-documents/$testFile"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ SUCCESS: File uploaded" -ForegroundColor Green
            $s3Key = "test-documents/$testFile"
        } else {
            Write-Host "  ✗ FAILED: Could not upload file" -ForegroundColor Red
            $s3Key = $null
        }
    }
    catch {
        Write-Host "  ✗ FAILED: $($_.Exception.Message)" -ForegroundColor Red
        $s3Key = $null
    }
    finally {
        Remove-Item $testFile -ErrorAction SilentlyContinue
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Phase 4: End-to-End Document Processing" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($s3Key) {
    # Test 7: Process Document
    $correlationId = "test-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    
    $processBody = @{
        jsonrpc = "2.0"
        id = "test-process"
        method = "process_document"
        params = @{
            s3_key = $s3Key
            priority = "normal"
        }
    }
    
    $test7 = Test-Endpoint -Url "$baseUrl/message" -TestName "Process Document" -Body $processBody -Method "POST"
    
    if ($test7.Success -and $test7.Data.result) {
        $taskId = $test7.Data.result.task_id
        Write-Host "  Task ID: $taskId" -ForegroundColor Cyan
        
        # Wait for processing
        Write-Host "`nWaiting for document processing (30 seconds)..." -ForegroundColor Yellow
        Start-Sleep -Seconds 30
        
        # Test 8: Check Task Status
        $statusBody = @{
            jsonrpc = "2.0"
            id = "test-status"
            method = "get_task_status"
            params = @{
                task_id = $taskId
            }
        }
        
        $test8 = Test-Endpoint -Url "$baseUrl/message" -TestName "Task Status" -Body $statusBody -Method "POST"
        
        if ($test8.Success -and $test8.Data.result) {
            $status = $test8.Data.result.status
            $currentStage = $test8.Data.result.current_stage
            Write-Host "  Status: $status" -ForegroundColor Cyan
            Write-Host "  Current Stage: $currentStage" -ForegroundColor Cyan
            
            if ($test8.Data.result.stages) {
                Write-Host "  Stages:" -ForegroundColor Cyan
                $test8.Data.result.stages.PSObject.Properties | ForEach-Object {
                    $stageName = $_.Name
                    $stageStatus = $_.Value.status
                    $stageIcon = if ($stageStatus -eq "completed") { "✓" } elseif ($stageStatus -eq "failed") { "✗" } else { "⋯" }
                    Write-Host "    $stageIcon $stageName : $stageStatus" -ForegroundColor $(if ($stageStatus -eq "completed") { "Green" } elseif ($stageStatus -eq "failed") { "Red" } else { "Yellow" })
                }
            }
        }
    } else {
        Write-Host "  ✗ Document processing failed or returned no task ID" -ForegroundColor Red
    }
} else {
    Write-Host "  ⊘ Skipping document processing (no S3 key available)" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Phase 5: Performance & Monitoring" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Test multiple requests to check performance
Write-Host "Running performance test (10 health checks)..." -ForegroundColor Yellow

$times = @()
for ($i = 1; $i -le 10; $i++) {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Invoke-RestMethod -Uri "$baseUrl/health" -Method Get -TimeoutSec 5 | Out-Null
        $stopwatch.Stop()
        $times += $stopwatch.ElapsedMilliseconds
        Write-Host "  Request $i : $($stopwatch.ElapsedMilliseconds) ms" -ForegroundColor Gray
    }
    catch {
        Write-Host "  Request $i : FAILED" -ForegroundColor Red
    }
}

if ($times.Count -gt 0) {
    $avgTime = ($times | Measure-Object -Average).Average
    $minTime = ($times | Measure-Object -Minimum).Minimum
    $maxTime = ($times | Measure-Object -Maximum).Maximum
    
    Write-Host "`n  Performance Summary:" -ForegroundColor Cyan
    Write-Host "    Average: $([math]::Round($avgTime, 2)) ms" -ForegroundColor Gray
    Write-Host "    Min: $minTime ms" -ForegroundColor Gray
    Write-Host "    Max: $maxTime ms" -ForegroundColor Gray
    
    if ($avgTime -lt 1000) {
        Write-Host "  ✓ Performance: Excellent (< 1s average)" -ForegroundColor Green
    } elseif ($avgTime -lt 3000) {
        Write-Host "  ✓ Performance: Good (< 3s average)" -ForegroundColor Yellow
    } else {
        Write-Host "  ⚠ Performance: Slow (> 3s average)" -ForegroundColor Red
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Phase 6: CloudWatch Logs Check" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Checking CloudWatch log groups..." -ForegroundColor Yellow

$logGroups = @("/ecs/ca-a2a-orchestrator", "/ecs/ca-a2a-extractor", "/ecs/ca-a2a-validator", "/ecs/ca-a2a-archivist")

foreach ($logGroup in $logGroups) {
    try {
        $streams = aws logs describe-log-streams --log-group-name $logGroup --max-items 1 --order-by LastEventTime --descending --query 'logStreams[0].logStreamName' --output text 2>&1
        
        if ($LASTEXITCODE -eq 0 -and $streams -notlike "*error*") {
            Write-Host "  ✓ $logGroup : Active" -ForegroundColor Green
        } else {
            Write-Host "  ✗ $logGroup : Not found" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  ? $logGroup : Unknown" -ForegroundColor Yellow
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$totalTests = 8
$passedTests = @($test1, $test2, $test3, $test4, $test5, $test6, $test7, $test8) | Where-Object { $_.Success } | Measure-Object | Select-Object -ExpandProperty Count

Write-Host "Tests Passed: $passedTests / $totalTests" -ForegroundColor $(if ($passedTests -eq $totalTests) { "Green" } elseif ($passedTests -ge $totalTests * 0.7) { "Yellow" } else { "Red" })

if ($passedTests -eq $totalTests) {
    Write-Host "`n✓ All tests passed! Deployment is working correctly." -ForegroundColor Green
} elseif ($passedTests -ge $totalTests * 0.7) {
    Write-Host "`n⚠ Most tests passed, but some issues detected. Review failures above." -ForegroundColor Yellow
} else {
    Write-Host "`n✗ Multiple test failures. Deployment may have issues." -ForegroundColor Red
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Additional Commands" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "View orchestrator logs:" -ForegroundColor Gray
Write-Host "  aws logs tail /ecs/ca-a2a-orchestrator --follow`n" -ForegroundColor Gray

Write-Host "View all ECS tasks:" -ForegroundColor Gray
Write-Host "  aws ecs list-tasks --cluster ca-a2a-cluster`n" -ForegroundColor Gray

Write-Host "View CloudWatch metrics:" -ForegroundColor Gray
Write-Host "  aws cloudwatch get-metric-statistics --namespace AWS/ECS --metric-name CPUUtilization ...`n" -ForegroundColor Gray

Write-Host "Connect to database:" -ForegroundColor Gray
Write-Host "  psql -h <rds-endpoint> -U postgres -d documents_db`n" -ForegroundColor Gray

Write-Host "`nTesting complete!`n" -ForegroundColor Cyan
