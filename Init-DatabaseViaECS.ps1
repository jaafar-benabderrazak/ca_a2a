# Database Initialization via ECS - PowerShell Script
# This script runs a one-time ECS task that initializes the database schema

param(
    [string]$Region = "eu-west-3",
    [string]$Cluster = "ca-a2a-cluster",
    [string]$Profile = "AWSAdministratorAccess-555043101106"
)

$ErrorActionPreference = "Stop"
$env:AWS_PROFILE = $Profile

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "   Database Initialization via ECS Task" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Cyan

# Python command to run in the container
$pythonCommand = @"
import asyncio
import sys
from mcp_protocol import PostgreSQLResource

async def init():
    print('='*60)
    print('DATABASE SCHEMA INITIALIZATION')
    print('='*60)
    db = PostgreSQLResource()
    try:
        print('\n[1/5] Connecting to PostgreSQL...')
        await db.connect()
        print('[OK] Connected!')
        
        print('\n[2/5] Creating schema...')
        await db.initialize_schema()
        print('[OK] Schema created!')
        
        print('\n[3/5] Verifying tables...')
        tables = await db.fetch_all('''
            SELECT table_name FROM information_schema.tables 
            WHERE table_schema = 'public' ORDER BY table_name
        ''')
        print(f'[OK] Found {len(tables)} tables:')
        for t in tables:
            table_name = t['table_name']
            print(f'     - {table_name}')
        
        print('\n[4/5] Counting rows...')
        doc_count = await db.fetch_value('SELECT COUNT(*) FROM documents')
        log_count = await db.fetch_value('SELECT COUNT(*) FROM processing_logs')
        print(f'[OK] documents: {doc_count} rows')
        print(f'[OK] processing_logs: {log_count} rows')
        
        print('\n[5/5] Disconnecting...')
        await db.disconnect()
        print('[OK] Disconnected')
        
        print('\n' + '='*60)
        print('SUCCESS! Database schema initialized')
        print('='*60)
    except Exception as e:
        print(f'\n[ERROR] {e}')
        import traceback
        traceback.print_exc()
        sys.exit(1)

asyncio.run(init())
"@

Write-Host "`n[1/4] Getting network configuration from running task..." -ForegroundColor Yellow

# Get network config from orchestrator service
$tasks = aws ecs list-tasks `
    --cluster $Cluster `
    --service-name orchestrator `
    --region $Region `
    --desired-status RUNNING `
    --output json | ConvertFrom-Json

if ($tasks.taskArns.Count -eq 0) {
    Write-Host "[ERROR] No running orchestrator tasks found!" -ForegroundColor Red
    Write-Host "Please start the orchestrator service first." -ForegroundColor Yellow
    exit 1
}

$taskArn = $tasks.taskArns[0]
Write-Host "  Using task: $($taskArn.Split('/')[-1])" -ForegroundColor White

# Get task details
$taskDetails = aws ecs describe-tasks `
    --cluster $Cluster `
    --tasks $taskArn `
    --region $Region `
    --output json | ConvertFrom-Json

$task = $taskDetails.tasks[0]
$taskDefArn = $task.taskDefinitionArn
$launchType = $task.launchType

# Get network configuration
$subnets = @()
$securityGroups = @()

foreach ($attachment in $task.attachments) {
    if ($attachment.type -eq "ElasticNetworkInterface") {
        foreach ($detail in $attachment.details) {
            if ($detail.name -eq "subnetId") {
                $subnets += $detail.value
            }
            if ($detail.name -eq "networkInterfaceId") {
                # Get security groups from ENI
                $eniId = $detail.value
                $eniDetails = aws ec2 describe-network-interfaces `
                    --network-interface-ids $eniId `
                    --region $Region `
                    --output json | ConvertFrom-Json
                
                foreach ($sg in $eniDetails.NetworkInterfaces[0].Groups) {
                    $securityGroups += $sg.GroupId
                }
            }
        }
    }
}

Write-Host "  Subnets: $($subnets -join ', ')" -ForegroundColor White
Write-Host "  Security Groups: $($securityGroups -join ', ')" -ForegroundColor White
Write-Host "  Task Definition: $($taskDefArn.Split('/')[-1])" -ForegroundColor White

Write-Host "`n[2/4] Creating task override configuration..." -ForegroundColor Yellow

# Create command override
$command = "python3", "-c", $pythonCommand

# Create overrides JSON
$overrides = @{
    containerOverrides = @(
        @{
            name = "orchestrator"
            command = $command
        }
    )
} | ConvertTo-Json -Depth 10 -Compress

# Create network configuration JSON
$networkConfiguration = @{
    awsvpcConfiguration = @{
        subnets = $subnets
        securityGroups = $securityGroups
        assignPublicIp = "DISABLED"
    }
} | ConvertTo-Json -Depth 10 -Compress

Write-Host "  [OK] Configuration prepared" -ForegroundColor Green

Write-Host "`n[3/4] Running one-time task..." -ForegroundColor Yellow
Write-Host "  This will:" -ForegroundColor White
Write-Host "    1. Start a new container with the orchestrator image" -ForegroundColor DarkGray
Write-Host "    2. Run the database initialization script" -ForegroundColor DarkGray
Write-Host "    3. Exit when complete" -ForegroundColor DarkGray
Write-Host "`n  Starting task..." -ForegroundColor Cyan

# Save configurations to files for AWS CLI
$overridesFile = "task-overrides.json"
$networkFile = "network-config.json"
[System.IO.File]::WriteAllText($overridesFile, $overrides, [System.Text.UTF8Encoding]($false))
[System.IO.File]::WriteAllText($networkFile, $networkConfiguration, [System.Text.UTF8Encoding]($false))

try {
    $result = aws ecs run-task `
        --cluster $Cluster `
        --task-definition $taskDefArn `
        --launch-type FARGATE `
        --network-configuration "file://$networkFile" `
        --overrides "file://$overridesFile" `
        --region $Region `
        --output json | ConvertFrom-Json
    
    if ($result.failures.Count -gt 0) {
        Write-Host "`n[ERROR] Task failed to start:" -ForegroundColor Red
        $result.failures | ForEach-Object {
            Write-Host "  - $($_.reason): $($_.detail)" -ForegroundColor Red
        }
        exit 1
    }
    
    $newTaskArn = $result.tasks[0].taskArn
    $newTaskId = $newTaskArn.Split('/')[-1]
    
    Write-Host "  [OK] Task started: $newTaskId" -ForegroundColor Green
    
    Write-Host "`n[4/4] Waiting for task to complete..." -ForegroundColor Yellow
    Write-Host "  Checking status every 10 seconds..." -ForegroundColor DarkGray
    
    $maxWait = 180  # 3 minutes
    $elapsed = 0
    $lastStatus = ""
    
    while ($elapsed -lt $maxWait) {
        Start-Sleep -Seconds 10
        $elapsed += 10
        
        $taskStatus = aws ecs describe-tasks `
            --cluster $Cluster `
            --tasks $newTaskArn `
            --region $Region `
            --output json | ConvertFrom-Json
        
        $currentStatus = $taskStatus.tasks[0].lastStatus
        
        if ($currentStatus -ne $lastStatus) {
            Write-Host "  Status: $currentStatus ($elapsed seconds)" -ForegroundColor Cyan
            $lastStatus = $currentStatus
        }
        
        if ($currentStatus -eq "STOPPED") {
            $exitCode = $taskStatus.tasks[0].containers[0].exitCode
            $stopReason = $taskStatus.tasks[0].stoppedReason
            
            Write-Host "`n  Task completed!" -ForegroundColor Green
            Write-Host "  Exit code: $exitCode" -ForegroundColor $(if($exitCode -eq 0){"Green"}else{"Red"})
            
            if ($exitCode -eq 0) {
                Write-Host "`n  [SUCCESS] Database schema initialized!" -ForegroundColor Green
                Write-Host "`n  To view the task logs:" -ForegroundColor Yellow
                Write-Host "    aws logs tail /ecs/ca-a2a-orchestrator --follow --region $Region" -ForegroundColor Gray
            } else {
                Write-Host "`n  [ERROR] Task failed: $stopReason" -ForegroundColor Red
                Write-Host "`n  Check logs for details:" -ForegroundColor Yellow
                Write-Host "    aws logs tail /ecs/ca-a2a-orchestrator --follow --region $Region" -ForegroundColor Gray
            }
            
            break
        }
    }
    
    if ($elapsed -ge $maxWait) {
        Write-Host "`n  [TIMEOUT] Task did not complete within $maxWait seconds" -ForegroundColor Yellow
        Write-Host "  Task is still running. Check CloudWatch logs for progress." -ForegroundColor White
    }
    
} finally {
    # Cleanup temp files
    Remove-Item -Path $overridesFile -ErrorAction SilentlyContinue
    Remove-Item -Path $networkFile -ErrorAction SilentlyContinue
}

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "   Complete!" -ForegroundColor Green
Write-Host "============================================`n" -ForegroundColor Cyan

