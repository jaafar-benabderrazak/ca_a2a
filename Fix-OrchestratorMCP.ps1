# Fix Orchestrator MCP Configuration
# This script updates the orchestrator task definition to use HTTP MCP client

param(
    [string]$Profile = "AWSAdministratorAccess-555043101106",
    [string]$Region = "eu-west-3"
)

$env:AWS_PROFILE = $Profile
$env:AWS_DEFAULT_REGION = $Region

Write-Host "[INFO] Fixing Orchestrator MCP Configuration..." -ForegroundColor Cyan

# Get current task definition
Write-Host "[INFO] Retrieving current orchestrator task definition..."
$currentTaskDef = aws ecs describe-task-definition --task-definition ca-a2a-orchestrator:9 --query 'taskDefinition' --output json | ConvertFrom-Json

# Get MCP server tasks to find their IP
Write-Host "[INFO] Finding MCP server endpoint..."
$mcpTasks = aws ecs list-tasks --cluster ca-a2a-cluster --service-name mcp-server --query 'taskArns[0]' --output text

if ($mcpTasks) {
    $mcpTaskDetails = aws ecs describe-tasks --cluster ca-a2a-cluster --tasks $mcpTasks --query 'tasks[0].containers[0].networkInterfaces[0].privateIpv4Address' --output text
    if ($mcpTaskDetails -and $mcpTaskDetails -ne "None") {
        $mcpServerUrl = "http://${mcpTaskDetails}:8000"
        Write-Host "[OK] MCP Server found at: $mcpServerUrl" -ForegroundColor Green
    } else {
        # Fallback to service discovery pattern
        $mcpServerUrl = "http://mcp-server.ca-a2a-cluster.local:8000"
        Write-Host "[INFO] Using service discovery URL: $mcpServerUrl" -ForegroundColor Yellow
    }
} else {
    $mcpServerUrl = "http://mcp-server.ca-a2a-cluster.local:8000"
    Write-Host "[INFO] Using default service discovery URL: $mcpServerUrl" -ForegroundColor Yellow
}

# Create new task definition with MCP_SERVER_URL
Write-Host "[INFO] Creating new task definition with MCP_SERVER_URL..."

$container = $currentTaskDef.containerDefinitions[0]

# Check if MCP_SERVER_URL already exists
$existingMcpUrl = $container.environment | Where-Object { $_.name -eq "MCP_SERVER_URL" }

if (-not $existingMcpUrl) {
    # Add MCP_SERVER_URL to environment variables
    $container.environment += @{
        name  = "MCP_SERVER_URL"
        value = $mcpServerUrl
    }
    Write-Host "[OK] Added MCP_SERVER_URL environment variable" -ForegroundColor Green
} else {
    # Update existing
    ($container.environment | Where-Object { $_.name -eq "MCP_SERVER_URL" }).value = $mcpServerUrl
    Write-Host "[OK] Updated MCP_SERVER_URL environment variable" -ForegroundColor Green
}

# Create minimal task definition JSON
$newTaskDef = @{
    family                  = $currentTaskDef.family
    taskRoleArn            = $currentTaskDef.taskRoleArn
    executionRoleArn       = $currentTaskDef.executionRoleArn
    networkMode            = $currentTaskDef.networkMode
    containerDefinitions   = @($container)
    requiresCompatibilities = $currentTaskDef.requiresCompatibilities
    cpu                    = $currentTaskDef.cpu
    memory                 = $currentTaskDef.memory
}

# Save to file
$newTaskDef | ConvertTo-Json -Depth 10 | Out-File -FilePath "orchestrator-taskdef-fixed.json" -Encoding utf8

# Register new task definition
Write-Host "[INFO] Registering new task definition..."
$registerResult = aws ecs register-task-definition --cli-input-json file://orchestrator-taskdef-fixed.json 2>&1

if ($LASTEXITCODE -eq 0) {
    $newRevision = ($registerResult | ConvertFrom-Json).taskDefinition.revision
    Write-Host "[OK] New task definition registered: ca-a2a-orchestrator:$newRevision" -ForegroundColor Green
    
    # Update service to use new task definition
    Write-Host "[INFO] Updating orchestrator service..."
    aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --task-definition "ca-a2a-orchestrator:$newRevision" --force-new-deployment | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Service updated successfully!" -ForegroundColor Green
        Write-Host "[INFO] New tasks will use HTTP MCP client" -ForegroundColor Cyan
        Write-Host "[INFO] Waiting for service to stabilize..." -ForegroundColor Yellow
        
        # Wait for service to stabilize (optional)
        # aws ecs wait services-stable --cluster ca-a2a-cluster --services orchestrator
        
        Write-Host "[SUCCESS] Orchestrator MCP configuration fixed!" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Failed to update service" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[FAIL] Failed to register task definition" -ForegroundColor Red
    Write-Host $registerResult -ForegroundColor Red
    exit 1
}

# Cleanup
Remove-Item "orchestrator-taskdef-fixed.json" -ErrorAction SilentlyContinue

Write-Host "`n[INFO] Monitoring new tasks..." -ForegroundColor Cyan
Write-Host "Run this command to check logs:" -ForegroundColor Yellow
Write-Host "aws logs tail /ecs/ca-a2a-orchestrator --follow | Select-String 'MCP'" -ForegroundColor White

