# Update Agent Services with MCP Server URL
# This script updates ECS task definitions to use the MCP server

param(
    [string]$Profile = "AWSAdministratorAccess-555043101106",
    [string]$Region = "eu-west-3",
    [string]$MCPServerURL = "http://mcp-server.ca-a2a.local:8000"
)

$ErrorActionPreference = "Stop"

# Configuration
$ACCOUNT_ID = "555043101106"
$CLUSTER_NAME = "ca-a2a-cluster"
$SERVICES = @("orchestrator", "extractor", "archivist")

# Set AWS profile
$env:AWS_PROFILE = $Profile
$env:AWS_DEFAULT_REGION = $Region

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  UPDATE AGENT SERVICES WITH MCP SERVER" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "MCP Server URL: $MCPServerURL" -ForegroundColor Yellow
Write-Host ""

foreach ($serviceName in $SERVICES) {
    Write-Host "[*] Updating service: $serviceName" -ForegroundColor Cyan
    
    # Get current task definition
    $service = aws ecs describe-services --cluster $CLUSTER_NAME --services $serviceName | ConvertFrom-Json
    $taskDefArn = $service.services[0].taskDefinition
    
    Write-Host "  Current task definition: $taskDefArn" -ForegroundColor Gray
    
    # Get task definition details
    $taskDef = aws ecs describe-task-definition --task-definition $taskDefArn | ConvertFrom-Json
    $containerDef = $taskDef.taskDefinition.containerDefinitions[0]
    
    # Add MCP_SERVER_URL to environment variables
    $envVars = $containerDef.environment
    $mcpEnvExists = $envVars | Where-Object { $_.name -eq "MCP_SERVER_URL" }
    
    if (-not $mcpEnvExists) {
        Write-Host "  Adding MCP_SERVER_URL environment variable" -ForegroundColor Yellow
        $envVars += @{name = "MCP_SERVER_URL"; value = $MCPServerURL}
    } else {
        Write-Host "  Updating MCP_SERVER_URL environment variable" -ForegroundColor Yellow
        ($envVars | Where-Object { $_.name -eq "MCP_SERVER_URL" }).value = $MCPServerURL
    }
    
    # Build new task definition JSON
    $newTaskDef = @{
        family = $taskDef.taskDefinition.family
        networkMode = $taskDef.taskDefinition.networkMode
        requiresCompatibilities = $taskDef.taskDefinition.requiresCompatibilities
        cpu = $taskDef.taskDefinition.cpu
        memory = $taskDef.taskDefinition.memory
        executionRoleArn = $taskDef.taskDefinition.executionRoleArn
        containerDefinitions = @(
            @{
                name = $containerDef.name
                image = $containerDef.image
                essential = $containerDef.essential
                portMappings = $containerDef.portMappings
                environment = $envVars
                secrets = $containerDef.secrets
                logConfiguration = $containerDef.logConfiguration
            }
        )
    }
    
    # Register new task definition
    $newTaskDefJson = $newTaskDef | ConvertTo-Json -Depth 10
    $newTaskDefJson | Out-File -FilePath "${serviceName}-taskdef.json" -Encoding ASCII
    
    $registeredTaskDef = aws ecs register-task-definition --cli-input-json file://${serviceName}-taskdef.json | ConvertFrom-Json
    
    if ($LASTEXITCODE -eq 0) {
        $newTaskDefArn = $registeredTaskDef.taskDefinition.taskDefinitionArn
        Write-Host "  [OK] New task definition registered: $newTaskDefArn" -ForegroundColor Green
        
        # Update service
        Write-Host "  Updating service with new task definition..." -ForegroundColor Yellow
        aws ecs update-service `
            --cluster $CLUSTER_NAME `
            --service $serviceName `
            --task-definition $newTaskDefArn `
            --force-new-deployment
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] Service updated successfully" -ForegroundColor Green
        } else {
            Write-Host "  [ERROR] Failed to update service" -ForegroundColor Red
        }
    } else {
        Write-Host "  [ERROR] Failed to register task definition" -ForegroundColor Red
    }
    
    # Clean up temp file
    Remove-Item "${serviceName}-taskdef.json" -ErrorAction SilentlyContinue
    
    Write-Host ""
}

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  UPDATE COMPLETE" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "All agent services have been updated to use MCP server." -ForegroundColor Green
Write-Host "Deployments are in progress. Monitor with:" -ForegroundColor Yellow
Write-Host "  aws ecs describe-services --cluster $CLUSTER_NAME --services orchestrator extractor archivist" -ForegroundColor Cyan
Write-Host ""

