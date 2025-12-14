# Quick test script for CA A2A agents
Write-Host "🧪 Testing CA A2A Multi-Agent System..." -ForegroundColor Cyan

# Test 1: Health checks
Write-Host "`n1️⃣ Testing Health Checks..." -ForegroundColor Yellow
@(8001, 8002, 8003, 8004) | ForEach-Object {
    $port = $_
    $health = Invoke-WebRequest "http://localhost:$port/health" -UseBasicParsing
    $status = ($health.Content | ConvertFrom-Json).status
    Write-Host "  Port $port : $status" -ForegroundColor $(if($status -eq "healthy"){"Green"}else{"Red"})
}

# Test 2: Agent Discovery
Write-Host "`n2️⃣ Testing Agent Discovery..." -ForegroundColor Yellow
$body = @{jsonrpc="2.0";id=1;method="get_agent_registry";params=@{}} | ConvertTo-Json
$registry = Invoke-WebRequest -Uri http://localhost:8001/message -Method Post -Body $body -ContentType "application/json" -UseBasicParsing
$agents = ($registry.Content | ConvertFrom-Json).result.agents
Write-Host "  Discovered: $($agents.Count) agents" -ForegroundColor Green

# Test 3: Correlation ID
Write-Host "`n3️⃣ Testing Correlation IDs..." -ForegroundColor Yellow
$headers = @{"X-Correlation-ID"="test-123";"Content-Type"="application/json"}
$body = @{jsonrpc="2.0";id=1;method="list_supported_formats";params=@{}} | ConvertTo-Json
$response = Invoke-WebRequest -Uri http://localhost:8002/message -Method Post -Body $body -Headers $headers -UseBasicParsing
$correlationId = ($response.Content | ConvertFrom-Json)._meta.correlation_id
Write-Host "  Correlation ID: $correlationId" -ForegroundColor Green

# Test 4: Performance Metrics
Write-Host "`n4️⃣ Testing Performance Monitoring..." -ForegroundColor Yellow
$status = Invoke-WebRequest http://localhost:8002/status -UseBasicParsing
$metrics = ($status.Content | ConvertFrom-Json).performance
Write-Host "  Total requests tracked: $($metrics.total_requests)" -ForegroundColor Green

Write-Host "`n✅ All tests completed!" -ForegroundColor Cyan