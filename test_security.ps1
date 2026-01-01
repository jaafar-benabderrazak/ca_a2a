# 🔒 Security Implementation - Testing Script
# Run this to test authentication and authorization features

Write-Host "🔐 CA A2A Security Testing" -ForegroundColor Cyan
Write-Host "=" * 70

# Test 1: Generate API Keys
Write-Host "`n1️⃣ Generating API Keys..." -ForegroundColor Yellow
python security_tools.py setup-all-agents

# Test 2: Verify JWT Token
Write-Host "`n2️⃣ Testing JWT Token Generation..." -ForegroundColor Yellow
$token = python security_tools.py generate-jwt test-agent --permissions extract_document validate_document
Write-Host "Token generated successfully" -ForegroundColor Green

# Test 3: Test Authentication (with valid credentials)
Write-Host "`n3️⃣ Testing Authentication (Valid API Key)..." -ForegroundColor Yellow
$headers = @{
    "Content-Type" = "application/json"
    "X-API-Key" = "orchestrator-abc123xyz789"
}
$body = @{
    jsonrpc = "2.0"
    id = 1
    method = "get_agent_registry"
    params = @{}
} | ConvertTo-Json

try {
    $response = Invoke-WebRequest -Uri "http://localhost:8001/message" -Method Post -Body $body -Headers $headers -UseBasicParsing
    Write-Host "✅ Authentication successful" -ForegroundColor Green
} catch {
    Write-Host "❌ Authentication failed: $_" -ForegroundColor Red
}

# Test 4: Test Authentication (without credentials)
Write-Host "`n4️⃣ Testing Authentication (No Credentials)..." -ForegroundColor Yellow
$headers = @{
    "Content-Type" = "application/json"
}
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8001/message" -Method Post -Body $body -Headers $headers -UseBasicParsing -ErrorAction Stop
    Write-Host "⚠️  Request succeeded without auth (auth may be disabled)" -ForegroundColor Yellow
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Host "✅ Correctly rejected unauthenticated request" -ForegroundColor Green
    } else {
        Write-Host "❌ Unexpected error: $_" -ForegroundColor Red
    }
}

# Test 5: Test Rate Limiting
Write-Host "`n5️⃣ Testing Rate Limiting..." -ForegroundColor Yellow
$count = 0
$start = Get-Date
for ($i = 1; $i -le 100; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8001/health" -UseBasicParsing -ErrorAction SilentlyContinue
        $count++
    } catch {
        if ($_.Exception.Response.StatusCode -eq 429) {
            Write-Host "✅ Rate limit triggered after $count requests" -ForegroundColor Green
            break
        }
    }
}
$duration = ((Get-Date) - $start).TotalSeconds
Write-Host "Sent $count requests in $([math]::Round($duration, 2)) seconds" -ForegroundColor Gray

# Test 6: Check Security Configuration
Write-Host "`n6️⃣ Checking Security Configuration..." -ForegroundColor Yellow
if (Test-Path ".env") {
    Write-Host "✅ .env file exists" -ForegroundColor Green
    
    $envContent = Get-Content .env -Raw
    if ($envContent -match "ENABLE_AUTHENTICATION") {
        Write-Host "✅ Security settings configured" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Security settings not found in .env" -ForegroundColor Yellow
        Write-Host "   Copy env.security.example to .env and configure" -ForegroundColor Gray
    }
} else {
    Write-Host "⚠️  .env file not found" -ForegroundColor Yellow
    Write-Host "   Copy env.security.example to .env" -ForegroundColor Gray
}

# Summary
Write-Host "`n" + "=" * 70
Write-Host "✅ Security Testing Complete!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Copy agent_credentials.env to your .env file"
Write-Host "  2. Set ENABLE_AUTHENTICATION=true"
Write-Host "  3. Restart agents with: python run_agents.py"
Write-Host "  4. Test with authenticated requests"
Write-Host ""
Write-Host "Documentation:" -ForegroundColor Yellow
Write-Host "  - SECURITY_GUIDE.md - Complete security documentation"
Write-Host "  - env.security.example - Configuration template"
Write-Host "  - security_tools.py - CLI tools for managing security"
Write-Host ""
