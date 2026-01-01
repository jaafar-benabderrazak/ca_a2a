param(
  [string]$AlbHost = 'ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com',
  [string]$AwsRegion = 'eu-west-3',
  [string]$Cluster = 'ca-a2a-cluster',
  [string]$Bucket = 'ca-a2a-documents-555043101106'
)

$ErrorActionPreference = 'Stop'

function Write-Section([string]$title) {
  Write-Host ""
  Write-Host "=== $title ===" -ForegroundColor Cyan
}

function Assert-Http([string]$code, [string]$expected, [string]$name) {
  if ($code -ne $expected) {
    throw "$name expected HTTP $expected but got $code"
  }
}

$apiKey = (Get-Content .\security-deploy-summary.json | ConvertFrom-Json).client_api_key
if (-not $apiKey) { throw "Missing client_api_key in security-deploy-summary.json" }

Write-Section "S0 Health"
$h = curl.exe -s -w "`n%{http_code}" "http://$AlbHost/health"
$lines = $h -split "`n"
$code = $lines[-1].Trim()
Assert-Http $code '200' 'health'
($lines[0..($lines.Length-2)] -join "`n") | Out-Host

Write-Section "S1 Skills visibility (anonymous vs external_client)"
$sAnon = curl.exe -s -w "`n%{http_code}" "http://$AlbHost/skills"
($sAnon -split "`n")[0] | Out-Host
Assert-Http (($sAnon -split "`n")[-1].Trim()) '200' 'skills(anon)'

$sAuth = curl.exe -s -w "`n%{http_code}" -H "X-API-Key: $apiKey" "http://$AlbHost/skills"
($sAuth -split "`n")[0] | Out-Host
Assert-Http (($sAuth -split "`n")[-1].Trim()) '200' 'skills(api key)'

Write-Section "S2 AuthN on /message (missing API key => 401)"
$m401 = curl.exe -s -w "`n%{http_code}" -H "Content-Type: application/json" -X POST "http://$AlbHost/message" --data-binary "@scripts/request_list_pending_limit5.json"
($m401 -split "`n")[0] | Out-Host
Assert-Http (($m401 -split "`n")[-1].Trim()) '401' 'message missing auth'

Write-Section "S3 RBAC forbidden => 403"
$m403 = curl.exe -s -w "`n%{http_code}" -H "Content-Type: application/json" -H "X-API-Key: $apiKey" -X POST "http://$AlbHost/message" --data-binary "@scripts/request_rbac_forbidden.json"
($m403 -split "`n")[0] | Out-Host
Assert-Http (($m403 -split "`n")[-1].Trim()) '403' 'rbac forbidden'

Write-Section "S4 Rate limit burst (expect some 403 depending on config)"
$ok=0; $forb=0
for ($i=0; $i -lt 10; $i++) {
  $c = (curl.exe -s -o NUL -w "%{http_code}" -H "Content-Type: application/json" -H "X-API-Key: $apiKey" -X POST "http://$AlbHost/message" --data-binary "@scripts/request_list_pending_limit5.json")
  if ($c -eq '200') { $ok++ } elseif ($c -eq '403') { $forb++ }
}
Write-Host "200=$ok 403=$forb"

Write-Section "S5 Payload too large => 413"
$pad = 'a' * 2000000
$payload = '{\"jsonrpc\":\"2.0\",\"method\":\"list_pending_documents\",\"params\":{\"limit\":5,\"pad\":\"' + $pad + '\"},\"id\":\"big\"}'
[System.IO.File]::WriteAllText('scripts/request_big_payload.json',$payload,[System.Text.UTF8Encoding]::new($false))
$pcode = (curl.exe -s -o NUL -w "%{http_code}" -H "Content-Type: application/json" -H "X-API-Key: $apiKey" -X POST "http://$AlbHost/message" --data-binary "@scripts/request_big_payload.json")
Assert-Http $pcode '413' 'payload limit'
Write-Host "status=$pcode"

Write-Section "S6 Discovery (wait for rate-limit window)"
Start-Sleep -Seconds 65
$disc = curl.exe -s -w "`n%{http_code}" -H "Content-Type: application/json" -H "X-API-Key: $apiKey" -X POST "http://$AlbHost/message" --data-binary "@scripts/request_discover_agents.json"
($disc -split "`n")[0] | Out-Host
Assert-Http (($disc -split "`n")[-1].Trim()) '200' 'discover_agents'

$reg = curl.exe -s -w "`n%{http_code}" -H "Content-Type: application/json" -H "X-API-Key: $apiKey" -X POST "http://$AlbHost/message" --data-binary "@scripts/request_get_agent_registry.json"
($reg -split "`n")[0] | Out-Host
Assert-Http (($reg -split "`n")[-1].Trim()) '200' 'get_agent_registry'

Write-Section "S7 End-to-end pipeline (CSV)"
aws s3 cp .\invoice_demo_20260101.csv "s3://$Bucket/incoming/invoice_demo_20260101.csv" --profile reply-sso --region $AwsRegion | Out-Null
$start = curl.exe -s -H "Content-Type: application/json" -H "X-API-Key: $apiKey" -X POST "http://$AlbHost/message" --data-binary "@scripts/request_process_document_invoice_csv.json"
$start | Out-Host
$taskId = ($start | ConvertFrom-Json).result.task_id
if (-not $taskId) { throw "No task_id returned" }

# The demo deployment has a low rate-limit (e.g. 5/min). To avoid flakiness,
# poll slowly and back off when we hit HTTP 403.
Start-Sleep -Seconds 10

$final = $null
for ($i=0; $i -lt 6; $i++) {
  $stObj = @{
    jsonrpc = '2.0'
    method  = 'get_task_status'
    params  = @{ task_id = $taskId }
    id      = 'st'
  }
  $stPayload = ($stObj | ConvertTo-Json -Compress)
  [System.IO.File]::WriteAllText('scripts/request_get_task_status_runtime.json', $stPayload, [System.Text.UTF8Encoding]::new($false))

  $raw = curl.exe -s -w "`n%{http_code}" -H "Content-Type: application/json" -H "X-API-Key: $apiKey" -X POST "http://$AlbHost/message" --data-binary "@scripts/request_get_task_status_runtime.json"
  $parts = $raw -split "`n"
  $http = $parts[-1].Trim()
  $body = ($parts[0..($parts.Length-2)] -join "`n")

  if ($http -eq '403') {
    Write-Host "[$i] status=rate_limited (HTTP 403) -> waiting 65s"
    Start-Sleep -Seconds 65
    continue
  }
  if ($http -ne '200') {
    throw "get_task_status unexpected HTTP ${http}: $body"
  }

  $j = $body | ConvertFrom-Json
  $status = $j.result.status
  Write-Host "[$i] status=$status"

  if ($status -eq 'completed' -or $status -eq 'failed') {
    $final = $body
    $final | Out-Host
    break
  }

  Start-Sleep -Seconds 5
}

if (-not $final) { throw "Pipeline did not reach a terminal state in time" }

Write-Section "S8 DB verification (ECS one-off init_db latest)"
$taskDef = aws ecs describe-services --profile reply-sso --cluster $Cluster --services orchestrator --region $AwsRegion --query 'services[0].taskDefinition' --output text
$subnets = (aws ecs describe-services --profile reply-sso --cluster $Cluster --services orchestrator --region $AwsRegion --query 'services[0].networkConfiguration.awsvpcConfiguration.subnets' --output text).Split()
$sg = aws ecs describe-services --profile reply-sso --cluster $Cluster --services orchestrator --region $AwsRegion --query 'services[0].networkConfiguration.awsvpcConfiguration.securityGroups[0]' --output text
$ov = 'file://c:/Users/j.benabderrazak/OneDrive - Reply/Bureau/work/CA/A2A/ca_a2a/scripts/ecs_overrides_latest_docs.json'
$taskArn = aws ecs run-task --profile reply-sso --region $AwsRegion --cluster $Cluster --launch-type FARGATE --task-definition $taskDef --count 1 `
  --network-configuration "awsvpcConfiguration={subnets=[$($subnets -join ',')],securityGroups=[$sg],assignPublicIp=DISABLED}" `
  --overrides $ov --query 'tasks[0].taskArn' --output text
$taskId2 = $taskArn.Split('/')[-1]
aws ecs wait tasks-stopped --profile reply-sso --region $AwsRegion --cluster $Cluster --tasks $taskArn | Out-Null
Write-Host "taskArn=$taskArn"
aws logs get-log-events --profile reply-sso --region $AwsRegion --log-group-name /ecs/ca-a2a-orchestrator --log-stream-name "ecs/orchestrator/$taskId2" --limit 50 --query 'events[*].message' --output text

Write-Host ""
Write-Host "ALL SCENARIOS COMPLETED" -ForegroundColor Green

