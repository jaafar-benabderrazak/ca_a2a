# Scenario-based Demo & Testing (Functionality + Security)

This document is a **scenario-based, copy/paste-friendly** test plan to validate:

- **Functionality**: end-to-end document pipeline (S3 → Orchestrator → Agents → PostgreSQL)
- **Security**: AuthN, RBAC, rate limiting, payload limits, and capability visibility

References:

- `DEMO_SECURITY_EVIDENCE.md` (captured outputs / evidence)
- `SECURITY.md` (security design summary)
- `SYSTEM_ARCHITECTURE.md` and `AWS_ARCHITECTURE.md` (architecture + security layers)

---

## Preconditions

- **ALB**: `http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com`
- **API key**: `security-deploy-summary.json` → `client_api_key`
- **S3 bucket**: `ca-a2a-documents-555043101106`
- **Region**: `eu-west-3`

On Windows, prefer **file-based JSON** (`--data-binary "@scripts/<file>.json"`) to avoid escaping issues.

---

## Quick runner (recommended)

Run all scenarios automatically:

```powershell
.\scripts\run_demo_scenarios.ps1
```

---

## Scenario 0 — Smoke test (health)

### Scenario 0 — Steps (PowerShell)

```powershell
$ALB='ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com'
curl.exe -s -w "`nstatus=%{http_code}`n" "http://$ALB/health"
```

### Scenario 0 — Expected

- `status=200`
- body contains `"status": "healthy"`

---

## Scenario 1 — Capability discovery visibility (role-based)

Goal: verify that `/skills` is **RBAC-filtered** (no auth → empty; API key → visible skills).

### Scenario 1 — Steps (PowerShell)

```powershell
$ALB='ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com'
$API_KEY=(Get-Content .\security-deploy-summary.json | ConvertFrom-Json).client_api_key

# anonymous
curl.exe -s -w "`nstatus=%{http_code}`n" "http://$ALB/skills"

# external_client
curl.exe -s -w "`nstatus=%{http_code}`n" -H "X-API-Key: $API_KEY" "http://$ALB/skills"
```

### Scenario 1 — Expected

- anonymous: `status=200` with `total_skills: 0`, `_meta.principal=anonymous`
- external_client: `status=200` with `total_skills > 0`, `_meta.principal=external_client`

---

## Scenario 2 — AuthN (missing API key) → 401

Goal: ensure `/message` is protected by **AuthN**.

### Scenario 2 — Steps (PowerShell)

```powershell
$ALB='ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com'
curl.exe -s -w "`nstatus=%{http_code}`n" `
  -H "Content-Type: application/json" `
  -X POST "http://$ALB/message" `
  --data-binary "@scripts/request_list_pending_limit5.json"
```

### Scenario 2 — Expected

- `status=401`
- JSON-RPC error code `-32010` ("Unauthorized")

---

## Scenario 3 — AuthZ/RBAC (forbidden method) → 403

Goal: ensure a caller cannot invoke non-allowed methods.

### Scenario 3 — Steps (PowerShell)

```powershell
$ALB='ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com'
$API_KEY=(Get-Content .\security-deploy-summary.json | ConvertFrom-Json).client_api_key

curl.exe -s -w "`nstatus=%{http_code}`n" `
  -H "Content-Type: application/json" `
  -H "X-API-Key: $API_KEY" `
  -X POST "http://$ALB/message" `
  --data-binary "@scripts/request_rbac_forbidden.json"
```

### Scenario 3 — Expected

- `status=403`
- JSON-RPC error code `-32011` ("Forbidden")

---

## Scenario 4 — Abuse resistance: rate limiting

Goal: verify burst calls are throttled.

Notes:

- current demo deployment uses a low limit (e.g. `5/min`) to make this visible.
- if you immediately run other scenarios, you may need to **wait 60s** before calling again.

### Scenario 4 — Steps (PowerShell)

```powershell
$ALB='ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com'
$API_KEY=(Get-Content .\security-deploy-summary.json | ConvertFrom-Json).client_api_key

$ok=0; $forb=0
for ($i=0; $i -lt 10; $i++) {
  $code = (curl.exe -s -o NUL -w "%{http_code}" `
    -H "Content-Type: application/json" `
    -H "X-API-Key: $API_KEY" `
    -X POST "http://$ALB/message" `
    --data-binary "@scripts/request_list_pending_limit5.json")
  if ($code -eq '200') { $ok++ } elseif ($code -eq '403') { $forb++ }
}
"200=$ok 403=$forb"
```

### Scenario 4 — Expected

- mix of `200` and `403` (throttling)

---

## Scenario 5 — Abuse resistance: payload size limit → 413

Goal: verify oversized requests are rejected.

### Scenario 5 — Steps (PowerShell)

```powershell
$ALB='ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com'
$API_KEY=(Get-Content .\security-deploy-summary.json | ConvertFrom-Json).client_api_key

$pad='a' * 2000000
$payload = '{\"jsonrpc\":\"2.0\",\"method\":\"list_pending_documents\",\"params\":{\"limit\":5,\"pad\":\"' + $pad + '\"},\"id\":\"big\"}'
[System.IO.File]::WriteAllText('scripts/request_big_payload.json',$payload,[System.Text.UTF8Encoding]::new($false))

curl.exe -s -o NUL -w "status=%{http_code}`n" `
  -H "Content-Type: application/json" `
  -H "X-API-Key: $API_KEY" `
  -X POST "http://$ALB/message" `
  --data-binary "@scripts/request_big_payload.json"
```

### Scenario 5 — Expected

- `status=413`

---

## Scenario 6 — Agent discovery (functional + secured)

Goal: verify orchestrator can discover all 3 internal agents and expose registry (after rate-limit window if needed).

### Scenario 6 — Steps (PowerShell)

```powershell
Start-Sleep -Seconds 65
$ALB='ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com'
$API_KEY=(Get-Content .\security-deploy-summary.json | ConvertFrom-Json).client_api_key

curl.exe -s -w "`nstatus=%{http_code}`n" `
  -H "Content-Type: application/json" `
  -H "X-API-Key: $API_KEY" `
  -X POST "http://$ALB/message" `
  --data-binary "@scripts/request_discover_agents.json"

curl.exe -s -w "`nstatus=%{http_code}`n" `
  -H "Content-Type: application/json" `
  -H "X-API-Key: $API_KEY" `
  -X POST "http://$ALB/message" `
  --data-binary "@scripts/request_get_agent_registry.json"
```

### Scenario 6 — Expected

- `discover_agents`: `status=200` with `discovered_agents=3`
- `get_agent_registry`: `status=200` with `total_agents=3` and `total_skills>=15`

---

## Scenario 7 — End-to-end processing (CSV) + task polling

Goal: verify the pipeline end-to-end and that archiving returns a `document_id`.

### Scenario 7 — Steps (PowerShell)

```powershell
$ALB='ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com'
$API_KEY=(Get-Content .\security-deploy-summary.json | ConvertFrom-Json).client_api_key

# Upload demo CSV
aws s3 cp .\invoice_demo_20260101.csv s3://ca-a2a-documents-555043101106/incoming/invoice_demo_20260101.csv --profile reply-sso --region eu-west-3

# Start pipeline
$resp = curl.exe -s -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -X POST "http://$ALB/message" --data-binary "@scripts/request_process_document_invoice_csv.json"
$resp | Out-Host
$taskId = ($resp | ConvertFrom-Json).result.task_id

# Poll status (creates a runtime request file)
for ($i=0; $i -lt 10; $i++) {
  $payloadObj = @{
    jsonrpc = '2.0'
    method  = 'get_task_status'
    params  = @{ task_id = $taskId }
    id      = 'st'
  }
  $payload = ($payloadObj | ConvertTo-Json -Compress)
  [System.IO.File]::WriteAllText('scripts/request_get_task_status_runtime.json',$payload,[System.Text.UTF8Encoding]::new($false))
  $st = curl.exe -s -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -X POST "http://$ALB/message" --data-binary "@scripts/request_get_task_status_runtime.json"
  $j = $st | ConvertFrom-Json
  if ($j.result.status -eq 'completed' -or $j.result.status -eq 'failed') { $st | Out-Host; break }
  Start-Sleep -Seconds 2
}
```

### Scenario 7 — Expected

- `process_document`: HTTP 200 and `task_id` returned
- `get_task_status`: reaches `status=completed`
- archiving stage includes `document_id` (integer)

---

## Scenario 8 — Verify archiving in PostgreSQL (ECS one-off)

Goal: show the `documents` row exists in DB (proof of persistence).

### Scenario 8 — Steps (PowerShell)

```powershell
$AWS_REGION='eu-west-3'
$CLUSTER='ca-a2a-cluster'
$taskDef = aws ecs describe-services --profile reply-sso --cluster $CLUSTER --services orchestrator --region $AWS_REGION --query 'services[0].taskDefinition' --output text
$subnets = (aws ecs describe-services --profile reply-sso --cluster $CLUSTER --services orchestrator --region $AWS_REGION --query 'services[0].networkConfiguration.awsvpcConfiguration.subnets' --output text).Split()
$sg = aws ecs describe-services --profile reply-sso --cluster $CLUSTER --services orchestrator --region $AWS_REGION --query 'services[0].networkConfiguration.awsvpcConfiguration.securityGroups[0]' --output text
$ov = 'file://c:/Users/j.benabderrazak/OneDrive - Reply/Bureau/work/CA/A2A/ca_a2a/scripts/ecs_overrides_latest_docs.json'

$taskArn = aws ecs run-task --profile reply-sso --region $AWS_REGION --cluster $CLUSTER --launch-type FARGATE --task-definition $taskDef --count 1 `
  --network-configuration "awsvpcConfiguration={subnets=[$($subnets -join ',')],securityGroups=[$sg],assignPublicIp=DISABLED}" `
  --overrides $ov --query 'tasks[0].taskArn' --output text

aws ecs wait tasks-stopped --profile reply-sso --region $AWS_REGION --cluster $CLUSTER --tasks $taskArn
$taskId = $taskArn.Split('/')[-1]
aws logs get-log-events --profile reply-sso --region $AWS_REGION --log-group-name /ecs/ca-a2a-orchestrator --log-stream-name "ecs/orchestrator/$taskId" --limit 50 --query 'events[*].message' --output text
```

### Scenario 8 — Expected

- log shows something like:
  - `id=<n> status=validated score=<score> type=csv s3_key=incoming/invoice_demo_20260101.csv`
