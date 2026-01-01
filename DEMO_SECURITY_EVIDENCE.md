# Demo + Security Evidence (CA-A2A)

This document is a **copy/paste friendly** demo script with **real outputs captured** from the current AWS deployment, plus a mapping to the **security notions/concepts** implemented and tested.

### Environment / endpoint

- **AWS account**: `555043101106` (SSO role `AWSAdministratorAccess`)
- **Region**: `eu-west-3`
- **ALB**: `http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com`
- **Client API key**: stored in `security-deploy-summary.json` (`client_api_key`)

### Core security configuration (app-level)

- **Auth required**: `A2A_REQUIRE_AUTH=true`
- **Auth method**: external client uses **`X-API-Key`**
- **RBAC**: method allow-list for `external_client` (see env `A2A_RBAC_POLICY_JSON` in task definition)
- **Rate limiting**: enabled, tested on ALB path `/message`
- **Payload size limit**: enabled (aiohttp `client_max_size`)

---

## 1) Health and capabilities (no auth)

### Health

Command:

```bash
curl -s "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health"
```

Observed:
- **HTTP 200**
- Body contains `"status": "healthy"`

### Agent card

Command:

```bash
curl -s "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/card"
```

Observed:
- **HTTP 200**
- Orchestrator exposes JSON-RPC methods: `process_document`, `get_task_status`, `list_pending_documents`, `discover_agents`, `get_agent_registry`…

#### Concepts shown
- **Health endpoints** (liveness)
- **Agent Card / capability discovery** (A2A metadata)

---

## 2) DB schema initialization (required for a smooth demo)

We initialize PostgreSQL tables using an **ECS one-off task** (same image, VPC, subnets, SG, and Secrets as the orchestrator).

Observed:
- Init task exit code **0** (success)
- Check task exit code **0** (schema present)

#### Concepts shown
- **One-off ECS tasks** for migrations / schema init
- **RDS connectivity** from private subnets

---

## 3) Security tests on `/message`

### 3.1 AuthN: missing API key → 401 Unauthorized

Command (file-based JSON):

```bash
curl -s -H "Content-Type: application/json" \
  -X POST "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message" \
  --data-binary "@scripts/request_list_pending_limit5.json"
```

Observed:
- **HTTP 401**
- JSON-RPC error code `-32010` ("Unauthorized")

### 3.2 AuthZ/RBAC: forbidden method → 403 Forbidden

Command:

```bash
curl -s -H "Content-Type: application/json" \
  -H "X-API-Key: <client_api_key>" \
  -X POST "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message" \
  --data-binary "@scripts/request_rbac_forbidden.json"
```

Observed:
- **HTTP 403**
- JSON-RPC error code `-32011` ("Forbidden")

### 3.3 Rate limiting (burst) → mix of 200 and 403

Observed (20 calls):
- `200: 6`
- `403: 14`

### 3.4 Payload abuse protection → 413 Payload Too Large

Command (creates 2MB JSON payload and posts it):

```powershell
$ALB='ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com'
$API_KEY=(Get-Content .\\security-deploy-summary.json | ConvertFrom-Json).client_api_key
$pad='a' * 2000000
$payload = '{\"jsonrpc\":\"2.0\",\"method\":\"list_pending_documents\",\"params\":{\"limit\":5,\"pad\":\"' + $pad + '\"},\"id\":\"big\"}'
[System.IO.File]::WriteAllText('scripts/request_big_payload.json',$payload,[System.Text.UTF8Encoding]::new($false))
curl.exe -s -o NUL -w \"status=%{http_code}`n\" -H \"Content-Type: application/json\" -H \"X-API-Key: $API_KEY\" -X POST \"http://$ALB/message\" --data-binary \"@scripts/request_big_payload.json\"
```

Observed:
- **HTTP 413**

#### Concepts shown
- **Authentication** (API key)
- **Authorization** (RBAC allow-list)
- **Rate limiting** (abuse resistance)
- **Request size limit** (DoS protection)

---

## 4) Service discovery fix (required for A2A calls)

### Problem observed

The pipeline initially failed with:
- `Cannot connect to host extractor.a2a:8002 ... [Name or service not known]`

Root cause:
- Cloud Map services were registered under the **`local`** namespace, while orchestrator env used `extractor.a2a`, `validator.a2a`, `archivist.a2a`.

### Fix applied

We registered a new orchestrator task definition revision to use:
- `extractor.local`, `validator.local`, `archivist.local`

Observed:
- `discover_agents` returned **3 agents**
- Registry shows **17 skills**

#### Concepts shown
- **Private DNS service discovery (AWS Cloud Map)**
- **Correct dependency wiring via task definition environment**

---

## 5) End-to-end demo (CSV pipeline)

### 5.1 Upload demo document to the bucket used by tasks

- Bucket used by tasks: `ca-a2a-documents-555043101106`
- Upload key: `incoming/invoice_demo_20260101.csv`

### 5.2 Run `process_document` and poll `get_task_status`

Command:

```bash
curl -s -H "Content-Type: application/json" \
  -H "X-API-Key: <client_api_key>" \
  -X POST "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message" \
  --data-binary "@scripts/request_process_document_invoice_csv.json"
```

Observed:
- **HTTP 200**
- Returned a `task_id`
- `get_task_status` reached **status `completed`**
- The final result includes:
  - `extraction.status = completed` with `document_type = csv`
  - `validation.status = completed` with `score = 94.0`
  - `archiving.status = completed` with `document_id = 1`

### 5.3 JSON/JSONB safety fix (NaN)

We hit an initial archiving error:
- `Token "NaN" is invalid.`

Fix applied:
- Extractor sanitizes JSON payloads (replaces NaN/Inf with `null`) before sending to other agents / DB.

#### Concepts shown
- **A2A orchestration**: Orchestrator → Extractor → Validator → Archivist
- **Async processing**: `task_id` + polling `get_task_status`
- **Persistence**: `document_id` returned from archiving stage
- **Data validation**: rule-based scoring
- **Secure serialization**: JSON/JSONB compatible payloads (no NaN)

---

## 6) Local automated tests (security module)

Command:

```bash
pytest -q
```

Observed:
- `11 passed`

What is covered:
- Auth disabled mode (dev)
- API key authentication + RBAC
- Missing auth rejected
- JWT happy path + replay protection
- JWT body-hash binding (tamper detection)
- Rate limiting behavior
- BaseAgent endpoint security behaviors

---

## Notes about mTLS / Service Connect

Current ECS services show **Service Connect not enabled** (`serviceConnectConfiguration: null`).

That means:
- **Network encryption between services is not currently enforced by Service Connect mTLS**
- We rely on **private subnets + SG segmentation + Cloud Map DNS** for network isolation, and on **app-layer auth** for identity/authorization.

