# 🚀 DEPLOYMENT READY - Run This Manually

## ⚠️ Important: Run in Interactive PowerShell

The deployment script requires AWS credentials and must be run in an **interactive PowerShell window**.

---

## 🎯 Quick Deploy (Recommended)

### Open PowerShell and run:

```powershell
cd C:\Users\Utilisateur\Desktop\projects\ca_a2a
.\Rebuild-All-Agents-NoPrompt.ps1
```

**Time:** ~10-15 minutes
- Build: 3-5 minutes
- Push: 2-3 minutes  
- Deploy: 3-4 minutes
- Verify: 1-2 minutes

---

## 📋 What the Script Does

### Step 1: ECR Login
Authenticates with AWS ECR to push Docker images

### Step 2: Build Images (Python 3.11)
Builds all 4 agent images:
- ✅ orchestrator (with upload handler)
- ✅ extractor
- ✅ validator
- ✅ archivist

**Key fixes applied:**
- Python 3.11 (required for `mcp>=0.9.0`)
- Fixed MCP SDK imports (conditional + API check)
- Graceful fallback for missing/incompatible SDK

### Step 3: Push to ECR
Pushes all images to:
`555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/<agent>:latest`

### Step 4: Update ECS Services
Forces new deployment for all services to pull latest images

### Step 5: Wait & Verify
- Waits for deployments to complete (4 minutes max)
- Tests orchestrator health endpoint
- Tests upload endpoint
- Shows deployment status

---

## ✅ Expected Results

### During Execution

```
==========================================
Rebuild and Redeploy ALL Agents
==========================================

Step 1/4: Login to ECR
  [OK] ECR login successful

Step 2/4: Build Docker Images
Building orchestrator...
  [OK] Built orchestrator in 45.2s
Building extractor...
  [OK] Built extractor in 42.8s
Building validator...
  [OK] Built validator in 41.3s
Building archivist...
  [OK] Built archivist in 40.9s

Build Summary:
  [OK] orchestrator
  [OK] extractor
  [OK] validator
  [OK] archivist

Step 3/4: Push Images to ECR
Pushing orchestrator...
  [OK] Pushed orchestrator
Pushing extractor...
  [OK] Pushed extractor
Pushing validator...
  [OK] Pushed validator
Pushing archivist...
  [OK] Pushed archivist

Step 4/4: Update ECS Services
Updating orchestrator service...
  [OK] Update initiated for orchestrator
Updating extractor service...
  [OK] Update initiated for extractor
Updating validator service...
  [OK] Update initiated for validator
Updating archivist service...
  [OK] Update initiated for archivist

Waiting for Deployments
  [15%] Elapsed: 36s / 240s
  [30%] Elapsed: 72s / 240s
  [45%] Elapsed: 108s / 240s
  [OK] All deployments completed!

Verification
Testing orchestrator health...
  [OK] Orchestrator is healthy
    Status: healthy
    Agent: Orchestrator
    Version: 1.0.0

Testing upload endpoint...
  [OK] Upload endpoint exists (405 = Method Not Allowed for GET)

==========================================
Deployment Complete!
==========================================
```

---

## 🔍 Verification After Deployment

### 1. Health Check
```powershell
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health
```

**Expected:**
```json
{
  "status": "healthy",
  "agent": "Orchestrator",
  "version": "1.0.0",
  "timestamp": "..."
}
```

### 2. Check Logs (No ImportError)
```bash
aws logs tail /ecs/ca-a2a/orchestrator --since 5m --region eu-west-3
```

**Expected output:**
```
[INFO] MCP HTTP context initialized
[INFO] Upload handler initialized  
[INFO] Upload endpoint registered at POST /upload
[INFO] Orchestrator initialized
[INFO] Server started on http://0.0.0.0:8001
```

**Should NOT see:**
```
ImportError: cannot import name 'ClientSession' from 'mcp.client'  ❌
```

### 3. Test Upload
```powershell
.\Test-UploadViaALB.ps1
```

---

## 🐛 Troubleshooting

### If ECR Login Fails

**Error:** `UnrecognizedClientException: The security token included in the request is invalid`

**Solution:** Configure AWS credentials
```powershell
aws configure
# OR
$env:AWS_PROFILE = "your-profile"
```

### If Build Fails

**Check Docker is running:**
```powershell
docker ps
```

**Check Dockerfile syntax:**
```powershell
docker build -f Dockerfile.orchestrator -t test .
```

### If Container Still Crashes

**Check logs for the specific agent:**
```bash
# Orchestrator
aws logs tail /ecs/ca-a2a/orchestrator --since 10m --region eu-west-3

# Extractor
aws logs tail /ecs/ca-a2a/extractor --since 10m --region eu-west-3

# Validator
aws logs tail /ecs/ca-a2a/validator --since 10m --region eu-west-3

# Archivist
aws logs tail /ecs/ca-a2a/archivist --since 10m --region eu-west-3
```

**Check task status:**
```bash
aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator --region eu-west-3
```

### If Deployment Takes Too Long

**Check service events:**
```bash
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].events[0:5]'
```

---

## 📚 Alternative: Deploy One Agent at a Time

If you prefer to deploy agents individually:

### Orchestrator Only
```powershell
.\Rebuild-And-Redeploy-Orchestrator.ps1
```

### Or manually:
```powershell
# Set variables
$AWS_REGION = "eu-west-3"
$AWS_ACCOUNT_ID = "555043101106"
$AGENT = "orchestrator"  # or extractor, validator, archivist

# Login
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# Build
docker build -f "Dockerfile.${AGENT}" -t "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/ca-a2a/${AGENT}:latest" .

# Push
docker push "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/ca-a2a/${AGENT}:latest"

# Deploy
aws ecs update-service --cluster ca-a2a-cluster --service $AGENT --force-new-deployment --region $AWS_REGION

# Wait 2-3 minutes then check
aws ecs describe-services --cluster ca-a2a-cluster --services $AGENT --region $AWS_REGION
```

---

## 📦 What Was Fixed

| File | Change | Impact |
|------|--------|--------|
| `mcp_client.py` | Conditional imports with API check | No crash if SDK missing/incompatible |
| `Dockerfile.orchestrator` | Python 3.9 → 3.11 | Compatible with mcp>=0.9.0 |
| `Dockerfile.extractor` | Python 3.9 → 3.11 | Compatible with mcp>=0.9.0 |
| `Dockerfile.validator` | Python 3.9 → 3.11 | Compatible with mcp>=0.9.0 |
| `Dockerfile.archivist` | Python 3.9 → 3.11 | Compatible with mcp>=0.9.0 |

---

## ✅ Success Criteria

After deployment, verify:
- [ ] All 4 services show "ACTIVE" status
- [ ] Orchestrator health endpoint returns 200
- [ ] Upload endpoint exists (POST /upload)
- [ ] No ImportError in logs
- [ ] Tasks running with desired count
- [ ] File upload works via ALB

---

## 🎯 Ready to Deploy

**Commands to run in PowerShell:**

```powershell
# Navigate to project
cd C:\Users\Utilisateur\Desktop\projects\ca_a2a

# Run deployment (10-15 minutes)
.\Rebuild-All-Agents-NoPrompt.ps1

# After completion, test upload
.\Test-UploadViaALB.ps1
```

---

## 📝 Commits Applied

- **18098d1** - Fix MCP SDK import error for AWS deployment
- **e19c9d9** - Add deployment documentation for MCP fix

**Status:** ✅ Code ready, scripts ready, waiting for manual execution

---

**Note:** The deployment script must be run in an interactive PowerShell session with AWS credentials configured. This cannot be automated from Cursor's terminal.

