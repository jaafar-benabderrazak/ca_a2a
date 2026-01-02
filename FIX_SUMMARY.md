# 🔧 Fix Summary: MCP SDK Import Error

**Date:** 2026-01-02  
**Status:** ✅ FIXED - Ready to Deploy

---

## 📊 Problem Summary

### What Happened
- New orchestrator container built with upload feature **failed to start**
- Error: `ImportError: cannot import name 'ClientSession' from 'mcp.client'`
- Old containers (without upload) continued working ✅
- Deployment stuck on old version
- Upload endpoint `/upload` unavailable

### Root Cause
The `mcp_client.py` file imports the MCP SDK stdio client at **module level**:
```python
from mcp.client import ClientSession, StdioServerParameters  # ❌ FAILED
```

**Why this broke:**
1. The MCP SDK API changed between versions
2. In AWS deployment, we **only use HTTP mode** (`mcp_client_http.py`)
3. But Python still executes module-level imports even if not used
4. The import failed because the SDK classes were renamed/removed

**Why old containers worked:**
- Built with older Python/dependencies before the SDK update
- Never attempted to import the new SDK version

---

## ✅ Solution Implemented

### Changes Made

#### 1. **`mcp_client.py`** - Defensive Import Pattern
```python
# Initialize to None first
ClientSession = None
StdioServerParameters = None
stdio_client = None
MCP_STDIO_AVAILABLE = False

try:
    # Import module first
    import mcp.client
    import mcp.client.stdio
    
    # Check if API exists before importing (compatibility check)
    if hasattr(mcp.client, 'ClientSession') and hasattr(mcp.client, 'StdioServerParameters'):
        from mcp.client import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        MCP_STDIO_AVAILABLE = True
    else:
        # SDK API has changed
        logging.debug("MCP SDK API has changed. Stdio mode unavailable.")
except ImportError:
    # SDK not installed (expected in AWS)
    logging.debug("MCP SDK not installed. Only HTTP mode available.")
except Exception as e:
    # Other errors
    logging.debug(f"MCP stdio client unavailable: {e}")
```

**Key improvements:**
- ✅ Graceful fallback when SDK unavailable
- ✅ API compatibility check before importing
- ✅ No crash if SDK classes don't exist
- ✅ HTTP mode works independently

#### 2. **All Dockerfiles** - Python 3.11 Upgrade
Updated all agent Dockerfiles to Python 3.11:
- `Dockerfile.orchestrator`
- `Dockerfile.extractor`
- `Dockerfile.validator`
- `Dockerfile.archivist`

**Why:** The `mcp>=0.9.0` package requires Python 3.11+

#### 3. **`Rebuild-And-Redeploy-Orchestrator.ps1`** - Deployment Script
New PowerShell script to automate the rebuild/redeploy:
- Login to ECR
- Build image with fixed code
- Push to ECR
- Force ECS service update
- Wait for deployment
- Verify health and upload endpoints

#### 4. **`TROUBLESHOOTING.md`** - Documentation
Added section documenting the issue and fix for future reference.

---

## 🚀 Deploy the Fix

### Option 1: Automated Script (Recommended)
```powershell
# Run the automated rebuild/redeploy script
.\Rebuild-And-Redeploy-Orchestrator.ps1
```

**What it does:**
1. Logs into ECR
2. Builds orchestrator image with Python 3.11 + fixed imports
3. Pushes to ECR
4. Updates ECS service with force new deployment
5. Waits for deployment to complete
6. Verifies health and upload endpoints

**Expected output:**
- ✅ ECR login successful
- ✅ Image built successfully
- ✅ Image pushed to ECR
- ✅ Service update initiated
- ✅ Deployment completed
- ✅ Health check passed
- ✅ Upload endpoint exists

**Time:** ~5-7 minutes (2 min build, 2-3 min deployment, 1 min verification)

### Option 2: Manual Steps
```powershell
# 1. Login to ECR
$AWS_REGION = "eu-west-3"
$AWS_ACCOUNT_ID = "555043101106"
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# 2. Build image
docker build -f Dockerfile.orchestrator -t ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/ca-a2a/orchestrator:latest .

# 3. Push to ECR
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/ca-a2a/orchestrator:latest

# 4. Update ECS service
aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --force-new-deployment --region $AWS_REGION

# 5. Wait and verify
Start-Sleep -Seconds 120
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health
```

---

## ✅ Verification Steps

### 1. Check Health Endpoint
```powershell
$ALB_URL = "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
Invoke-RestMethod -Uri "$ALB_URL/health" -Method Get
```

**Expected response:**
```json
{
  "status": "healthy",
  "agent": "Orchestrator",
  "version": "1.0.0",
  "timestamp": "..."
}
```

### 2. Check Upload Endpoint Exists
```powershell
# This should return 405 Method Not Allowed (since we're using GET)
Invoke-WebRequest -Uri "$ALB_URL/upload" -Method Get -SkipHttpErrorCheck
```

**Expected:** `405 Method Not Allowed` (endpoint exists but requires POST)

### 3. Test File Upload
```powershell
.\Test-UploadViaALB.ps1
```

### 4. Monitor Logs
```bash
# Watch orchestrator logs
aws logs tail /ecs/ca-a2a/orchestrator --follow --region eu-west-3

# Should see:
# - "MCP HTTP context initialized" ✅
# - "Upload handler initialized" ✅
# - "Upload endpoint registered at POST /upload" ✅
# - No ImportError ✅
```

---

## 📋 What Was Fixed

| Component | Before | After |
|-----------|--------|-------|
| **mcp_client.py** | Hard import (crashes if SDK unavailable) | Conditional import with API check |
| **Dockerfiles** | Python 3.9 | Python 3.11 |
| **Container startup** | ❌ Crashes with ImportError | ✅ Starts successfully |
| **Upload endpoint** | ❌ Unavailable | ✅ Available at `/upload` |
| **HTTP mode** | ✅ Works (but container crashes) | ✅ Works correctly |

---

## 🔄 Rollout Plan

### Phase 1: Orchestrator (Priority)
1. Deploy orchestrator fix (this document)
2. Verify upload endpoint works
3. Test document upload

### Phase 2: Other Agents (Optional)
The other agents (extractor, validator, archivist) don't have the upload feature, but we updated their Dockerfiles to Python 3.11 for consistency.

**Rebuild all agents:**
```bash
# Use existing deployment script
./update-aws-deployment.sh
```

Or rebuild individually as needed.

---

## 🎯 Next Steps

1. **Deploy the fix:**
   ```powershell
   .\Rebuild-And-Redeploy-Orchestrator.ps1
   ```

2. **Test upload:**
   ```powershell
   .\Test-UploadViaALB.ps1
   ```

3. **Monitor the system:**
   - Check orchestrator logs for any errors
   - Verify all agents are healthy
   - Test end-to-end document processing

4. **Optional: Update other agents** (when convenient)
   - Run `./update-aws-deployment.sh` to rebuild all agents with Python 3.11

---

## 📚 Technical Details

### Why This Pattern Works

**Conditional Import:**
```python
ClientSession = None  # Initialize first
try:
    import mcp.client
    if hasattr(mcp.client, 'ClientSession'):  # API check
        from mcp.client import ClientSession
except:
    pass  # Graceful fallback
```

**Benefits:**
- ✅ Module is always importable (doesn't crash)
- ✅ Works whether SDK is present or not
- ✅ Works with old or new SDK versions
- ✅ HTTP mode completely independent

### Architecture Reminder

```
In AWS Deployment:
┌─────────────────────────────────────────────────────┐
│ Agent Containers (orchestrator, extractor, etc.)    │
│                                                     │
│  - Import: mcp_context_auto.py                     │
│  - Checks: MCP_SERVER_URL env var is set           │
│  - Uses: mcp_client_http.py (HTTP mode) ✅         │
│  - Skips: mcp_client.py (stdio mode) ⏭️            │
│                                                     │
│  BUT: Python still loads mcp_client.py module      │
│       → Must not crash on import                   │
└─────────────────────────────────────────────────────┘
```

---

## 🐛 Troubleshooting

### If deployment fails:
```bash
# Check ECS service events
aws ecs describe-services --cluster ca-a2a-cluster --service orchestrator --region eu-west-3

# Check task logs
aws logs tail /ecs/ca-a2a/orchestrator --since 10m --region eu-west-3

# Check task status
aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator --region eu-west-3
```

### If container still crashes:
1. Verify Python 3.11 in Dockerfile
2. Verify `requirements.txt` has `mcp>=0.9.0`
3. Check if any other files import `mcp_client` directly
4. Review CloudWatch logs for full stack trace

---

## ✅ Summary

**Problem:** MCP SDK import failed in new containers  
**Root Cause:** Module-level import with incompatible SDK version  
**Solution:** Conditional import with API compatibility check  
**Status:** Fixed and ready to deploy  
**Deploy:** Run `.\Rebuild-And-Redeploy-Orchestrator.ps1`  
**Time:** ~5-7 minutes  

**Commit:** `18098d1` - "Fix MCP SDK import error for AWS deployment"

