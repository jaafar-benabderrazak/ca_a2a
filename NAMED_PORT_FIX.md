# Quick Fix: Named Port Mapping Error

## ❌ Error You Got:
```
InvalidParameterException: portName(http) does not refer to any named PortMapping
```

## 🔍 Root Cause:
The archivist service is configured to use a named port `"http"`, but the task definition doesn't include the port name.

## ✅ Solution:

### Option 1: Quick Fix in CloudShell (Fastest)

Run this command to fix the script:

```bash
sed -i 's/"portMappings": \[{"containerPort": 8004, "protocol": "tcp"}\]/"portMappings": [{"containerPort": 8004, "protocol": "tcp", "name": "http"}]/' deploy-archivist-fix.sh
```

Then re-run:
```bash
./deploy-archivist-fix.sh
```

### Option 2: Manual Fix

Edit the script:
```bash
nano deploy-archivist-fix.sh
```

Find line with:
```json
"portMappings": [{"containerPort": 8004, "protocol": "tcp"}],
```

Change to:
```json
"portMappings": [{"containerPort": 8004, "protocol": "tcp", "name": "http"}],
```

Save (Ctrl+X, Y, Enter) and re-run:
```bash
./deploy-archivist-fix.sh
```

### Option 3: Use Updated File from Cursor

The file `deploy-archivist-fix.sh` in Cursor has been updated. Re-upload it to CloudShell:
1. Click **Actions** → **Upload file**
2. Select `deploy-archivist-fix.sh` (will replace the existing one)
3. Run:
```bash
chmod +x deploy-archivist-fix.sh
./deploy-archivist-fix.sh
```

## ✅ Expected Result:

After the fix, you should see:
```
Step 1: Registering new task definition with MCP_SERVER_URL...
✓ New task definition registered: revision 9

Step 2: Updating service to use new task definition and force deployment...
[Success output with service update]

Step 3: Waiting 45 seconds for new tasks to start...
```

## 🎯 Quick One-Liner (Copy-Paste in CloudShell):

```bash
sed -i 's/"portMappings": \[{"containerPort": 8004, "protocol": "tcp"}\]/"portMappings": [{"containerPort": 8004, "protocol": "tcp", "name": "http"}]/' deploy-archivist-fix.sh && ./deploy-archivist-fix.sh
```

This will fix and run in one command! 🚀

