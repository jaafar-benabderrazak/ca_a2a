# AWS CLI Terminal Fix Guide

## Problem
AWS CLI is installed but not recognized in some terminal sessions opened before installation.

## Quick Solution

### ✅ EASIEST METHOD: Restart Terminals

1. **Close ALL existing terminals:**
   - Click the "X" on each terminal tab
   - Or right-click → Kill Terminal

2. **Open a new terminal:**
   - Press `Ctrl+`` (backtick)
   - Or: Terminal → New Terminal
   - Or: View → Terminal

3. **Test AWS CLI:**
```powershell
aws --version
```

Expected output: `aws-cli/2.32.23 ...`

---

## Alternative: Refresh PATH Without Restart

### For PowerShell Terminals

Run this command in each PowerShell terminal:

```powershell
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
```

Then test:
```powershell
aws --version
```

### For CMD Terminals

CMD cannot refresh PATH dynamically. You must:
1. Close the CMD terminal
2. Open a new CMD terminal

---

## Current Terminal Status

Based on your setup:

| Terminal | Type | Status | Action Needed |
|----------|------|--------|---------------|
| Terminal 4 | PowerShell | ✅ Working | None - use this one! |
| Terminal 3 | CMD | ❌ Not Working | Close and reopen |
| Other PowerShell | PowerShell | ❌ Not Working | Close and reopen OR run PATH refresh |

---

## Recommended Approach

**Use Terminal 4** (where I fixed the PATH) for your AWS testing:

```powershell
# Verify AWS CLI works
aws --version

# Configure credentials
aws configure sso
# OR
aws configure

# Run tests
.\test-aws-complete.ps1
```

---

## Next Steps After Configuration

Once AWS CLI is configured:

```powershell
# Test connection
aws sts get-caller-identity --region eu-west-3

# List ECS clusters
aws ecs list-clusters --region eu-west-3

# Run full test suite
.\test-aws-complete.ps1
```

---

## Troubleshooting

### If AWS CLI still not found after restart:

1. **Verify installation:**
```powershell
Test-Path "C:\Program Files\Amazon\AWSCLIV2\aws.exe"
```

2. **Check PATH manually:**
```powershell
$env:Path -split ';' | Select-String "AWS"
```

Expected output should show: `C:\Program Files\Amazon\AWSCLIV2`

3. **Add to PATH manually** (if missing):
```powershell
$existingPath = [System.Environment]::GetEnvironmentVariable("Path","Machine")
$awsPath = "C:\Program Files\Amazon\AWSCLIV2"
[System.Environment]::SetEnvironmentVariable("Path", "$existingPath;$awsPath", "Machine")
```

Then restart your terminal.

---

## Summary

**Simplest solution:** Close all terminals, open a new one, AWS CLI will work.

**Current working terminal:** Terminal 4 - use this for AWS testing right now!

