# Installing AWS CLI on Windows - Quick Guide

## Issue
You tried to run AWS tests but got: `aws : Le terme «aws» n'est pas reconnu`

This means AWS CLI is not installed on your Windows machine.

---

## ✅ Solution 1: Install AWS CLI (Recommended for Local Testing)

### Option A: Using winget (Windows Package Manager)

```powershell
# Run in PowerShell as Administrator
winget install Amazon.AWSCLI

# After installation, restart PowerShell
# Then verify:
aws --version
```

### Option B: Using MSI Installer

1. **Download AWS CLI:**
   - Visit: https://aws.amazon.com/cli/
   - Download: `AWSCLIV2.msi` (64-bit Windows)

2. **Install:**
   - Double-click the downloaded file
   - Follow the installation wizard
   - Accept default settings

3. **Verify Installation:**
   ```powershell
   # Open NEW PowerShell window
   aws --version
   
   # Should show something like:
   # aws-cli/2.15.0 Python/3.11.6 Windows/10 exe/AMD64
   ```

### Configure AWS Credentials

After installing, configure your AWS credentials:

```powershell
# Configure with SSO (recommended for your setup)
aws configure sso

# Follow the prompts:
# SSO session name: ca-a2a
# SSO start URL: [your-sso-url]
# SSO region: eu-west-3
# Default client Region: eu-west-3
# Default output format: json

# Then login:
aws sso login --profile default

# Verify:
aws sts get-caller-identity --region eu-west-3
```

### Run Tests

Once AWS CLI is installed and configured:

```powershell
# Navigate to project
cd C:\Users\Utilisateur\Desktop\projects\ca_a2a

# Run PowerShell test suite
.\test-aws-complete.ps1
```

---

## ✅ Solution 2: Use AWS CloudShell (No Installation Required!)

**Recommended if you just want to test quickly without installing anything.**

### Steps:

1. **Open AWS Console:**
   - Go to: https://console.aws.amazon.com
   - Login with your credentials

2. **Switch to eu-west-3 Region:**
   - Click the region dropdown (top right)
   - Select: **Europe (Paris) eu-west-3**

3. **Open CloudShell:**
   - Click the **CloudShell icon** (terminal icon) in the top navigation bar
   - Wait ~30 seconds for CloudShell to initialize

4. **Upload Test Script:**
   ```bash
   # In CloudShell, create the test script
   cat > test-aws-complete.sh << 'EOF'
   # ... paste the content from test-aws-complete.sh ...
   EOF
   
   # Or clone the repo
   git clone https://github.com/jaafar-benabderrazak/ca_a2a.git
   cd ca_a2a
   ```

5. **Run Tests:**
   ```bash
   chmod +x test-aws-complete.sh
   ./test-aws-complete.sh
   ```

### Advantages of CloudShell:
- ✅ No installation required
- ✅ AWS CLI pre-installed and configured
- ✅ `jq` pre-installed
- ✅ Already authenticated
- ✅ Inside AWS network (faster)
- ✅ Free to use

---

## ✅ Solution 3: Quick API Tests (Without AWS CLI)

If you only want to test the API endpoints (not infrastructure), you can use PowerShell without AWS CLI:

```powershell
# Set ALB URL
$ALB_URL = "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Test 1: Health Check
$health = Invoke-RestMethod -Uri "$ALB_URL/health"
$health | ConvertTo-Json

# Test 2: Agent Card
$card = Invoke-RestMethod -Uri "$ALB_URL/card"
$card | ConvertTo-Json

# Test 3: List Skills
$skills = Invoke-RestMethod -Uri "$ALB_URL/skills"
$skills.skills | ForEach-Object { $_.skill_id }

# Test 4: Process Document (requires document in S3)
$body = @{
    s3_key = "incoming/sample_invoice.pdf"
} | ConvertTo-Json

$result = Invoke-RestMethod -Uri "$ALB_URL/process" -Method Post -Body $body -ContentType "application/json"
$result | ConvertTo-Json
```

---

## 📋 Comparison

| Method | Pros | Cons | Best For |
|--------|------|------|----------|
| **Install AWS CLI** | Full control, local testing, all features | Requires installation & configuration | Regular development work |
| **AWS CloudShell** | No setup, pre-configured, free | Requires AWS Console access | Quick tests, demos |
| **API Tests Only** | No AWS CLI needed, quick | Can't test infrastructure | Testing API endpoints only |

---

## 🎯 Recommended Approach

### For Your Situation:

**Use AWS CloudShell** for now because:
1. ✅ No installation needed
2. ✅ You need to test the full infrastructure (not just API)
3. ✅ It's already configured and ready
4. ✅ The bash script will work perfectly there

### Steps Right Now:

```powershell
# 1. Open AWS Console in browser
Start-Process "https://console.aws.amazon.com"

# 2. Switch to eu-west-3 region
# 3. Click CloudShell icon
# 4. In CloudShell, run:
#    git clone https://github.com/jaafar-benabderrazak/ca_a2a.git
#    cd ca_a2a
#    bash test-aws-complete.sh
```

### For Future (Install Locally):

```powershell
# Install AWS CLI for future use
winget install Amazon.AWSCLI

# Restart PowerShell, then configure
aws configure sso

# Then you can run local tests
.\test-aws-complete.ps1
```

---

## 🐛 Troubleshooting

### Issue: `winget: command not found`

**Solution:** Update Windows or use MSI installer instead.

```powershell
# Check Windows version
winver

# If Windows 10 < 1809 or Windows 11 < 21H2, use MSI installer
# Download from: https://aws.amazon.com/cli/
```

### Issue: AWS CLI installed but still not recognized

**Solution:** Restart PowerShell and check PATH.

```powershell
# Close and reopen PowerShell
# Then check:
$env:Path -split ';' | Select-String -Pattern 'AWS'

# If not found, add manually:
$env:Path += ";C:\Program Files\Amazon\AWSCLIV2\"
```

### Issue: AWS credentials not working

**Solution:** Reconfigure credentials.

```powershell
# Remove old credentials
Remove-Item -Path "$env:USERPROFILE\.aws" -Recurse -Force

# Reconfigure
aws configure sso
```

---

## 📞 Need Help?

**Quick Links:**
- AWS CLI Docs: https://docs.aws.amazon.com/cli/
- CloudShell Docs: https://docs.aws.amazon.com/cloudshell/
- Project Repo: https://github.com/jaafar-benabderrazak/ca_a2a

**Files Created:**
- `test-aws-complete.ps1` - PowerShell version (requires AWS CLI)
- `test-aws-complete.sh` - Bash version (for CloudShell or WSL)
- `AWS_COMPREHENSIVE_TESTS.md` - Full documentation

---

**Status:** Choose your method and start testing! 🚀

