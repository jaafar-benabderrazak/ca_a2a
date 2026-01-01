# AWS Testing on Windows - Complete Guide

## Current Status ✅

- **AWS CLI**: Installed and working
- **PowerShell**: Terminal 5 is ready
- **Test Scripts**: Available (`test-aws-complete.ps1`)
- **Next Step**: Configure AWS credentials

---

## 🚀 Quick Start - Three Options

### Option 1: AWS CloudShell (Recommended - Fastest!)

**No local configuration needed! Test in 2 minutes!**

1. **Open AWS Console**: https://console.aws.amazon.com
2. **Sign in** to your AWS account
3. **Switch region** to `eu-west-3` (Paris) - top-right dropdown
4. **Open CloudShell**: Click the terminal icon (>_) in the top navigation bar
5. **Run tests**:

```bash
# If you haven't cloned the repo yet
git clone https://github.com/jaafar-benabderrazak/ca_a2a.git
cd ca_a2a

# Run the comprehensive test suite
bash test-aws-complete.sh
```

**Advantages:**
- ✅ Already authenticated
- ✅ No credential configuration
- ✅ No line ending issues (Linux environment)
- ✅ Works immediately

---

### Option 2: Configure AWS SSO Locally

**Use this if your organization uses AWS Single Sign-On**

```powershell
# Configure SSO
aws configure sso

# You'll be prompted for:
# - SSO start URL: (ask your AWS admin)
# - SSO Region: eu-west-3
# - Account: (select from list)
# - Role: (select from list)
# - Default region: eu-west-3
# - Output format: json

# After configuration, test connection
aws sts get-caller-identity --region eu-west-3

# Run the test suite
.\test-aws-complete.ps1
```

**When to use:**
- Your organization uses AWS SSO
- You have the SSO start URL

---

### Option 3: Configure AWS Access Keys Locally

**Use this if you have IAM access keys**

```powershell
# Configure with access keys
aws configure

# You'll be prompted for:
# - AWS Access Key ID: [your access key]
# - AWS Secret Access Key: [your secret key]
# - Default region name: eu-west-3
# - Default output format: json

# Test connection
aws sts get-caller-identity --region eu-west-3

# Run the test suite
.\test-aws-complete.ps1
```

**When to use:**
- You have IAM user credentials
- You have Access Key ID and Secret Access Key

**Security Note:**
- Access keys are long-term credentials
- Store them securely
- Consider using SSO instead for better security

---

## 📋 Test Suite Overview

### What Gets Tested

The comprehensive test suite (`test-aws-complete.ps1` or `test-aws-complete.sh`) includes:

#### 1. Infrastructure Tests (7 tests)
- ECS cluster exists
- All 4 services running (Orchestrator, Extractor, Validator, Archivist)
- ALB is active
- Target groups healthy
- RDS database accessible
- S3 bucket accessible
- CloudWatch log groups exist

#### 2. API Health Tests (5 tests)
- All agent endpoints responding
- Health check endpoints
- Agent discovery
- A2A protocol version

#### 3. Document Processing Tests (8 tests)
- Single document upload
- Batch processing
- Document validation
- Archival to S3
- Processing status tracking
- Error handling
- Document retrieval

#### 4. Security Tests (6 tests)
- HTTPS/TLS enforcement
- Authentication required
- Invalid token rejection
- Rate limiting
- API key validation
- JWT token validation

#### 5. Integration Tests (5 tests)
- Full pipeline flow
- Agent-to-agent communication
- Error propagation
- Correlation ID tracking
- Async processing

#### 6. Performance Tests (5 tests)
- Response time < 2s
- Concurrent requests
- Throughput measurement
- Load testing
- Memory usage

#### 7. Monitoring Tests (4 tests)
- CloudWatch logs working
- Metrics being recorded
- Alarms configured
- Log retention policies

#### 8. Data Persistence Tests (3 tests)
- RDS data persistence
- S3 object storage
- Database backups

#### 9. Scalability Tests (2 tests)
- Auto-scaling configuration
- Service task count

**Total: 45+ comprehensive tests**

---

## 🔧 Troubleshooting

### Issue: "Unable to locate credentials"

**Solution:** Configure AWS credentials using one of the three options above.

```powershell
# Quick test if credentials are configured
aws sts get-caller-identity --region eu-west-3

# If this fails, you need to configure credentials
```

---

### Issue: "bash: $'\r': command not found"

**Solution:** You're running a bash script on Windows with wrong line endings.

**Use the PowerShell script instead:**
```powershell
.\test-aws-complete.ps1
```

**OR** run in AWS CloudShell (Option 1) where line endings don't matter.

---

### Issue: "aws: command not found" in new terminals

**Solution:** Refresh PATH or restart terminal

```powershell
# Option A: Refresh PATH in current terminal
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Option B: Close and reopen terminal
# Terminal → New Terminal
```

---

### Issue: Test script shows "AccessDenied" errors

**Possible causes:**
1. **Wrong region**: Make sure you're using `eu-west-3`
2. **Insufficient permissions**: Your IAM user/role needs:
   - ECS read permissions
   - RDS describe permissions
   - S3 read/write permissions
   - CloudWatch read permissions
3. **Expired credentials**: Re-run `aws configure sso` or refresh your session

**Check your identity:**
```powershell
aws sts get-caller-identity --region eu-west-3
```

---

### Issue: "No resources found" errors

**Possible causes:**
1. **Services not deployed yet**: Deploy first using deployment scripts
2. **Wrong region**: Verify you're checking `eu-west-3`
3. **Resources deleted**: Re-run deployment

**Verify deployment:**
```powershell
# Check ECS cluster
aws ecs list-clusters --region eu-west-3

# Check services
aws ecs list-services --cluster ca-a2a-cluster --region eu-west-3

# Check ALB
aws elbv2 describe-load-balancers --region eu-west-3 | Select-String "ca-a2a"
```

---

## 🎯 Testing Workflow

### 1. First-Time Setup (One-time only)

```powershell
# Install AWS CLI (already done!)
winget install Amazon.AWSCLI

# Restart PowerShell or refresh PATH
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Configure credentials (choose one method)
aws configure sso  # OR
aws configure      # OR use CloudShell
```

### 2. Pre-Test Verification

```powershell
# Verify AWS connectivity
aws sts get-caller-identity --region eu-west-3

# Check deployment exists
aws ecs describe-clusters --clusters ca-a2a-cluster --region eu-west-3
```

### 3. Run Tests

```powershell
# Full comprehensive test suite
.\test-aws-complete.ps1

# OR specific test sections (when script supports it)
.\test-aws-complete.ps1 -Section Infrastructure
.\test-aws-complete.ps1 -Section API
.\test-aws-complete.ps1 -Section Security
```

### 4. Review Results

Tests output:
- ✅ Passed tests in green
- ❌ Failed tests in red
- Summary at the end
- Log file saved (if configured)

---

## 📊 Expected Test Results

### Healthy Deployment
- **Infrastructure**: 7/7 passed
- **API Health**: 5/5 passed
- **Document Processing**: 8/8 passed
- **Security**: 6/6 passed
- **Integration**: 5/5 passed
- **Performance**: 5/5 passed
- **Monitoring**: 4/4 passed
- **Data Persistence**: 3/3 passed
- **Scalability**: 2/2 passed

**Total: 45/45 tests passing** ✅

### Common Failures and Fixes

**"ECS services not running"**
- Check service status: `aws ecs describe-services --cluster ca-a2a-cluster --services orchestrator extractor validator archivist --region eu-west-3`
- Check task status for errors
- Review CloudWatch logs

**"ALB unhealthy targets"**
- Check security groups
- Verify health check settings
- Review application logs

**"RDS not accessible"**
- Check security group rules
- Verify RDS is in `available` state
- Check database credentials

**"Performance tests failing"**
- May be normal if system is under load
- Check CPU/memory metrics
- Consider scaling up tasks

---

## 💡 Pro Tips

### Faster Iteration
- Use CloudShell for quick tests (no credential hassle)
- Use local PowerShell for detailed debugging
- Keep multiple terminal windows open

### Cost Optimization
- Stop services when not testing: `aws ecs update-service --cluster ca-a2a-cluster --service [service-name] --desired-count 0 --region eu-west-3`
- Restart when needed: `--desired-count 1`

### Security Best Practices
- Use SSO instead of access keys when possible
- Rotate access keys regularly
- Use least-privilege IAM roles
- Never commit credentials to git

### Debugging
- Check CloudWatch logs: AWS Console → CloudWatch → Log Groups
- Use `aws ecs describe-tasks` to see task failures
- Review ALB access logs for HTTP issues

---

## 📚 Related Documentation

- `README.md` - Project overview and setup
- `AWS_COMPREHENSIVE_TESTS.md` - Detailed test documentation
- `AWS_TESTING_QUICK_REF.md` - Quick reference for common commands
- `AWS_CLI_INSTALLATION_GUIDE.md` - Installation steps
- `TERMINAL_FIX_GUIDE.md` - Terminal PATH troubleshooting

---

## 🚦 Quick Decision Tree

```
Do you want to test AWS deployment?
│
├─ Yes, quickly and easily
│  └─→ Use AWS CloudShell (Option 1)
│     Open console → CloudShell → Run tests
│
├─ Yes, from my Windows machine
│  │
│  ├─ Organization uses SSO
│  │  └─→ Use Option 2 (aws configure sso)
│  │
│  └─ Have IAM access keys
│     └─→ Use Option 3 (aws configure)
│
└─ No, just testing locally
   └─→ Use docker-compose.yml
      docker-compose up
      pytest test_pipeline.py
```

---

## ✅ Summary

**Current Status:**
- AWS CLI: ✅ Installed
- Terminal: ✅ Ready (Terminal 5)
- Test Scripts: ✅ Available
- AWS Credentials: ⏳ Needs configuration

**Next Action:**
Choose one of the three configuration options and run tests!

**Recommended:** Start with AWS CloudShell (Option 1) for immediate results!

