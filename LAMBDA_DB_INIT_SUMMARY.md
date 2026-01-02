# Database Schema Initialization - Solution Summary

## 🎯 Problem

**Current Status in `ETAT_DU_PROJET.md`:**
```
| Database | documents_db | ⚠️ Existe mais schéma à initialiser |
```

**What's Missing:**
- ❌ `documents` table
- ❌ `processing_logs` table
- ❌ Indexes for performance

**Why Not Fixed:**
- RDS is in **private subnet** (no public access)
- CloudShell **cannot reach** private RDS
- Code doesn't **auto-initialize** on startup

---

## ✅ Solution: Lambda Function (Option 3)

### Architecture

```
┌─────────────────┐
│  Your Computer  │
│  or CloudShell  │
└────────┬────────┘
         │
         │ 1. Deploy Lambda
         ▼
┌─────────────────────────────────────┐
│        AWS Lambda Function          │
│  ┌───────────────────────────────┐  │
│  │  Lambda in VPC                │  │
│  │  - Runs in private subnet     │  │
│  │  - Reads DB password from     │  │
│  │    Secrets Manager            │  │
│  │  - Connects to RDS            │  │
│  │  - Creates schema             │  │
│  └───────────────┬───────────────┘  │
└──────────────────┼───────────────────┘
                   │ 2. Create Tables
                   ▼
         ┌─────────────────┐
         │  RDS PostgreSQL │
         │  documents_db   │
         │  ┌───────────┐  │
         │  │ documents │  │
         │  │ + indexes │  │
         │  ├───────────┤  │
         │  │proc. logs │  │
         │  │ + indexes │  │
         │  └───────────┘  │
         └─────────────────┘
```

---

## 📦 What I Created

### 1. `Deploy-DatabaseInitLambda.ps1`
**Fully automated PowerShell script**

**Steps:**
1. ✅ Get AWS account and infrastructure config
2. ✅ Retrieve VPC, subnets, security groups
3. ✅ Get RDS endpoint
4. ✅ Create Lambda function code
5. ✅ Create IAM role with permissions
6. ✅ Deploy Lambda to VPC with psycopg2 layer
7. ✅ Invoke Lambda to create schema
8. ✅ Display results and clean up

**Usage:**
```powershell
.\Deploy-DatabaseInitLambda.ps1           # Run and auto-cleanup
.\Deploy-DatabaseInitLambda.ps1 -KeepLambda  # Keep for reuse
```

---

### 2. `LAMBDA_DB_INIT_GUIDE.md`
**Comprehensive documentation**

**Contents:**
- Problem explanation
- Solution architecture
- Automated script usage
- Manual AWS CLI steps
- Troubleshooting guide
- Security considerations
- Cost estimation
- Next steps after initialization

---

## 🗄️ Database Schema Created

### Tables

**1. `documents`**
```sql
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    s3_key VARCHAR(500) UNIQUE NOT NULL,
    document_type VARCHAR(50) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_size INTEGER,
    upload_date TIMESTAMP,
    processing_date TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending',
    validation_score FLOAT,
    metadata JSONB,
    extracted_data JSONB,
    validation_details JSONB,
    error_message TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

**2. `processing_logs`**
```sql
CREATE TABLE processing_logs (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id),
    agent_name VARCHAR(50) NOT NULL,
    action VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    details JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Indexes (6 total)
- `idx_documents_s3_key` - Fast S3 key lookup
- `idx_documents_status` - Filter by status
- `idx_documents_type` - Filter by document type
- `idx_documents_date` - Time-based queries
- `idx_logs_document_id` - Logs per document
- `idx_logs_agent` - Logs per agent

---

## 🚀 How to Run

### Prerequisites

**AWS Credentials:** You need one of:
- ✅ AWS Access Keys (via `aws configure`)
- ✅ AWS SSO (via `aws configure sso`)
- ✅ AWS CloudShell (already authenticated)

### Option A: AWS CloudShell (Recommended - Zero Setup)

1. Open https://console.aws.amazon.com
2. Switch to **eu-west-3** region
3. Click **CloudShell icon** (terminal in top bar)
4. Upload `Deploy-DatabaseInitLambda.ps1`:
   ```bash
   # In CloudShell
   # Actions > Upload file > Select Deploy-DatabaseInitLambda.ps1
   ```
5. Run:
   ```bash
   pwsh Deploy-DatabaseInitLambda.ps1
   ```

### Option B: Local Windows (Requires Credentials)

1. Configure AWS CLI:
   ```powershell
   aws configure
   ```
   
2. Run the script:
   ```powershell
   cd C:\Users\Utilisateur\Desktop\projects\ca_a2a
   .\Deploy-DatabaseInitLambda.ps1
   ```

---

## ⏱️ Execution Flow

```
Starting...
├─ [1/8] Getting AWS Account Info... ✓
├─ [2/8] Retrieving VPC Configuration... ✓
├─ [3/8] Getting RDS Configuration... ✓
├─ [4/8] Creating Lambda Code... ✓
├─ [5/8] Creating Deployment Package... ✓
├─ [6/8] Creating IAM Role... ✓
├─ [7/8] Deploying Lambda Function... ✓
├─ [8/8] Invoking Lambda... ✓
│
├─ Lambda Execution:
│  ├─ Getting DB password from Secrets Manager... ✓
│  ├─ Connecting to RDS... ✓
│  ├─ Creating documents table... ✓
│  ├─ Creating processing_logs table... ✓
│  ├─ Creating indexes... ✓
│  └─ Verification: Found 2 tables
│     ├─ documents: 0 rows
│     └─ processing_logs: 0 rows
│
├─ [CLEANUP] Removing temp files... ✓
└─ [CLEANUP] Deleting Lambda... ✓

✓ Database schema initialized successfully!
```

**Total Time:** ~2-3 minutes  
**Cost:** < $0.01 USD

---

## ✅ After Running

### Update Documentation

In `ETAT_DU_PROJET.md`, change:
```markdown
| Database | `documents_db` | ⚠️ **Existe mais schéma à initialiser** |
```

To:
```markdown
| Database | `documents_db` | ✅ **Schéma initialisé et prêt** |
```

### Verify

**Method 1: Re-run the script**
```powershell
.\Deploy-DatabaseInitLambda.ps1 -KeepLambda
```
It will show existing tables and row counts.

**Method 2: Test document processing**
```bash
# Upload test document
aws s3 cp test.pdf s3://ca-a2a-documents/incoming/

# Check agents process it
# Verify entry in documents table
```

---

## 🔐 Security

- ✅ **Network Isolation:** Lambda runs in private subnet
- ✅ **Credentials:** Password from Secrets Manager, never hardcoded
- ✅ **IAM:** Least privilege permissions
- ✅ **TLS/SSL:** Encrypted connection to RDS
- ✅ **Idempotent:** Safe to run multiple times (`IF NOT EXISTS`)

---

## 💰 Cost Breakdown

| Resource | Duration | Cost |
|----------|----------|------|
| Lambda execution | ~10 seconds | < $0.001 |
| Lambda storage (if kept) | 1 month | ~$0.001/month |
| IAM role | N/A | Free |
| CloudWatch logs | < 1 MB | Free (within limits) |
| **TOTAL** | One-time | **< $0.01** |

---

## 🐛 Troubleshooting

### Lambda Timeout
**Problem:** Lambda times out after 60 seconds

**Causes:**
- Security group not allowing outbound PostgreSQL (port 5432)
- Subnet routing issues
- RDS not reachable from Lambda's subnet

**Fix:** Verify security group rules

### psycopg2 Not Found
**Problem:** `ModuleNotFoundError: No module named 'psycopg2'`

**Fix:** Script automatically adds psycopg2 layer. If issue persists, check layer ARN.

### Secrets Manager Access Denied
**Problem:** `AccessDeniedException` when reading secret

**Fix:** Verify IAM role has `SecretsManagerReadWrite` policy attached

---

## 📚 Files Reference

| File | Purpose | Location |
|------|---------|----------|
| `Deploy-DatabaseInitLambda.ps1` | Automated deployment script | Project root |
| `LAMBDA_DB_INIT_GUIDE.md` | Full documentation | Project root |
| `LAMBDA_DB_INIT_SUMMARY.md` | This quick reference | Project root |
| `ETAT_DU_PROJET.md` | Project status (French) | Project root |

---

## 📞 Support

**If script fails:**
1. Check CloudWatch logs: `/aws/lambda/ca-a2a-db-init`
2. Verify VPC configuration matches RDS location
3. Ensure IAM permissions are correct
4. Review `LAMBDA_DB_INIT_GUIDE.md` troubleshooting section

**If successful:**
- Schema is ready for production
- Agents can start processing documents
- Update project documentation to reflect completion

---

## ✨ Summary

**Before:**
```
Database: documents_db ⚠️ Existe mais schéma à initialiser
```

**After:**
```
Database: documents_db ✅ Schéma initialisé
├─ documents table (with 4 indexes)
├─ processing_logs table (with 2 indexes)
└─ Ready for production use
```

**Action Required:**
1. Configure AWS credentials (or use CloudShell)
2. Run: `.\Deploy-DatabaseInitLambda.ps1`
3. Wait ~2-3 minutes
4. Done! ✅

---

**Created by:** Jaafar Benabderrazak  
**Date:** January 1, 2026  
**Version:** 1.0

