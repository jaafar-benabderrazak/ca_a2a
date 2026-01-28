# Deployment Script Fix Summary - 2026-01-25

## Root Cause Identified

**Problem**: The deployment script was using security groups from the wrong VPC, causing RDS cluster creation to fail.

**Error**: 
```
The DB instance and EC2 security group are in different VPCs. 
The DB instance is in vpc-0839f598c557a60c8 and the EC2 security group is in vpc-03f0bb6691348dede
```

## Fix Applied

Updated `cloudshell-complete-deploy.sh` to include VPC ID filtering for ALL security group lookups:

### Lines Fixed:
1. **Line 445** - ALB Security Group lookup
2. **Line 468** - Agent Security Groups lookup (orchestrator, extractor, validator, archivist, keycloak, mcp-server)
3. **Line 504** - RDS Security Group lookup
4. **Line 923** - VPC Endpoint Security Group lookup

### Change Pattern:
```bash
# BEFORE (incorrect - no VPC filtering)
aws ec2 describe-security-groups --filters "Name=group-name,Values=${PROJECT_NAME}-rds-sg" \
    --region ${AWS_REGION} --query 'SecurityGroups[0].GroupId' --output text

# AFTER (correct - with VPC filtering)
aws ec2 describe-security-groups --filters "Name=vpc-id,Values=${VPC_ID}" "Name=group-name,Values=${PROJECT_NAME}-rds-sg" \
    --region ${AWS_REGION} --query 'SecurityGroups[0].GroupId' --output text
```

## Current Status

### ✅ Completed:
- VPC created: `vpc-0839f598c557a60c8`
- All security groups created in correct VPC
- S3 bucket configured
- Secrets Manager secrets created
- Aurora cluster `ca-a2a-documents-db` is **creating** (8-10 minutes)

### ⏳ In Progress:
- Aurora PostgreSQL 15.15 cluster creation
- Expected completion: ~10 minutes from 17:46 UTC (2026-01-25)

### 🔜 Next Steps:
1. Wait for Aurora cluster to become available
2. Run `./resume-deployment.sh` to:
   - Create Aurora instance (db.t3.medium)
   - Create Keycloak database (PostgreSQL 16.6, db.t3.small)
3. Run `./cloudshell-complete-deploy.sh` to complete ECS services deployment

## Scripts Added

### `fix-rds-sg-and-create-cluster.sh`
- Finds correct RDS security group in current VPC
- Creates Aurora cluster with correct security group
- Used to resolve the immediate issue

### `resume-deployment.sh`
- Monitors Aurora cluster creation status
- Automatically creates Aurora instance once cluster is available
- Creates Keycloak database
- Provides next steps for completing deployment

## Verification

To verify the fix worked:
```bash
# Check Aurora cluster status
aws rds describe-db-clusters \
  --db-cluster-identifier ca-a2a-documents-db \
  --region us-east-1 \
  --query 'DBClusters[0].{Status:Status,VPC:VpcSecurityGroups[0].VpcSecurityGroupId}'

# Should show:
# Status: "creating" (then "available")
# VpcSecurityGroupId: sg-0dce43e25fe157b2d (from vpc-0839f598c557a60c8)
```

## Why This Happened

Multiple deployment attempts across different regions (eu-west-3, us-east-1) and VPC limit issues led to:
1. Multiple VPCs being created
2. Security group IDs being cached or picked up from wrong VPC
3. The `describe-security-groups` commands not filtering by VPC ID, so they picked the first match (wrong VPC)

## Prevention

The fix ensures:
- All security group lookups are scoped to the current VPC
- No cross-VPC resource references can occur
- Deployments are idempotent and safe to re-run

## Commit

**Commit**: 1d5688d  
**Message**: "Fix VPC ID filtering for all security group lookups"  
**Files Changed**: 
- `cloudshell-complete-deploy.sh` (4 security group lookups fixed)
- `resume-deployment.sh` (new helper script)

---

**Fixed by**: Jaafar Benabderrazak  
**Date**: 2026-01-25  
**Region**: us-east-1

