# ⚠️ Migration v5.1 Requirement: RDS Access from VPC

## Problem
The RDS database is correctly secured in a **private subnet** and is **not accessible from the internet**. This is a **security best practice** ✅.

## Solution: Use AWS RDS Query Editor

### Step-by-Step Instructions

#### 1. Open AWS Console
- Go to: https://console.aws.amazon.com/
- Region: `eu-west-3` (Paris)
- Service: **RDS**

#### 2. Navigate to Query Editor
- In the left sidebar, click **"Query Editor"**
- Or go directly to: https://eu-west-3.console.aws.amazon.com/rds/home?region=eu-west-3#query-editor:

#### 3. Connect to Database
- **Database instance**: Select `documents-db` (or the writer instance if it shows multiple)
- **Database name**: `documents`
- **Authentication**:
  - Select: **"Connect with a Secrets Manager ARN"**
  - Secret: `ca-a2a/db-password`
- Click **"Connect to database"**

#### 4. Execute Migration SQL
Copy and paste the following SQL into the query editor:

```sql
-- CA-A2A v5.1: Token Revocation Table Migration
-- Purpose: Store revoked JWT tokens to prevent reuse

BEGIN;

-- Create revoked_tokens table
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,           -- JWT ID (unique identifier)
    revoked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_by VARCHAR(255),                 -- Principal who revoked it (optional)
    reason TEXT,                              -- Reason for revocation (optional)
    expires_at TIMESTAMP NOT NULL             -- Original JWT expiry (for cleanup)
);

-- Create index on expires_at for efficient cleanup queries
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at 
ON revoked_tokens(expires_at);

-- Create index on revoked_at for audit queries
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_revoked_at 
ON revoked_tokens(revoked_at);

COMMIT;

-- Verify table was created
SELECT 
    table_name, 
    pg_size_pretty(pg_total_relation_size(quote_ident(table_name))) as size
FROM information_schema.tables 
WHERE table_name = 'revoked_tokens';

-- Show table structure
\d revoked_tokens
```

#### 5. Verify Success
You should see output like:

```
table_name      | size
----------------+------
revoked_tokens  | 8192 bytes
```

And the table structure:

```
Column       | Type          | Modifiers
-------------+---------------+-----------
jti          | varchar(255)  | not null
revoked_at   | timestamp     | not null
revoked_by   | varchar(255)  |
reason       | text          |
expires_at   | timestamp     | not null

Indexes:
    "revoked_tokens_pkey" PRIMARY KEY, btree (jti)
    "idx_revoked_tokens_expires_at" btree (expires_at)
    "idx_revoked_tokens_revoked_at" btree (revoked_at)
```

#### 6. Test the Table
Run a quick test:

```sql
-- Insert a test token
INSERT INTO revoked_tokens (jti, revoked_by, reason, expires_at)
VALUES ('test-jti-12345', 'admin', 'Test migration', NOW() + INTERVAL '1 hour');

-- Query it back
SELECT * FROM revoked_tokens WHERE jti = 'test-jti-12345';

-- Clean up test data
DELETE FROM revoked_tokens WHERE jti = 'test-jti-12345';
```

#### 7. Mark as Complete
Once the table is created and verified, the migration is complete! ✅

---

## Alternative: Run from Within VPC (Advanced)

If you need to automate this in the future, you can:

### Option A: Use AWS Systems Manager Session Manager
```bash
# Connect to an ECS task
aws ecs execute-command \
    --cluster ca-a2a-cluster \
    --task <task-id> \
    --container orchestrator \
    --interactive \
    --command "/bin/bash" \
    --region eu-west-3

# Then inside the container:
pip install asyncpg
export DB_PASSWORD=$(aws secretsmanager get-secret-value --secret-id ca-a2a/db-password --region eu-west-3 --query SecretString --output text)
cd /tmp
# Upload and run migration script
```

### Option B: Create a Bastion Host
- Launch an EC2 instance in a public subnet
- Install PostgreSQL client
- Connect to RDS through private network

### Option C: Use VPN or AWS Client VPN
- Set up VPN access to the VPC
- Run migration from your local machine through VPN tunnel

---

## Next Steps After Migration

Once the table is created:

1. ✅ **Phase 1 Complete**: Database migration done
2. ⏭️ **Phase 2**: Deploy Admin API
3. ⏭️ **Phase 3**: Update agent services
4. ⏭️ **Phase 4**: Verification and testing

**Total estimated time remaining**: 20-30 minutes

---

## Troubleshooting

### "Cannot connect to database"
- Verify you selected the correct database instance
- Check that the secret `ca-a2a/db-password` exists and has the correct format
- Ensure your AWS Console session is in region `eu-west-3`

### "Permission denied"
- Your IAM user/role needs:
  - `rds:*` permissions for Query Editor
  - `secretsmanager:GetSecretValue` for ca-a2a/db-password

### "Table already exists"
- That's OK! The SQL uses `IF NOT EXISTS`
- You can skip to the verification step

---

**Need help?** Check the AWS RDS Query Editor documentation:
https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/query-editor.html

