# Initialize Database Schema from Windows Machine
# Run this in PowerShell

$ErrorActionPreference = "Stop"

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host "  DATABASE SCHEMA INITIALIZATION" -ForegroundColor Green
Write-Host "=========================================`n" -ForegroundColor Green

Write-Host "Step 1: Getting database password..." -ForegroundColor Cyan
$DB_PASSWORD = aws secretsmanager get-secret-value `
  --secret-id ca-a2a/db-password `
  --region eu-west-3 `
  --profile reply-sso `
  --query 'SecretString' `
  --output text

if ([string]::IsNullOrEmpty($DB_PASSWORD)) {
    Write-Host "Failed to get database password" -ForegroundColor Red
    exit 1
}

Write-Host "Password retrieved`n" -ForegroundColor Green

Write-Host "Step 2: Getting your IP address..." -ForegroundColor Cyan
$MY_IP = (Invoke-RestMethod -Uri "https://checkip.amazonaws.com").Trim()
Write-Host "Your IP: $MY_IP`n" -ForegroundColor White

Write-Host "Step 3: Temporarily allowing your IP in RDS security group..." -ForegroundColor Cyan
try {
    aws ec2 authorize-security-group-ingress `
      --group-id sg-0dfffbf7f98f77a4c `
      --protocol tcp `
      --port 5432 `
      --cidr "$MY_IP/32" `
      --region eu-west-3 `
      --profile reply-sso 2>$null
    Write-Host "IP whitelisted`n" -ForegroundColor Green
} catch {
    Write-Host "IP might already be whitelisted (continuing...)`n" -ForegroundColor Yellow
}

Write-Host "Step 4: Initializing database schema...`n" -ForegroundColor Cyan

# Create Python init script
$PYTHON_SCRIPT = @'
import asyncio
import asyncpg
import sys

DB_HOST = "ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com"
DB_PORT = 5432
DB_USER = "postgres"
DB_NAME = "documents_db"

async def initialize_schema(password):
    try:
        print(f"Connecting to {DB_HOST}:{DB_PORT}/{DB_NAME}...")
        
        conn = await asyncpg.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=password,
            database=DB_NAME,
            ssl='require'
        )
        
        print("Connected!")
        print("\nCreating tables...")
        
        # Create documents table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                s3_key VARCHAR(500) UNIQUE NOT NULL,
                document_type VARCHAR(50) NOT NULL,
                file_name VARCHAR(255) NOT NULL,
                file_size INTEGER,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processing_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'pending',
                validation_score FLOAT,
                metadata JSONB,
                extracted_data JSONB,
                validation_details JSONB,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("Created documents table")
        
        # Create processing_logs table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS processing_logs (
                id SERIAL PRIMARY KEY,
                document_id INTEGER REFERENCES documents(id),
                agent_name VARCHAR(50) NOT NULL,
                action VARCHAR(100) NOT NULL,
                status VARCHAR(50) NOT NULL,
                details JSONB,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        print("Created processing_logs table")
        
        # Create indexes
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_s3_key ON documents(s3_key)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_date ON documents(processing_date)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_document_id ON processing_logs(document_id)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_agent ON processing_logs(agent_name)")
        print("Created indexes")
        
        # Verify
        tables = await conn.fetch("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('documents', 'processing_logs')
            ORDER BY table_name
        """)
        
        print(f"\nVerification: Found {len(tables)} tables")
        for table in tables:
            row_count = await conn.fetchval(f"SELECT COUNT(*) FROM {table['table_name']}")
            print(f"  - {table['table_name']}: {row_count} rows")
        
        await conn.close()
        print("\nDatabase schema initialized successfully!")
        return True
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python init_schema.py <password>")
        sys.exit(1)
    
    success = asyncio.run(initialize_schema(sys.argv[1]))
    sys.exit(0 if success else 1)
'@

# Save script to temp file
$PYTHON_SCRIPT | Out-File -FilePath "$env:TEMP\init_schema.py" -Encoding UTF8

# Run the init script
python "$env:TEMP\init_schema.py" $DB_PASSWORD

$INIT_RESULT = $LASTEXITCODE

Write-Host "`nStep 5: Removing temporary security group rule..." -ForegroundColor Cyan
try {
    aws ec2 revoke-security-group-ingress `
      --group-id sg-0dfffbf7f98f77a4c `
      --protocol tcp `
      --port 5432 `
      --cidr "$MY_IP/32" `
      --region eu-west-3 `
      --profile reply-sso 2>$null
    Write-Host "Temporary rule removed`n" -ForegroundColor Green
} catch {
    Write-Host "Rule already removed or doesn't exist`n" -ForegroundColor Yellow
}

if ($INIT_RESULT -eq 0) {
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "  INITIALIZATION COMPLETE!" -ForegroundColor Green
    Write-Host "=========================================`n" -ForegroundColor Green
    
    Write-Host "You can now test the API from CloudShell:" -ForegroundColor Cyan
    Write-Host 'curl -s -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \' -ForegroundColor White
    Write-Host '  -H "Content-Type: application/json" \' -ForegroundColor White
    Write-Host '  -d ''{"jsonrpc": "2.0", "method": "list_pending_documents", "params": {"limit": 5}, "id": 1}'' | jq ''.''' -ForegroundColor White
} else {
    Write-Host "=========================================" -ForegroundColor Red
    Write-Host "  INITIALIZATION FAILED" -ForegroundColor Red
    Write-Host "=========================================`n" -ForegroundColor Red
    exit 1
}

