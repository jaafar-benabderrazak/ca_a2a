#!/bin/bash

# Migration Runner Script
# Applies database migrations to RDS PostgreSQL cluster
# Usage: ./run_migration.sh [migration_file]

set -e

PROJECT_NAME="${PROJECT_NAME:-ca-a2a}"
REGION="${REGION:-eu-west-3}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "============================================"
echo "DATABASE MIGRATION RUNNER"
echo "============================================"
echo ""

# Get RDS cluster endpoint
echo "Retrieving RDS cluster information..."
CLUSTER_ENDPOINT=$(aws rds describe-db-clusters \
    --db-cluster-identifier ${PROJECT_NAME}-postgres \
    --region ${REGION} \
    --query 'DBClusters[0].Endpoint' \
    --output text)

if [ -z "$CLUSTER_ENDPOINT" ] || [ "$CLUSTER_ENDPOINT" == "None" ]; then
    echo -e "${RED}Error: Could not find RDS cluster endpoint${NC}"
    exit 1
fi

echo "RDS Endpoint: $CLUSTER_ENDPOINT"

# Get database credentials from Secrets Manager
echo "Retrieving database credentials..."
DB_SECRET=$(aws secretsmanager get-secret-value \
    --secret-id ${PROJECT_NAME}/db-password \
    --region ${REGION} \
    --query SecretString \
    --output text)

DB_PASSWORD="$DB_SECRET"
DB_USERNAME="${DB_USERNAME:-postgres}"
DB_NAME="${DB_NAME:-documents}"
DB_PORT="${DB_PORT:-5432}"

# Check if migration file is specified
MIGRATION_FILE="${1:-migrations/001_create_revoked_tokens_table.sql}"

if [ ! -f "$MIGRATION_FILE" ]; then
    echo -e "${RED}Error: Migration file not found: $MIGRATION_FILE${NC}"
    exit 1
fi

echo "Migration file: $MIGRATION_FILE"
echo ""

# Option 1: Using psql (if available)
if command -v psql &> /dev/null; then
    echo -e "${GREEN}Running migration using psql...${NC}"
    PGPASSWORD="$DB_PASSWORD" psql \
        -h "$CLUSTER_ENDPOINT" \
        -U "$DB_USERNAME" \
        -d "$DB_NAME" \
        -p "$DB_PORT" \
        -f "$MIGRATION_FILE"
    
    echo -e "${GREEN}✓ Migration completed successfully${NC}"
    exit 0
fi

# Option 2: Using Python (if psql not available)
if command -v python3 &> /dev/null; then
    echo -e "${YELLOW}psql not found, using Python...${NC}"
    
    python3 - <<EOF
import asyncpg
import asyncio
import sys

async def run_migration():
    try:
        # Read migration file
        with open('$MIGRATION_FILE', 'r') as f:
            sql = f.read()
        
        # Connect to database
        conn = await asyncpg.connect(
            host='$CLUSTER_ENDPOINT',
            port=$DB_PORT,
            user='$DB_USERNAME',
            password='$DB_PASSWORD',
            database='$DB_NAME'
        )
        
        # Execute migration
        await conn.execute(sql)
        
        print("${GREEN}✓ Migration completed successfully${NC}")
        
        await conn.close()
        return 0
    except Exception as e:
        print(f"${RED}Error running migration: {e}${NC}", file=sys.stderr)
        return 1

sys.exit(asyncio.run(run_migration()))
EOF
    
    exit $?
fi

# Option 3: Manual instructions
echo -e "${YELLOW}Neither psql nor Python available${NC}"
echo ""
echo "Please run the migration manually:"
echo "1. Connect to RDS using RDS Query Editor in AWS Console"
echo "2. Execute the contents of: $MIGRATION_FILE"
echo ""
echo "Or install psql:"
echo "  sudo apt-get install postgresql-client  # Ubuntu/Debian"
echo "  brew install postgresql                 # macOS"
echo ""
exit 1

