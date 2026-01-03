#!/bin/bash
REGION="eu-west-3"

echo "============================================"
echo "CHECKING RDS POSTGRESQL DATABASE"
echo "============================================"
echo ""

# Get RDS endpoint from environment
echo "1. Getting database connection info..."

# Check archivist task definition for DB credentials
TASK_DEF=$(aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services archivist \
    --region ${REGION} \
    --query 'services[0].taskDefinition' \
    --output text)

echo "   Task definition: $TASK_DEF"

# Extract DB connection details from task definition
DB_HOST=$(aws ecs describe-task-definition \
    --task-definition ${TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`POSTGRES_HOST`].value' \
    --output text)

DB_NAME=$(aws ecs describe-task-definition \
    --task-definition ${TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`POSTGRES_DB`].value' \
    --output text)

DB_USER=$(aws ecs describe-task-definition \
    --task-definition ${TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`POSTGRES_USER`].value' \
    --output text)

DB_PASSWORD=$(aws ecs describe-task-definition \
    --task-definition ${TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`POSTGRES_PASSWORD`].value' \
    --output text)

echo "   Database: $DB_NAME"
echo "   Host: $DB_HOST"
echo "   User: $DB_USER"

if [ -z "$DB_HOST" ] || [ -z "$DB_NAME" ]; then
    echo ""
    echo "   ✗ Could not retrieve database connection info from task definition"
    echo ""
    echo "   Trying to get from environment variables..."
    
    # Check ca-a2a-config.env
    if [ -f "ca-a2a-config.env" ]; then
        source ca-a2a-config.env
        DB_HOST=${POSTGRES_HOST:-$DB_HOST}
        DB_NAME=${POSTGRES_DB:-$DB_NAME}
        DB_USER=${POSTGRES_USER:-$DB_USER}
        DB_PASSWORD=${POSTGRES_PASSWORD:-$DB_PASSWORD}
        
        echo "   Database: $DB_NAME"
        echo "   Host: $DB_HOST"
        echo "   User: $DB_USER"
    fi
fi

if [ -z "$DB_HOST" ]; then
    echo ""
    echo "   ✗ Cannot proceed without database connection info"
    echo ""
    echo "   Please provide database details:"
    echo "   export POSTGRES_HOST=<your-rds-endpoint>"
    echo "   export POSTGRES_DB=<database-name>"
    echo "   export POSTGRES_USER=<username>"
    echo "   export POSTGRES_PASSWORD=<password>"
    exit 1
fi

echo ""
echo "2. Querying documents table..."
echo ""

# Use psql to query the database
export PGPASSWORD="$DB_PASSWORD"

# Check if psql is installed
if ! command -v psql &> /dev/null; then
    echo "   psql not installed. Installing..."
    sudo yum install -y postgresql15 2>/dev/null || sudo apt-get install -y postgresql-client 2>/dev/null
fi

echo "=== DOCUMENTS TABLE ==="
psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT 
    id,
    s3_key,
    status,
    validation_score,
    created_at,
    updated_at
FROM documents
ORDER BY created_at DESC
LIMIT 10;
" 2>&1

echo ""
echo "=== DOCUMENT COUNT BY STATUS ==="
psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT 
    status,
    COUNT(*) as count
FROM documents
GROUP BY status
ORDER BY count DESC;
" 2>&1

echo ""
echo "=== RECENT DOCUMENT DETAILS ==="
psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c "
SELECT 
    id,
    s3_key,
    status,
    validation_score,
    extracted_data::json->>'total_pages' as pages,
    extracted_data::json->>'format' as format,
    created_at
FROM documents
ORDER BY created_at DESC
LIMIT 5;
" 2>&1

# Unset password
unset PGPASSWORD

echo ""
echo "============================================"
echo "✓ DATABASE CHECK COMPLETE"
echo "============================================"

