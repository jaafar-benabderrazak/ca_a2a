#!/bin/bash
REGION="eu-west-3"

echo "============================================"
echo "RETRIEVING DATABASE CREDENTIALS"
echo "============================================"
echo ""

# Get Archivist task definition
echo "1. Getting Archivist task definition..."
TASK_DEF=$(aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services archivist \
    --region ${REGION} \
    --query 'services[0].taskDefinition' \
    --output text)

echo "   Task definition: $TASK_DEF"
echo ""

# Get all environment variables
echo "2. Database credentials from environment variables:"
echo ""

aws ecs describe-task-definition \
    --task-definition ${TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].environment[?starts_with(name, `POSTGRES`)]' \
    --output table

echo ""
echo "3. Formatted connection string:"
echo ""

DB_HOST=$(aws ecs describe-task-definition \
    --task-definition ${TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`POSTGRES_HOST`].value' \
    --output text)

DB_PORT=$(aws ecs describe-task-definition \
    --task-definition ${TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`POSTGRES_PORT`].value' \
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

if [ -z "$DB_PORT" ]; then
    DB_PORT="5432"
fi

echo "   Host: $DB_HOST"
echo "   Port: $DB_PORT"
echo "   Database: $DB_NAME"
echo "   Username: $DB_USER"
echo "   Password: $DB_PASSWORD"

echo ""
echo "4. For RDS Query Editor:"
echo ""
echo "   → Use 'Password authentication'"
echo "   → Database instance: Find the one matching endpoint above"
echo "   → Database name: $DB_NAME"
echo "   → Database username: $DB_USER"
echo "   → Password: $DB_PASSWORD"

echo ""
echo "5. For psql command line:"
echo ""
echo "   export PGPASSWORD='$DB_PASSWORD'"
echo "   psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME"

echo ""
echo "============================================"
echo "✓ CREDENTIALS RETRIEVED"
echo "============================================"

