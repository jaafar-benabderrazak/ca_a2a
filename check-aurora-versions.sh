#!/bin/bash

# Check available Aurora PostgreSQL versions

AWS_REGION="us-east-1"

echo "=== Available Aurora PostgreSQL Versions in ${AWS_REGION} ==="
echo ""

aws rds describe-db-engine-versions \
    --engine aurora-postgresql \
    --region ${AWS_REGION} \
    --query 'DBEngineVersions[*].{Version:EngineVersion,Status:Status}' \
    --output table | head -30

echo ""
echo "Latest versions (most recent 10):"
aws rds describe-db-engine-versions \
    --engine aurora-postgresql \
    --region ${AWS_REGION} \
    --query 'DBEngineVersions[-10:].EngineVersion' \
    --output table

