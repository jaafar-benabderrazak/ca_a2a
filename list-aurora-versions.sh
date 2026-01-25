#!/bin/bash
AWS_REGION="us-east-1"

echo "=== Checking Available Aurora PostgreSQL Versions in ${AWS_REGION} ==="
echo ""
echo "All available Aurora PostgreSQL versions:"
aws rds describe-db-engine-versions \
    --engine aurora-postgresql \
    --region ${AWS_REGION} \
    --query 'DBEngineVersions[*].EngineVersion' \
    --output text | tr '\t' '\n' | sort -V

echo ""
echo "Recommended latest stable versions:"
aws rds describe-db-engine-versions \
    --engine aurora-postgresql \
    --region ${AWS_REGION} \
    --query 'DBEngineVersions[-5:].EngineVersion' \
    --output table

