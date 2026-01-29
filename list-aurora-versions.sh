#!/bin/bash

AWS_REGION="us-east-1"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║     Available Aurora PostgreSQL Versions in ${AWS_REGION}              ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

echo "Fetching available engine versions..."
aws rds describe-db-engine-versions \
    --engine aurora-postgresql \
    --region ${AWS_REGION} \
    --query 'DBEngineVersions[?starts_with(EngineVersion, `15.`) || starts_with(EngineVersion, `14.`)].{Version:EngineVersion,Status:Status}' \
    --output table

echo ""
echo "Fetching available PostgreSQL versions (for Keycloak DB)..."
aws rds describe-db-engine-versions \
    --engine postgres \
    --region ${AWS_REGION} \
    --query 'DBEngineVersions[?starts_with(EngineVersion, `15.`) || starts_with(EngineVersion, `14.`)].{Version:EngineVersion,Status:Status}' \
    --output table
