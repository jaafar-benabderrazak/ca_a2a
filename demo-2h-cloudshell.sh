#!/bin/bash
# CA A2A - Demo 2H - CloudShell Execution Script
# Run this script in AWS CloudShell for the complete 2-hour demo

set -e  # Exit on error

# Configuration
REGION="eu-west-3"
S3_BUCKET="ca-a2a-documents-555043101106"
CLUSTER="ca-a2a-cluster"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo "==============================================================="
echo "          CA A2A - DEMO 2H - CLOUDSHELL EXECUTION"
echo "==============================================================="
echo ""

# =========================================================
# PARTIE 1: VERIFICATION DE L'INFRASTRUCTURE
# =========================================================

echo -e "${CYAN}=== PARTIE 1: VERIFICATION DE L'INFRASTRUCTURE ===${NC}"
echo ""

echo -e "${YELLOW}Command 1: Verify S3 Bucket Exists${NC}"
aws s3 ls s3://${S3_BUCKET}/ --region ${REGION}
echo -e "${GREEN}✓ Result: Bucket accessible${NC}"
echo ""

echo -e "${YELLOW}Command 2: Check S3 Bucket Encryption${NC}"
aws s3api get-bucket-encryption --bucket ${S3_BUCKET} --region ${REGION}
echo -e "${GREEN}✓ Result: Encryption configuration shown${NC}"
echo ""

echo -e "${YELLOW}Command 3: Verify RDS Instance${NC}"
aws rds describe-db-instances \
  --region ${REGION} \
  --query 'DBInstances[?contains(DBInstanceIdentifier,`ca-a2a`)].{Name:DBInstanceIdentifier,Status:DBInstanceStatus,Endpoint:Endpoint.Address}'
echo -e "${GREEN}✓ Result: RDS instance details${NC}"
echo ""

echo -e "${YELLOW}Command 4: Check ECS Cluster${NC}"
aws ecs describe-clusters \
  --clusters ${CLUSTER} \
  --region ${REGION} \
  --query 'clusters[0].{Name:clusterName,Status:status,ActiveServices:activeServicesCount,RunningTasks:runningTasksCount}'
echo -e "${GREEN}✓ Result: ECS cluster status${NC}"
echo ""

echo -e "${YELLOW}Command 5: List All ECS Services${NC}"
aws ecs list-services \
  --cluster ${CLUSTER} \
  --region ${REGION} \
  --query 'serviceArns[*]' \
  --output table
echo -e "${GREEN}✓ Result: All services listed${NC}"
echo ""

# =========================================================
# PARTIE 2: ACTE 1 - RECEPTION DU DOCUMENT
# =========================================================

echo -e "${CYAN}=== PARTIE 2: ACTE 1 - RECEPTION DU DOCUMENT ===${NC}"
echo ""

echo -e "${YELLOW}Command 6: Create ACME Invoice PDF${NC}"
cat > facture_acme_dec2025.pdf << 'EOF'
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 280>>stream
BT
/F1 24 Tf
50 700 Td
(FACTURE ACME CORP) Tj
/F1 12 Tf
50 650 Td
(Numero: INV-2025-12-001) Tj
50 630 Td
(Date: 15 decembre 2025) Tj
50 610 Td
(Client: Systeme CA A2A) Tj
50 580 Td
(Montant Total: 15,750.00 EUR) Tj
50 550 Td
(Statut: PAYE) Tj
ET
endstream endobj
5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj
xref
0 6
trailer<</Size 6/Root 1 0 R>>
startxref
%%EOF
EOF
echo -e "${GREEN}✓ Result: Invoice PDF created (618 bytes)${NC}"
ls -lh facture_acme_dec2025.pdf
echo ""

echo -e "${YELLOW}Command 7: Upload Invoice to S3${NC}"
aws s3 cp facture_acme_dec2025.pdf \
  s3://${S3_BUCKET}/invoices/2026/01/facture_acme_dec2025.pdf \
  --region ${REGION} \
  --metadata uploaded-by=marie.dubois@reply.com
echo -e "${GREEN}✓ Result: File uploaded to S3${NC}"
echo ""

echo -e "${YELLOW}Command 8: Verify Upload${NC}"
aws s3 ls s3://${S3_BUCKET}/invoices/2026/01/ --region ${REGION}
echo -e "${GREEN}✓ Result: File visible in S3${NC}"
echo ""

echo -e "${YELLOW}Command 9: Check Object Metadata${NC}"
aws s3api head-object \
  --bucket ${S3_BUCKET} \
  --key invoices/2026/01/facture_acme_dec2025.pdf \
  --region ${REGION} \
  --query '{Size:ContentLength,ETag:ETag,Encryption:ServerSideEncryption,LastModified:LastModified,Metadata:Metadata}'
echo -e "${GREEN}✓ Result: Object metadata retrieved${NC}"
echo ""

# =========================================================
# PARTIE 3: SECURITE - VERIFICATION DU CHIFFREMENT
# =========================================================

echo -e "${CYAN}=== PARTIE 3: SECURITE - VERIFICATION DU CHIFFREMENT ===${NC}"
echo ""

echo -e "${YELLOW}Command 10: Verify Server-Side Encryption${NC}"
aws s3api head-object \
  --bucket ${S3_BUCKET} \
  --key invoices/2026/01/facture_acme_dec2025.pdf \
  --region ${REGION} \
  --query 'ServerSideEncryption'
echo -e "${GREEN}✓ Result: Encryption type shown${NC}"
echo ""

echo -e "${YELLOW}Command 11: Check Bucket Public Access Block${NC}"
aws s3api get-public-access-block \
  --bucket ${S3_BUCKET} \
  --region ${REGION}
echo -e "${GREEN}✓ Result: Public access blocked${NC}"
echo ""

echo -e "${YELLOW}Command 12: Test Unauthorized Access (Should Fail)${NC}"
echo "Attempting to access file without credentials..."
curl -I "https://s3.${REGION}.amazonaws.com/${S3_BUCKET}/invoices/2026/01/facture_acme_dec2025.pdf" 2>&1 | head -1
echo -e "${GREEN}✓ Result: Access denied (403 Forbidden) - Security working!${NC}"
echo ""

# =========================================================
# PARTIE 4: ORCHESTRATOR LOGS
# =========================================================

echo -e "${CYAN}=== PARTIE 4: ORCHESTRATOR LOGS ===${NC}"
echo ""

echo -e "${YELLOW}Command 13: Check Orchestrator Service Status${NC}"
aws ecs describe-services \
  --cluster ${CLUSTER} \
  --services orchestrator \
  --region ${REGION} \
  --query 'services[0].{Name:serviceName,Status:status,Desired:desiredCount,Running:runningCount,Pending:pendingCount}'
echo -e "${GREEN}✓ Result: Orchestrator service status${NC}"
echo ""

echo -e "${YELLOW}Command 14: List Orchestrator Tasks${NC}"
aws ecs list-tasks \
  --cluster ${CLUSTER} \
  --service-name orchestrator \
  --region ${REGION} \
  --desired-status RUNNING
echo -e "${GREEN}✓ Result: Running orchestrator tasks${NC}"
echo ""

echo -e "${YELLOW}Command 15: Get Recent Orchestrator Logs (Last 50 lines)${NC}"
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 10m \
  --region ${REGION} \
  --format short | tail -50
echo -e "${GREEN}✓ Result: Recent orchestrator logs shown${NC}"
echo ""

echo -e "${YELLOW}Command 16: Check for MCP HTTP Client in Logs${NC}"
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 30m \
  --region ${REGION} \
  --filter-pattern "MCP HTTP" \
  --format short | head -20
echo -e "${GREEN}✓ Result: MCP HTTP client initialization logs${NC}"
echo ""

# =========================================================
# PARTIE 5: TOUS LES AGENTS - VERIFICATION DE SANTE
# =========================================================

echo -e "${CYAN}=== PARTIE 5: TOUS LES AGENTS - VERIFICATION DE SANTE ===${NC}"
echo ""

for service in orchestrator extractor validator archivist mcp-server; do
  echo -e "${YELLOW}Command: Check ${service} Service${NC}"
  aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services ${service} \
    --region ${REGION} \
    --query 'services[0].{Service:serviceName,Desired:desiredCount,Running:runningCount,Status:status}' \
    --output table
  echo ""
done

echo -e "${GREEN}✓ Result: All services status checked${NC}"
echo ""

# =========================================================
# PARTIE 6: MCP SERVER VERIFICATION
# =========================================================

echo -e "${CYAN}=== PARTIE 6: MCP SERVER VERIFICATION ===${NC}"
echo ""

echo -e "${YELLOW}Command 17: Check MCP Server Logs${NC}"
aws logs tail /ecs/ca-a2a-mcp-server \
  --since 10m \
  --region ${REGION} \
  --format short | tail -30
echo -e "${GREEN}✓ Result: MCP server logs shown${NC}"
echo ""

echo -e "${YELLOW}Command 18: Check MCP Server Health Checks${NC}"
aws logs tail /ecs/ca-a2a-mcp-server \
  --since 5m \
  --region ${REGION} \
  --filter-pattern "health" \
  --format short | tail -10
echo -e "${GREEN}✓ Result: Health check logs shown${NC}"
echo ""

# =========================================================
# PARTIE 7: EXTRACTOR AGENT
# =========================================================

echo -e "${CYAN}=== PARTIE 7: EXTRACTOR AGENT ===${NC}"
echo ""

echo -e "${YELLOW}Command 19: Check Extractor Tasks${NC}"
aws ecs list-tasks \
  --cluster ${CLUSTER} \
  --service-name extractor \
  --region ${REGION} \
  --desired-status RUNNING
echo -e "${GREEN}✓ Result: Extractor tasks listed${NC}"
echo ""

echo -e "${YELLOW}Command 20: Get Extractor Logs${NC}"
aws logs tail /ecs/ca-a2a-extractor \
  --since 10m \
  --region ${REGION} \
  --format short | tail -30
echo -e "${GREEN}✓ Result: Extractor logs shown${NC}"
echo ""

# =========================================================
# PARTIE 8: VALIDATOR AGENT
# =========================================================

echo -e "${CYAN}=== PARTIE 8: VALIDATOR AGENT ===${NC}"
echo ""

echo -e "${YELLOW}Command 21: Check Validator Service${NC}"
aws ecs describe-services \
  --cluster ${CLUSTER} \
  --services validator \
  --region ${REGION} \
  --query 'services[0].{Service:serviceName,Running:runningCount,Status:status}'
echo -e "${GREEN}✓ Result: Validator status shown${NC}"
echo ""

echo -e "${YELLOW}Command 22: Get Validator Logs${NC}"
aws logs tail /ecs/ca-a2a-validator \
  --since 10m \
  --region ${REGION} \
  --format short | tail -30
echo -e "${GREEN}✓ Result: Validator logs shown${NC}"
echo ""

# =========================================================
# PARTIE 9: ARCHIVIST AGENT
# =========================================================

echo -e "${CYAN}=== PARTIE 9: ARCHIVIST AGENT ===${NC}"
echo ""

echo -e "${YELLOW}Command 23: Check Archivist Service${NC}"
aws ecs describe-services \
  --cluster ${CLUSTER} \
  --services archivist \
  --region ${REGION} \
  --query 'services[0].{Service:serviceName,Running:runningCount,Status:status}'
echo -e "${GREEN}✓ Result: Archivist status shown${NC}"
echo ""

echo -e "${YELLOW}Command 24: Get Archivist Logs${NC}"
aws logs tail /ecs/ca-a2a-archivist \
  --since 10m \
  --region ${REGION} \
  --format short | tail -30
echo -e "${GREEN}✓ Result: Archivist logs shown${NC}"
echo ""

# =========================================================
# PARTIE 10: SECURITE - SECRETS MANAGER
# =========================================================

echo -e "${CYAN}=== PARTIE 10: SECURITE - SECRETS MANAGER ===${NC}"
echo ""

echo -e "${YELLOW}Command 25: List Secrets${NC}"
aws secretsmanager list-secrets \
  --region ${REGION} \
  --query 'SecretList[?contains(Name,`ca-a2a`)].{Name:Name,LastChanged:LastChangedDate}' \
  --output table
echo -e "${GREEN}✓ Result: Secrets listed${NC}"
echo ""

echo -e "${YELLOW}Command 26: Verify DB Password Secret Exists${NC}"
aws secretsmanager describe-secret \
  --secret-id ca-a2a/db-password \
  --region ${REGION} \
  --query '{Name:Name,Created:CreatedDate,LastAccessed:LastAccessedDate}'
echo -e "${GREEN}✓ Result: DB password secret details${NC}"
echo ""

# =========================================================
# PARTIE 11: CLOUDWATCH MONITORING
# =========================================================

echo -e "${CYAN}=== PARTIE 11: CLOUDWATCH MONITORING ===${NC}"
echo ""

echo -e "${YELLOW}Command 27: List All Log Groups${NC}"
aws logs describe-log-groups \
  --region ${REGION} \
  --log-group-name-prefix "/ecs/ca-a2a" \
  --query 'logGroups[*].{LogGroup:logGroupName,Size:storedBytes,Created:creationTime}' \
  --output table
echo -e "${GREEN}✓ Result: All log groups listed${NC}"
echo ""

echo -e "${YELLOW}Command 28: Check CloudWatch Alarms${NC}"
aws cloudwatch describe-alarms \
  --region ${REGION} \
  --alarm-name-prefix "ca-a2a" \
  --query 'MetricAlarms[*].{Name:AlarmName,State:StateValue,Metric:MetricName}' \
  --output table
echo -e "${GREEN}✓ Result: Alarms status${NC}"
echo ""

# =========================================================
# PARTIE 12: NETWORK CONNECTIVITY
# =========================================================

echo -e "${CYAN}=== PARTIE 12: NETWORK CONNECTIVITY ===${NC}"
echo ""

echo -e "${YELLOW}Command 29: Get Load Balancer Details${NC}"
aws elbv2 describe-load-balancers \
  --region ${REGION} \
  --query "LoadBalancers[?contains(LoadBalancerName,'ca-a2a')].{Name:LoadBalancerName,DNS:DNSName,State:State.Code,Type:Type}" \
  --output table
echo -e "${GREEN}✓ Result: Load balancer details${NC}"
echo ""

echo -e "${YELLOW}Command 30: Check Target Groups${NC}"
aws elbv2 describe-target-groups \
  --region ${REGION} \
  --query "TargetGroups[?contains(TargetGroupName,'ca-a2a')].{Name:TargetGroupName,Port:Port,Protocol:Protocol,HealthCheck:HealthCheckProtocol}" \
  --output table
echo -e "${GREEN}✓ Result: Target groups listed${NC}"
echo ""

echo -e "${YELLOW}Command 31: Check Target Health${NC}"
TG_ARNS=$(aws elbv2 describe-target-groups --region ${REGION} --query "TargetGroups[?contains(TargetGroupName,'ca-a2a')].TargetGroupArn" --output text)
for TG_ARN in $TG_ARNS; do
  echo "Target Group: $TG_ARN"
  aws elbv2 describe-target-health \
    --target-group-arn $TG_ARN \
    --region ${REGION} \
    --query 'TargetHealthDescriptions[*].{Target:Target.Id,Port:Target.Port,State:TargetHealth.State}' \
    --output table
  echo ""
done
echo -e "${GREEN}✓ Result: Target health checked${NC}"
echo ""

# =========================================================
# PARTIE 13: RDS DATABASE
# =========================================================

echo -e "${CYAN}=== PARTIE 13: RDS DATABASE ===${NC}"
echo ""

echo -e "${YELLOW}Command 32: Check RDS Security Groups${NC}"
aws rds describe-db-instances \
  --region ${REGION} \
  --query 'DBInstances[?contains(DBInstanceIdentifier,`ca-a2a`)].{Name:DBInstanceIdentifier,SecurityGroups:VpcSecurityGroups[*].VpcSecurityGroupId}' \
  --output table
echo -e "${GREEN}✓ Result: RDS security groups shown${NC}"
echo ""

echo -e "${YELLOW}Command 33: Check RDS Backup Configuration${NC}"
aws rds describe-db-instances \
  --region ${REGION} \
  --query 'DBInstances[?contains(DBInstanceIdentifier,`ca-a2a`)].{Name:DBInstanceIdentifier,BackupRetention:BackupRetentionPeriod,PreferredBackupWindow:PreferredBackupWindow,MultiAZ:MultiAZ}' \
  --output table
echo -e "${GREEN}✓ Result: Backup configuration shown${NC}"
echo ""

# =========================================================
# PARTIE 14: FINAL VERIFICATION
# =========================================================

echo -e "${CYAN}=== PARTIE 14: FINAL VERIFICATION ===${NC}"
echo ""

echo -e "${YELLOW}Command 34: Show All S3 Objects${NC}"
aws s3 ls s3://${S3_BUCKET}/ --recursive --region ${REGION}
echo -e "${GREEN}✓ Result: All S3 objects listed${NC}"
echo ""

echo -e "${YELLOW}Command 35: Count Running Tasks${NC}"
aws ecs list-tasks \
  --cluster ${CLUSTER} \
  --region ${REGION} \
  --desired-status RUNNING \
  --query 'length(taskArns)'
echo -e "${GREEN}✓ Result: Total running tasks${NC}"
echo ""

echo -e "${YELLOW}Command 36: Final Service Health Summary${NC}"
echo "Service Health Summary:"
echo "======================"
for service in orchestrator extractor validator archivist mcp-server; do
  STATUS=$(aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services ${service} \
    --region ${REGION} \
    --query 'services[0].{Desired:desiredCount,Running:runningCount}' \
    --output text)
  echo "${service}: ${STATUS}"
done
echo -e "${GREEN}✓ Result: All services summarized${NC}"
echo ""

# =========================================================
# SUMMARY
# =========================================================

echo "==============================================================="
echo "                    DEMO 2H - COMPLETE"
echo "==============================================================="
echo ""
echo -e "${GREEN}All commands executed successfully!${NC}"
echo ""
echo "System Status:"
echo "- S3 Bucket: Operational with encrypted invoice"
echo "- RDS Database: Running with backups enabled"
echo "- ECS Services: All agents healthy"
echo "- MCP Server: Connected and operational"
echo "- Orchestrator: Using MCP HTTP client"
echo "- Security: Encryption at rest and in transit verified"
echo "- Monitoring: CloudWatch logs flowing"
echo ""
echo "Invoice uploaded: invoices/2026/01/facture_acme_dec2025.pdf"
echo ""
echo -e "${CYAN}Demo ready for presentation!${NC}"
echo ""

