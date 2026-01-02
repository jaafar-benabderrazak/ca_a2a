# CA A2A - Demo 2H Quick Reference Card

Copy-paste these commands directly into AWS CloudShell (eu-west-3)

---

## SETUP (Run Once)

```bash
# Set variables
export REGION="eu-west-3"
export S3_BUCKET="ca-a2a-documents-555043101106"
export CLUSTER="ca-a2a-cluster"
```

---

## PART 1: Infrastructure Verification

```bash
# 1. Check S3 bucket
aws s3 ls s3://${S3_BUCKET}/ --region ${REGION}

# 2. Verify encryption
aws s3api get-bucket-encryption --bucket ${S3_BUCKET} --region ${REGION}

# 3. Check RDS
aws rds describe-db-instances --region ${REGION} \
  --query 'DBInstances[?contains(DBInstanceIdentifier,`ca-a2a`)].{Name:DBInstanceIdentifier,Status:DBInstanceStatus,Endpoint:Endpoint.Address}'

# 4. Check ECS cluster
aws ecs describe-clusters --clusters ${CLUSTER} --region ${REGION} \
  --query 'clusters[0].{Name:clusterName,Status:status,Services:activeServicesCount,Tasks:runningTasksCount}'

# 5. List services
aws ecs list-services --cluster ${CLUSTER} --region ${REGION}
```

---

## PART 2: Create and Upload Invoice

```bash
# 6. Create invoice PDF
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

# 7. Upload to S3
aws s3 cp facture_acme_dec2025.pdf \
  s3://${S3_BUCKET}/invoices/2026/01/facture_acme_dec2025.pdf \
  --region ${REGION} \
  --metadata uploaded-by=marie.dubois@reply.com

# 8. Verify upload
aws s3 ls s3://${S3_BUCKET}/invoices/2026/01/ --region ${REGION}

# 9. Check metadata
aws s3api head-object \
  --bucket ${S3_BUCKET} \
  --key invoices/2026/01/facture_acme_dec2025.pdf \
  --region ${REGION}
```

---

## PART 3: Security Verification

```bash
# 10. Check encryption
aws s3api head-object \
  --bucket ${S3_BUCKET} \
  --key invoices/2026/01/facture_acme_dec2025.pdf \
  --region ${REGION} \
  --query 'ServerSideEncryption'

# 11. Public access block
aws s3api get-public-access-block --bucket ${S3_BUCKET} --region ${REGION}

# 12. Test unauthorized access (should fail with 403)
curl -I "https://s3.${REGION}.amazonaws.com/${S3_BUCKET}/invoices/2026/01/facture_acme_dec2025.pdf"
```

---

## PART 4: Orchestrator Status

```bash
# 13. Service status
aws ecs describe-services \
  --cluster ${CLUSTER} \
  --services orchestrator \
  --region ${REGION} \
  --query 'services[0].{Name:serviceName,Status:status,Desired:desiredCount,Running:runningCount}'

# 14. List tasks
aws ecs list-tasks \
  --cluster ${CLUSTER} \
  --service-name orchestrator \
  --region ${REGION}

# 15. Recent logs
aws logs tail /ecs/ca-a2a-orchestrator --since 10m --region ${REGION} | tail -50

# 16. Check MCP HTTP client
aws logs tail /ecs/ca-a2a-orchestrator --since 30m --region ${REGION} --filter-pattern "MCP HTTP" | head -10
```

---

## PART 5: All Services Health Check

```bash
# Check all services at once
for service in orchestrator extractor validator archivist mcp-server; do
  echo "=== $service ==="
  aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services $service \
    --region ${REGION} \
    --query 'services[0].{Service:serviceName,Desired:desiredCount,Running:runningCount,Status:status}'
  echo ""
done
```

---

## PART 6: MCP Server

```bash
# 17. MCP server logs
aws logs tail /ecs/ca-a2a-mcp-server --since 10m --region ${REGION} | tail -30

# 18. Health checks
aws logs tail /ecs/ca-a2a-mcp-server --since 5m --region ${REGION} --filter-pattern "health" | tail -10
```

---

## PART 7: Extractor Agent

```bash
# 19. Extractor tasks
aws ecs list-tasks --cluster ${CLUSTER} --service-name extractor --region ${REGION}

# 20. Extractor logs
aws logs tail /ecs/ca-a2a-extractor --since 10m --region ${REGION} | tail -30
```

---

## PART 8: Validator Agent

```bash
# 21. Validator status
aws ecs describe-services \
  --cluster ${CLUSTER} \
  --services validator \
  --region ${REGION} \
  --query 'services[0].{Service:serviceName,Running:runningCount,Status:status}'

# 22. Validator logs
aws logs tail /ecs/ca-a2a-validator --since 10m --region ${REGION} | tail -30
```

---

## PART 9: Archivist Agent

```bash
# 23. Archivist status
aws ecs describe-services \
  --cluster ${CLUSTER} \
  --services archivist \
  --region ${REGION} \
  --query 'services[0].{Service:serviceName,Running:runningCount,Status:status}'

# 24. Archivist logs
aws logs tail /ecs/ca-a2a-archivist --since 10m --region ${REGION} | tail -30
```

---

## PART 10: Security - Secrets Manager

```bash
# 25. List secrets
aws secretsmanager list-secrets \
  --region ${REGION} \
  --query 'SecretList[?contains(Name,`ca-a2a`)].{Name:Name,LastChanged:LastChangedDate}'

# 26. DB password secret
aws secretsmanager describe-secret \
  --secret-id ca-a2a/db-password \
  --region ${REGION}
```

---

## PART 11: CloudWatch Monitoring

```bash
# 27. List log groups
aws logs describe-log-groups \
  --region ${REGION} \
  --log-group-name-prefix "/ecs/ca-a2a" \
  --query 'logGroups[*].{LogGroup:logGroupName,Size:storedBytes}'

# 28. Check alarms
aws cloudwatch describe-alarms \
  --region ${REGION} \
  --alarm-name-prefix "ca-a2a" \
  --query 'MetricAlarms[*].{Name:AlarmName,State:StateValue}'
```

---

## PART 12: Network Connectivity

```bash
# 29. Load balancer
aws elbv2 describe-load-balancers \
  --region ${REGION} \
  --query "LoadBalancers[?contains(LoadBalancerName,'ca-a2a')].{Name:LoadBalancerName,DNS:DNSName,State:State.Code}"

# 30. Target groups
aws elbv2 describe-target-groups \
  --region ${REGION} \
  --query "TargetGroups[?contains(TargetGroupName,'ca-a2a')].{Name:TargetGroupName,Port:Port,Protocol:Protocol}"

# 31. Target health
TG_ARNS=$(aws elbv2 describe-target-groups --region ${REGION} \
  --query "TargetGroups[?contains(TargetGroupName,'ca-a2a')].TargetGroupArn" --output text)
for TG_ARN in $TG_ARNS; do
  echo "=== Target Group: $(echo $TG_ARN | cut -d'/' -f2) ==="
  aws elbv2 describe-target-health \
    --target-group-arn $TG_ARN \
    --region ${REGION} \
    --query 'TargetHealthDescriptions[*].{Target:Target.Id,Port:Target.Port,State:TargetHealth.State}'
  echo ""
done
```

---

## PART 13: RDS Database

```bash
# 32. RDS security groups
aws rds describe-db-instances \
  --region ${REGION} \
  --query 'DBInstances[?contains(DBInstanceIdentifier,`ca-a2a`)].VpcSecurityGroups'

# 33. Backup configuration
aws rds describe-db-instances \
  --region ${REGION} \
  --query 'DBInstances[?contains(DBInstanceIdentifier,`ca-a2a`)].{Name:DBInstanceIdentifier,BackupRetention:BackupRetentionPeriod,MultiAZ:MultiAZ}'
```

---

## FINAL SUMMARY

```bash
# 34. All S3 objects
aws s3 ls s3://${S3_BUCKET}/ --recursive --region ${REGION}

# 35. Total running tasks
aws ecs list-tasks \
  --cluster ${CLUSTER} \
  --region ${REGION} \
  --desired-status RUNNING \
  --query 'length(taskArns)'

# 36. Service health summary
echo "=== SERVICE HEALTH SUMMARY ==="
for service in orchestrator extractor validator archivist mcp-server; do
  STATUS=$(aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services $service \
    --region ${REGION} \
    --query 'services[0].[desiredCount,runningCount]' \
    --output text)
  echo "$service: $STATUS"
done
```

---

## QUICK HIGHLIGHTS (For Narration)

### Security Features Demonstrated:
- ✅ S3 encryption at rest (AES-256)
- ✅ TLS 1.3 encryption in transit
- ✅ Private bucket (403 on unauthorized access)
- ✅ Secrets Manager for credentials
- ✅ VPC isolation (private subnets)
- ✅ IAM roles for service authentication

### Architecture Highlights:
- ✅ Multi-agent system (5 agents)
- ✅ Orchestrator with 2 tasks (HA)
- ✅ MCP HTTP client (fixed!)
- ✅ Service Discovery for inter-agent communication
- ✅ Load balancer for external access
- ✅ Multi-AZ RDS for data persistence

### Operational Excellence:
- ✅ CloudWatch logging (all agents)
- ✅ Health checks (all services)
- ✅ Automated backups (7-day retention)
- ✅ Multi-AZ deployment
- ✅ Container orchestration (ECS Fargate)

---

## Key Messages for Demo:

1. **"Voici notre système multi-agents CA A2A déployé sur AWS"**
2. **"Tous les agents sont opérationnels et sains"**
3. **"La sécurité est garantie à tous les niveaux - chiffrement, authentification, isolation"**
4. **"L'orchestrateur utilise maintenant le client MCP HTTP - problème résolu!"**
5. **"Le système est prêt à traiter des factures en toute sécurité"**

---

**Temps d'exécution estimé:** 10-15 minutes  
**Nombre de commandes:** 36  
**Taux de succès attendu:** 100%

🚀 **Prêt pour la démo!**
