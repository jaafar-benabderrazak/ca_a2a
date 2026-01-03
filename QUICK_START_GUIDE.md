# 🚀 QUICK START GUIDE - CA-A2A System

**Status:** ✅ **100% OPERATIONAL** | **Last Updated:** January 3, 2026

---

## ⚡ Quick Commands

### Test Complete System
```bash
cd ~/ca_a2a
./comprehensive-system-test.sh
```

### Test Single Document
```bash
cd ~/ca_a2a
./test-full-pipeline.sh
```

### Check Service Health
```bash
# All services
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator extractor validator archivist \
    --region eu-west-3 \
    --query 'services[*].{Name:serviceName,Running:runningCount,Desired:desiredCount}' \
    --output table
```

### View Recent Logs
```bash
# Orchestrator
aws logs tail /ecs/ca-a2a-orchestrator --since 10m --region eu-west-3 --follow

# Extractor  
aws logs tail /ecs/ca-a2a-extractor --since 10m --region eu-west-3 --follow

# Archivist
aws logs tail /ecs/ca-a2a-archivist --since 10m --region eu-west-3 --follow

# Lambda
aws logs tail /aws/lambda/ca-a2a-s3-processor --since 10m --region eu-west-3 --follow
```

---

## 📊 System Architecture

```
S3 Upload → SQS → Lambda → Orchestrator → Extractor → Validator → Archivist → PostgreSQL
            (Event)  (API Key)    (RBAC)      (MCP)       (RBAC)      (MCP)     (Database)
```

**Processing Time:** < 1 second end-to-end

---

## 🔑 Key Components

| Component | Endpoint | Port | Status |
|-----------|----------|------|--------|
| Orchestrator | orchestrator.ca-a2a.local | 8001 | ✅ 2/2 |
| Extractor | extractor.ca-a2a.local | 8002 | ✅ 2/2 |
| Validator | validator.ca-a2a.local | 8003 | ✅ 2/2 |
| Archivist | archivist.ca-a2a.local | 8004 | ✅ 2/2 |
| Lambda | ca-a2a-s3-processor | - | ✅ Active |
| Database | documents-db | 5432 | ✅ Available |

---

## 🔒 Security Features

**Authentication:**
- ✅ API Key authentication (Lambda → Orchestrator)
- ✅ RBAC authorization (all agent communications)

**Check Security Config:**
```bash
# API Keys
aws ecs describe-task-definition \
    --task-definition ca-a2a-orchestrator \
    --region eu-west-3 \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_API_KEYS_JSON`]'

# RBAC Policy
aws ecs describe-task-definition \
    --task-definition ca-a2a-orchestrator \
    --region eu-west-3 \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_RBAC_POLICY_JSON`]'
```

---

## 💾 Database Access

### Get Credentials
```bash
# Password
aws secretsmanager get-secret-value \
    --secret-id "ca-a2a/db-password" \
    --region eu-west-3 \
    --query 'SecretString' \
    --output text

# Connection info
./get-db-credentials.sh
```

### Query via RDS Query Editor
1. Go to: https://eu-west-3.console.aws.amazon.com/rds/home?region=eu-west-3#query-editor:
2. Connect to **`documents-db`** cluster
3. Database: **`documents_db`**
4. Username: **`postgres`**
5. Run query:
```sql
SELECT * FROM documents ORDER BY created_at DESC;
```

---

## 📤 Upload Test Document

### Via S3 CLI
```bash
aws s3 cp your_invoice.pdf \
    s3://ca-a2a-documents-555043101106/invoices/2026/01/ \
    --region eu-west-3
```

### Via Script
```bash
cd ~/ca_a2a
./test-full-pipeline.sh  # Automatically creates and uploads test PDF
```

---

## 🔧 Troubleshooting

### Service Not Running
```bash
# Check task status
aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name <SERVICE_NAME> \
    --region eu-west-3 \
    --desired-status STOPPED \
    --query 'taskArns[0]' --output text | \
    xargs -I {} aws ecs describe-tasks \
    --cluster ca-a2a-cluster \
    --tasks {} \
    --region eu-west-3 \
    --query 'tasks[0].stoppedReason'
```

### Force Restart Service
```bash
# Stop all tasks (new ones will start automatically)
aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name <SERVICE_NAME> \
    --region eu-west-3 \
    --query 'taskArns[]' --output text | \
    xargs -I {} aws ecs stop-task \
    --cluster ca-a2a-cluster \
    --task {} \
    --region eu-west-3 \
    --reason "Manual restart"
```

### Check Logs for Errors
```bash
# Search for errors across all services
for SERVICE in orchestrator extractor validator archivist; do
    echo "=== $SERVICE ==="
    aws logs tail /ecs/ca-a2a-$SERVICE \
        --since 30m \
        --region eu-west-3 | grep -i error | tail -5
done
```

---

## 📈 Performance Monitoring

### Check Current Load
```bash
# Task count by service
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator extractor validator archivist \
    --region eu-west-3 \
    --query 'services[*].{Service:serviceName,Running:runningCount,Pending:pendingCount,Desired:desiredCount}' \
    --output table
```

### Document Processing Stats
```bash
# Count successful archivals
aws logs tail /ecs/ca-a2a-archivist \
    --since 1h \
    --region eu-west-3 | \
    grep "Successfully archived" | wc -l
```

---

## 🚀 Deployment

### Rebuild and Deploy Agent
```bash
cd ~/ca_a2a

# Example: Deploy updated Extractor
./build-and-deploy-cloudshell.sh
```

### Update Single Agent
```bash
# Force new deployment without code changes
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service <SERVICE_NAME> \
    --force-new-deployment \
    --region eu-west-3
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| **FINAL_STATUS_REPORT.md** | Complete system status and test results |
| **README.md** | Project overview |
| **SYSTEM_ARCHITECTURE.md** | Architecture details |
| **SECURITY_GUIDE.md** | Security implementation |
| **COMPLETE_TECHNICAL_DOCUMENTATION.md** | Full technical guide |

---

## ⚠️ Important Notes

1. **Database is in private VPC** - Cannot access from CloudShell directly
2. **Use RDS Query Editor** for database queries (see above)
3. **Native MCP** - No external MCP server needed
4. **API Keys** - Stored in environment variables
5. **Logs** - CloudWatch Logs, accessible via AWS CLI

---

## 🆘 Support

**Issues?** Check logs first:
```bash
./comprehensive-system-test.sh  # Comprehensive diagnostics
```

**Common Issues:**
- **401 Unauthorized:** Check API key configuration
- **500 Internal Error:** Check agent logs for stack traces
- **Timeout:** Check security groups and network connectivity
- **Database errors:** Verify RDS cluster is available

---

## ✅ System Health Checklist

```bash
# Quick health check
echo "🔍 Checking system health..."
echo ""
echo "Services:"
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator extractor validator archivist \
    --region eu-west-3 \
    --query 'services[*].{Name:serviceName,Health:runningCount}' \
    --output table

echo ""
echo "Lambda:"
aws lambda get-function \
    --function-name ca-a2a-s3-processor \
    --region eu-west-3 \
    --query '{Name:Configuration.FunctionName,State:Configuration.State}' \
    --output table

echo ""
echo "Database:"
aws rds describe-db-clusters \
    --region eu-west-3 \
    --db-cluster-identifier documents-db \
    --query '{Cluster:DBClusters[0].DBClusterIdentifier,Status:DBClusters[0].Status}' \
    --output table

echo ""
echo "✅ Health check complete!"
```

---

**Last Updated:** January 3, 2026  
**Version:** 1.0.0  
**Status:** ✅ Production Ready

