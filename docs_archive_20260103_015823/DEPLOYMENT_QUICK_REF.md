# Quick Deployment Reference Card

## 🚀 Part 1: Fix Archivist (3 minutes)

```bash
chmod +x deploy-archivist-fix.sh
./deploy-archivist-fix.sh
```

**Wait for:** `✓ ARCHIVIST DEPLOYMENT COMPLETE`

**Verify:**
```bash
aws ecs describe-services --cluster ca-a2a-cluster --services archivist \
  --region eu-west-3 --query 'services[0].[desiredCount,runningCount]'
# Expected: [2, 2]
```

---

## 🚀 Part 2: Setup S3 Event Pipeline (5 minutes)

```bash
chmod +x setup-s3-event-pipeline.sh
./setup-s3-event-pipeline.sh
```

**Wait for:** `✓ S3 EVENT PIPELINE SETUP COMPLETE`

**Verify:**
```bash
# Test upload
aws s3 cp facture_acme_dec2025.pdf \
  s3://ca-a2a-documents-555043101106/invoices/2026/01/test_$(date +%s).pdf \
  --region eu-west-3

# Watch processing (wait 10 seconds)
sleep 10
aws logs tail /aws/lambda/ca-a2a-s3-processor --since 1m --region eu-west-3
aws logs tail /ecs/ca-a2a-orchestrator --since 1m --region eu-west-3 | grep task_id
```

---

## ✅ Success Indicators

### Archivist Fixed:
```
✅ 2/2 tasks running
✅ Logs show: "Using MCP HTTP client"
✅ No DNS errors
```

### Pipeline Working:
```
✅ Upload triggers Lambda
✅ Lambda calls orchestrator
✅ Orchestrator creates task_id
✅ Document processed automatically
```

---

## 🔍 Quick Troubleshooting

**Archivist still failing?**
```bash
aws logs tail /ecs/ca-a2a-archivist --since 5m --region eu-west-3 | grep -E "Error|Failed"
```

**Lambda not triggering?**
```bash
aws sqs get-queue-attributes \
  --queue-url $(aws sqs get-queue-url --queue-name ca-a2a-document-uploads --region eu-west-3 --query QueueUrl --output text) \
  --attribute-names All --region eu-west-3
```

**Orchestrator not processing?**
```bash
aws logs tail /ecs/ca-a2a-orchestrator --since 5m --region eu-west-3 | tail -50
```

---

## 📊 Monitoring

```bash
# Watch everything
watch -n 5 'echo "Services:" && \
  aws ecs describe-services --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist mcp-server \
  --region eu-west-3 --query "services[*].[serviceName,runningCount]" --output table'
```

---

## 🎯 One-Liner Test

```bash
# Complete test: Upload and verify processing
aws s3 cp facture_acme_dec2025.pdf s3://ca-a2a-documents-555043101106/invoices/2026/01/test_$(date +%s).pdf --region eu-west-3 && sleep 15 && aws logs tail /ecs/ca-a2a-orchestrator --since 1m --region eu-west-3 | grep -E "task_id|process_document"
```

**Expected:** See `task_id=` in output

---

**Ready? Just run the scripts in order!** 🚀

