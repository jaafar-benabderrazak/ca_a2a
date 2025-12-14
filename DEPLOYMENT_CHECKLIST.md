# Production Deployment Checklist

## Pre-Deployment

### Code Quality
- [x] All agents implement BaseAgent contract
- [x] All skills have JSON schemas defined
- [x] Structured logging implemented
- [x] Error handling with retry logic
- [x] Circuit breakers for external calls
- [x] Timeouts on all async operations
- [x] Idempotency for write operations
- [x] Health checks include dependencies
- [ ] Unit tests for each skill (70%+ coverage)
- [ ] Integration tests for agent communication
- [ ] Load tests for performance baselines

### Configuration
- [ ] Environment-specific configs (.env per environment)
- [ ] Secrets in AWS Secrets Manager (not in code)
- [ ] IAM roles configured (no hardcoded keys)
- [ ] S3 bucket policies restrictive
- [ ] RDS security groups locked down
- [ ] VPC endpoints for S3 (private traffic)

### Documentation
- [x] README.md updated
- [x] Agent cards document all skills
- [x] AWS deployment guide complete
- [x] Best practices documented
- [ ] Runbook for common operations
- [ ] Incident response playbook
- [ ] Architecture diagrams current

## AWS Infrastructure

### Networking
- [ ] VPC created with public/private subnets
- [ ] NAT Gateway for private subnets
- [ ] Security groups configured per agent
- [ ] VPC endpoints for S3
- [ ] Network ACLs configured

### Compute (ECS Fargate)
- [ ] Task definitions created for each agent
- [ ] Task execution role configured
- [ ] Task role configured (for S3/RDS access)
- [ ] Container images pushed to ECR
- [ ] Health checks configured (use /health endpoint)
- [ ] Resource limits set (CPU, memory)
- [ ] Auto-scaling policies defined

### Storage
- [ ] RDS PostgreSQL provisioned
- [ ] Multi-AZ enabled for RDS
- [ ] Automated backups enabled (7-30 days)
- [ ] Performance Insights enabled
- [ ] S3 bucket created with versioning
- [ ] S3 lifecycle policies configured
- [ ] S3 encryption enabled (SSE-S3 or KMS)

### Load Balancing
- [ ] Application Load Balancer created
- [ ] Target groups for Orchestrator
- [ ] Health checks pointing to /health
- [ ] SSL/TLS certificate (ACM)
- [ ] HTTPS listener configured
- [ ] HTTP → HTTPS redirect

### Service Discovery
- [ ] AWS Cloud Map namespace created
- [ ] Service discovery for each agent
- [ ] DNS names configured (extractor.local, etc.)

### Secrets Management
- [ ] PostgreSQL password in Secrets Manager
- [ ] AWS credentials removed from config
- [ ] Task definitions reference secrets
- [ ] Secrets rotation enabled

### Monitoring
- [ ] CloudWatch Log Groups created
- [ ] Log retention policy set (7-30 days)
- [ ] CloudWatch alarms configured:
  - [ ] High CPU utilization
  - [ ] High memory utilization
  - [ ] ECS task failures
  - [ ] RDS CPU/connections
  - [ ] ALB 5xx errors
  - [ ] ALB response time
- [ ] CloudWatch Container Insights enabled
- [ ] SNS topic for alarms
- [ ] Email/Slack notifications configured

## Post-Deployment

### Smoke Tests
- [ ] Orchestrator health check returns 200
- [ ] Each agent /card endpoint accessible
- [ ] Agent discovery works (orchestrator)
- [ ] Process single document end-to-end
- [ ] Check document appears in PostgreSQL
- [ ] Verify logs in CloudWatch

### Performance Validation
- [ ] Baseline latency measured (p50, p95, p99)
- [ ] Throughput tested (documents/minute)
- [ ] Resource utilization acceptable (<70%)
- [ ] Database connections stable
- [ ] No memory leaks over 24h

### Monitoring Setup
- [ ] Dashboard created in CloudWatch
- [ ] Key metrics displayed:
  - Requests per agent per skill
  - Latency percentiles
  - Error rates
  - Circuit breaker states
  - Idempotency cache hits
- [ ] Log queries saved:
  - Errors by agent
  - Slow requests (>5s)
  - Correlation ID traces

### Documentation
- [ ] Deployment date recorded
- [ ] Version numbers documented
- [ ] Known issues listed
- [ ] Contact information updated
- [ ] On-call schedule created

## Operations

### Daily
- [ ] Check CloudWatch alarms
- [ ] Review error logs
- [ ] Monitor resource utilization
- [ ] Check database performance

### Weekly
- [ ] Review performance trends
- [ ] Check for cost anomalies
- [ ] Update capacity plan
- [ ] Security patch review

### Monthly
- [ ] Review and optimize costs
- [ ] Update dependencies
- [ ] Disaster recovery drill
- [ ] Capacity planning review

## Rollback Plan

### If Deployment Fails
1. [ ] ALB target group: drain connections
2. [ ] ECS: update service to previous task definition
3. [ ] Wait for tasks to reach healthy state
4. [ ] Verify with smoke tests
5. [ ] Document failure reason

### If Partial Failure
1. [ ] Identify failing agent
2. [ ] Scale down failing agent to 0
3. [ ] Other agents continue operation (degraded)
4. [ ] Fix and redeploy single agent
5. [ ] Scale back up

## Security

### Access Control
- [ ] IAM roles follow least privilege
- [ ] No SSH access to tasks (ECS Exec if needed)
- [ ] Secrets rotated regularly
- [ ] MFA enabled for AWS console

### Network Security
- [ ] Security groups whitelist only required ports
- [ ] RDS not publicly accessible
- [ ] S3 bucket not public
- [ ] WAF rules on ALB (optional)
- [ ] VPC Flow Logs enabled

### Compliance
- [ ] Data encryption at rest (S3, RDS)
- [ ] Data encryption in transit (TLS)
- [ ] Audit logs enabled (CloudTrail)
- [ ] Backup and retention policies
- [ ] GDPR/compliance requirements met

## Cost Optimization

### Current Estimate
- ECS Fargate (4 tasks): $30/month
- RDS PostgreSQL: $50/month
- ALB: $20/month
- S3: $5/month
- CloudWatch: $5/month
- **Total**: ~$110/month

### Optimization Opportunities
- [ ] Use Fargate Spot for dev/test (70% savings)
- [ ] RDS Reserved Instances for prod (40% savings)
- [ ] S3 lifecycle to Glacier after 90 days
- [ ] CloudWatch log retention = 7 days for dev
- [ ] Auto-scaling during off-hours

## Troubleshooting

### Common Issues

**Agent Not Responding**
- Check ECS task status
- Check health check endpoint
- Review CloudWatch logs
- Check security group rules

**Database Connection Errors**
- Verify RDS security group
- Check connection pool exhaustion
- Review RDS metrics
- Check secrets validity

**S3 Access Errors**
- Verify IAM role permissions
- Check bucket policies
- Test with VPC endpoint
- Review CloudTrail logs

**High Latency**
- Check resource utilization
- Review slow query logs
- Check network latency
- Enable X-Ray tracing

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | | | |
| DevOps | | | |
| Security | | | |
| Manager | | | |

---

**Deployment Date**: ___________  
**Version**: 1.0.0  
**Environment**: Production  
**Deployed By**: ___________
