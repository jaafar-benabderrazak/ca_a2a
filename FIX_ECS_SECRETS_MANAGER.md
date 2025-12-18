# Fix ECS Tasks Unable to Access Secrets Manager

## Problem

ECS tasks running in private subnets cannot access AWS Secrets Manager to fetch the database password, resulting in:

```
ResourceInitializationError: unable to pull secrets or registry auth: 
unable to retrieve secret from asm: There is a connection issue between 
the task and AWS Secrets Manager.
```

## Root Cause

ECS tasks are deployed in **private subnets** with `assignPublicIp=DISABLED`. Without VPC endpoints, these tasks cannot reach AWS services like:
- **Secrets Manager** (to fetch DB password)
- **ECR** (to pull container images)
- **CloudWatch Logs** (to send logs)

## Solution: Create VPC Endpoints

VPC endpoints allow private resources to access AWS services without going through the internet.

### Quick Fix

**Option 1: Using Bash (Git Bash / WSL)**
```bash
./create-vpc-endpoints.sh
```

**Option 2: Using PowerShell**
```powershell
.\scripts\create-vpc-endpoints.ps1
```

### What the Script Does

1. **Finds route tables** for private subnets
2. **Configures security group** to allow HTTPS (port 443) from VPC
3. **Creates VPC endpoints** for:
   - Secrets Manager (Interface endpoint)
   - ECR API (Interface endpoint)
   - ECR DKR (Interface endpoint)
   - CloudWatch Logs (Interface endpoint)
   - S3 (Gateway endpoint - optional but recommended)
4. **Waits for endpoints** to become available
5. **Verifies** all endpoints are active

### After Creating Endpoints

1. **Wait 2-3 minutes** for DNS propagation
2. **Restart ECS services** to pick up the new endpoints:

```bash
# Option 1: Use the fix script
./fix-ecs-connectivity.sh

# Option 2: Manually restart each service
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service extractor \
    --force-new-deployment \
    --region eu-west-3

aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service validator \
    --force-new-deployment \
    --region eu-west-3

aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service archivist \
    --force-new-deployment \
    --region eu-west-3
```

3. **Verify tasks are running**:
```bash
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services extractor validator archivist \
    --region eu-west-3 \
    --query 'services[*].[serviceName,runningCount,desiredCount]' \
    --output table
```

## Verify VPC Endpoints

Check that endpoints exist and are available:

```bash
aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=vpc-086392a3eed899f72" \
    --region eu-west-3 \
    --query 'VpcEndpoints[*].[VpcEndpointId,ServiceName,State]' \
    --output table
```

Expected output should show:
- `com.amazonaws.eu-west-3.secretsmanager` - **available**
- `com.amazonaws.eu-west-3.ecr.api` - **available**
- `com.amazonaws.eu-west-3.ecr.dkr` - **available**
- `com.amazonaws.eu-west-3.logs` - **available**
- `com.amazonaws.eu-west-3.s3` - **available** (optional)

## Cost Considerations

- **Interface endpoints**: ~$7.20/month per endpoint + data transfer
- **Gateway endpoints**: Free (S3 and DynamoDB only)
- **Total estimated cost**: ~$30/month for all required endpoints

This is typically cheaper than NAT Gateway costs for high-traffic scenarios.

## Alternative: Use NAT Gateway

If you prefer not to use VPC endpoints, ensure:
1. NAT Gateway exists in public subnet
2. Private subnet route table routes `0.0.0.0/0` → NAT Gateway
3. Security group allows outbound HTTPS (443) to `0.0.0.0/0`

However, VPC endpoints are:
- **More secure** (traffic stays within AWS network)
- **More reliable** (no internet dependency)
- **Lower latency** (direct connection to AWS services)

## Troubleshooting

### Endpoints Created But Tasks Still Failing

1. **Check endpoint state**: Must be `available`, not `pending`
2. **Check security group**: Must allow HTTPS (443) from VPC CIDR
3. **Check DNS**: Wait 2-3 minutes after creation
4. **Check task logs**: Look for specific error messages

### View Task Logs

```bash
# Get task ID
TASK_ID=$(aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name extractor \
    --region eu-west-3 \
    --query 'taskArns[0]' \
    --output text)

# View logs
aws logs tail /ecs/ca-a2a-extractor \
    --follow \
    --region eu-west-3
```

### Check Task Status

```bash
aws ecs describe-tasks \
    --cluster ca-a2a-cluster \
    --tasks $TASK_ID \
    --region eu-west-3 \
    --query 'tasks[0].[lastStatus,stoppedReason,containers[0].reason]' \
    --output table
```

## References

- [AWS VPC Endpoints Documentation](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints.html)
- [ECS Task Networking](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-networking.html)
- [Secrets Manager VPC Endpoints](https://docs.aws.amazon.com/secretsmanager/latest/userguide/vpc-endpoint-overview.html)

