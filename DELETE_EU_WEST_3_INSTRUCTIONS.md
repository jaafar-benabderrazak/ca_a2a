# Instructions for Deleting CA-A2A Deployment in eu-west-3

**Date:** January 29, 2026  
**Region:** eu-west-3 (Paris)  
**Account:** 555043101106

## Overview

This document provides instructions for completely removing all CA-A2A resources deployed in the eu-west-3 AWS region.

## ⚠️ WARNING

**This is a DESTRUCTIVE operation that CANNOT be undone!**

The deletion will permanently remove:
- All running ECS services and containers
- All RDS database clusters and their data
- All documents stored in S3 buckets
- All Docker images in ECR repositories
- All VPC networking infrastructure
- All CloudWatch logs
- All secrets in Secrets Manager
- All IAM roles

## Prerequisites

Before running the deletion, ensure:

1. **AWS Credentials**: You must have valid AWS credentials configured with permissions to delete resources
2. **Confirmation**: You are absolutely certain you want to delete everything
3. **Backup** (if needed): If any data needs to be saved, backup before proceeding

## AWS Credentials Setup

If you receive an "Invalid security token" error, configure your AWS credentials:

```powershell
# Option 1: Configure AWS CLI
aws configure

# Option 2: Set environment variables
$env:AWS_ACCESS_KEY_ID="your-access-key"
$env:AWS_SECRET_ACCESS_KEY="your-secret-key"
$env:AWS_DEFAULT_REGION="eu-west-3"

# Option 3: Use AWS SSO
aws sso login --profile your-profile
$env:AWS_PROFILE="your-profile"
```

## Deletion Methods

### Method 1: Automated PowerShell Script (Recommended)

Run the PowerShell deletion script:

```powershell
cd "c:\Users\j.benabderrazak\OneDrive - Reply\Bureau\work\CA\A2A\ca_a2a"
.\Delete-EuWest3-Deployment.ps1
```

When prompted, type `DELETE-EU-WEST-3` to confirm.

**Estimated time:** 10-15 minutes

### Method 2: Manual Deletion via AWS CLI

If the automated script has issues, follow these manual steps:

#### Step 1: Scale Down and Delete ECS Services (5 minutes)

```powershell
# Scale down all services to 0
aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --desired-count 0 --region eu-west-3
aws ecs update-service --cluster ca-a2a-cluster --service extractor --desired-count 0 --region eu-west-3
aws ecs update-service --cluster ca-a2a-cluster --service validator --desired-count 0 --region eu-west-3
aws ecs update-service --cluster ca-a2a-cluster --service archivist --desired-count 0 --region eu-west-3
aws ecs update-service --cluster ca-a2a-cluster --service keycloak --desired-count 0 --region eu-west-3
aws ecs update-service --cluster ca-a2a-cluster --service mcp-server --desired-count 0 --region eu-west-3

# Wait for tasks to drain (45 seconds)
Start-Sleep -Seconds 45

# Delete all services
aws ecs delete-service --cluster ca-a2a-cluster --service orchestrator --force --region eu-west-3
aws ecs delete-service --cluster ca-a2a-cluster --service extractor --force --region eu-west-3
aws ecs delete-service --cluster ca-a2a-cluster --service validator --force --region eu-west-3
aws ecs delete-service --cluster ca-a2a-cluster --service archivist --force --region eu-west-3
aws ecs delete-service --cluster ca-a2a-cluster --service keycloak --force --region eu-west-3
aws ecs delete-service --cluster ca-a2a-cluster --service mcp-server --force --region eu-west-3

# Wait for services to be deleted
Start-Sleep -Seconds 20

# Delete the cluster
aws ecs delete-cluster --cluster ca-a2a-cluster --region eu-west-3
```

#### Step 2: Delete Load Balancer and Target Groups (2 minutes)

```powershell
# Get ALB ARN
$ALB_ARN = aws elbv2 describe-load-balancers --region eu-west-3 --query 'LoadBalancers[?contains(LoadBalancerName, `ca-a2a`)].LoadBalancerArn' --output text

# Delete ALB
if ($ALB_ARN) {
    aws elbv2 delete-load-balancer --load-balancer-arn $ALB_ARN --region eu-west-3
}

# Wait for ALB to be deleted
Start-Sleep -Seconds 75

# Get and delete all target groups
$TG_ARNS = aws elbv2 describe-target-groups --region eu-west-3 --query 'TargetGroups[?contains(TargetGroupName, `ca-a2a`)].TargetGroupArn' --output text

if ($TG_ARNS) {
    foreach ($tg in ($TG_ARNS -split '\s+')) {
        aws elbv2 delete-target-group --target-group-arn $tg --region eu-west-3
    }
}
```

#### Step 3: Delete SQS Queues (1 minute)

```powershell
# Get SQS queue URLs
$QUEUE_URLS = aws sqs list-queues --region eu-west-3 --queue-name-prefix "ca-a2a" --query 'QueueUrls' --output text

if ($QUEUE_URLS) {
    foreach ($queue in ($QUEUE_URLS -split '\s+')) {
        aws sqs delete-queue --queue-url $queue --region eu-west-3
    }
}
```

#### Step 4: Delete RDS Clusters (10-15 minutes)

```powershell
# Get all RDS clusters
$RDS_CLUSTERS = aws rds describe-db-clusters --region eu-west-3 --query 'DBClusters[?contains(DBClusterIdentifier, `ca-a2a`) || contains(DBClusterIdentifier, `documents-db`) || contains(DBClusterIdentifier, `keycloak`)].DBClusterIdentifier' --output text

if ($RDS_CLUSTERS) {
    foreach ($cluster in ($RDS_CLUSTERS -split '\s+')) {
        Write-Host "Deleting RDS cluster: $cluster"
        
        # Get instances in cluster
        $INSTANCES = aws rds describe-db-clusters --region eu-west-3 --db-cluster-identifier $cluster --query 'DBClusters[0].DBClusterMembers[].DBInstanceIdentifier' --output text
        
        # Delete instances first
        if ($INSTANCES) {
            foreach ($instance in ($INSTANCES -split '\s+')) {
                aws rds delete-db-instance --db-instance-identifier $instance --skip-final-snapshot --region eu-west-3
            }
        }
        
        Start-Sleep -Seconds 15
        
        # Delete cluster
        aws rds delete-db-cluster --db-cluster-identifier $cluster --skip-final-snapshot --region eu-west-3
    }
}

# Wait for RDS deletion to progress
Start-Sleep -Seconds 150
```

#### Step 5: Delete S3 Buckets (2 minutes)

```powershell
# Get all CA-A2A buckets
$BUCKETS = aws s3api list-buckets --query 'Buckets[?contains(Name, `ca-a2a`)].Name' --output text

if ($BUCKETS) {
    foreach ($bucket in ($BUCKETS -split '\s+')) {
        Write-Host "Emptying and deleting bucket: $bucket"
        # Empty bucket
        aws s3 rm "s3://$bucket" --recursive --region eu-west-3
        # Delete bucket
        aws s3 rb "s3://$bucket" --region eu-west-3
    }
}
```

#### Step 6: Delete ECR Repositories (1 minute)

```powershell
# Get all ECR repos
$ECR_REPOS = aws ecr describe-repositories --region eu-west-3 --query 'repositories[?contains(repositoryName, `ca-a2a`)].repositoryName' --output text

if ($ECR_REPOS) {
    foreach ($repo in ($ECR_REPOS -split '\s+')) {
        Write-Host "Deleting ECR repository: $repo"
        aws ecr delete-repository --repository-name $repo --force --region eu-west-3
    }
}
```

#### Step 7: Delete CloudWatch Log Groups (1 minute)

```powershell
# Get all log groups
$LOG_GROUPS = aws logs describe-log-groups --region eu-west-3 --log-group-name-prefix "/ecs/ca-a2a" --query 'logGroups[].logGroupName' --output text

if ($LOG_GROUPS) {
    foreach ($logGroup in ($LOG_GROUPS -split '\s+')) {
        aws logs delete-log-group --log-group-name $logGroup --region eu-west-3
    }
}
```

#### Step 8: Delete Secrets (1 minute)

```powershell
# Get all secrets
$SECRETS = aws secretsmanager list-secrets --region eu-west-3 --query 'SecretList[?contains(Name, `ca-a2a`)].Name' --output text

if ($SECRETS) {
    foreach ($secret in ($SECRETS -split '\s+')) {
        Write-Host "Deleting secret: $secret"
        aws secretsmanager delete-secret --secret-id $secret --force-delete-without-recovery --region eu-west-3
    }
}
```

#### Step 9: Delete Service Discovery (1 minute)

```powershell
# Get namespace
$NAMESPACE_ID = aws servicediscovery list-namespaces --query 'Namespaces[?Name==`ca-a2a.local`].Id' --output text --region eu-west-3

if ($NAMESPACE_ID) {
    # Get and delete services
    $SERVICES = aws servicediscovery list-services --filters "Name=NAMESPACE_ID,Values=$NAMESPACE_ID" --query 'Services[].Id' --output text --region eu-west-3
    
    if ($SERVICES) {
        foreach ($svc in ($SERVICES -split '\s+')) {
            aws servicediscovery delete-service --id $svc --region eu-west-3
        }
    }
    
    Start-Sleep -Seconds 15
    
    # Delete namespace
    aws servicediscovery delete-namespace --id $NAMESPACE_ID --region eu-west-3
}
```

#### Step 10: Delete VPC Resources (5 minutes)

```powershell
# Get VPC ID
$VPC_ID = aws ec2 describe-vpcs --region eu-west-3 --filters "Name=tag:Name,Values=*ca-a2a*" --query 'Vpcs[0].VpcId' --output text

if ($VPC_ID -and $VPC_ID -ne "None") {
    Write-Host "Deleting VPC: $VPC_ID"
    
    # Delete VPC Endpoints
    $VPC_ENDPOINTS = aws ec2 describe-vpc-endpoints --region eu-west-3 --filters "Name=vpc-id,Values=$VPC_ID" --query 'VpcEndpoints[].VpcEndpointId' --output text
    if ($VPC_ENDPOINTS) {
        foreach ($endpoint in ($VPC_ENDPOINTS -split '\s+')) {
            aws ec2 delete-vpc-endpoints --vpc-endpoint-ids $endpoint --region eu-west-3
        }
        Start-Sleep -Seconds 30
    }
    
    # Delete NAT Gateways
    $NAT_GWS = aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID" "Name=state,Values=available" --query 'NatGateways[].NatGatewayId' --output text --region eu-west-3
    if ($NAT_GWS) {
        foreach ($natGw in ($NAT_GWS -split '\s+')) {
            $EIP = aws ec2 describe-nat-gateways --nat-gateway-ids $natGw --query 'NatGateways[0].NatGatewayAddresses[0].AllocationId' --output text --region eu-west-3
            aws ec2 delete-nat-gateway --nat-gateway-id $natGw --region eu-west-3
            if ($EIP -and $EIP -ne "None") {
                Start-Sleep -Seconds 45
                aws ec2 release-address --allocation-id $EIP --region eu-west-3
            }
        }
    }
    
    # Delete Security Groups (except default)
    $SGS = aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text --region eu-west-3
    if ($SGS) {
        foreach ($sg in ($SGS -split '\s+')) {
            aws ec2 delete-security-group --group-id $sg --region eu-west-3
        }
    }
    
    # Delete Subnets
    $SUBNETS = aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query 'Subnets[].SubnetId' --output text --region eu-west-3
    if ($SUBNETS) {
        foreach ($subnet in ($SUBNETS -split '\s+')) {
            aws ec2 delete-subnet --subnet-id $subnet --region eu-west-3
        }
    }
    
    # Delete Route Tables (except main)
    $RTS = aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" --query 'RouteTables[?Associations[0].Main!=`true`].RouteTableId' --output text --region eu-west-3
    if ($RTS) {
        foreach ($rt in ($RTS -split '\s+')) {
            aws ec2 delete-route-table --route-table-id $rt --region eu-west-3
        }
    }
    
    # Detach and Delete Internet Gateway
    $IGWS = aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --query 'InternetGateways[].InternetGatewayId' --output text --region eu-west-3
    if ($IGWS) {
        foreach ($igw in ($IGWS -split '\s+')) {
            aws ec2 detach-internet-gateway --internet-gateway-id $igw --vpc-id $VPC_ID --region eu-west-3
            aws ec2 delete-internet-gateway --internet-gateway-id $igw --region eu-west-3
        }
    }
    
    # Delete VPC
    aws ec2 delete-vpc --vpc-id $VPC_ID --region eu-west-3
}
```

#### Step 11: Delete IAM Roles (2 minutes)

```powershell
# Get all CA-A2A IAM roles
$IAM_ROLES = aws iam list-roles --query 'Roles[?contains(RoleName, `ca-a2a`)].RoleName' --output text

if ($IAM_ROLES) {
    foreach ($roleName in ($IAM_ROLES -split '\s+')) {
        Write-Host "Deleting IAM role: $roleName"
        
        # Detach managed policies
        $POLICIES = aws iam list-attached-role-policies --role-name $roleName --query 'AttachedPolicies[].PolicyArn' --output text
        if ($POLICIES) {
            foreach ($policy in ($POLICIES -split '\s+')) {
                aws iam detach-role-policy --role-name $roleName --policy-arn $policy
            }
        }
        
        # Delete inline policies
        $INLINE_POLICIES = aws iam list-role-policies --role-name $roleName --query 'PolicyNames' --output text
        if ($INLINE_POLICIES) {
            foreach ($policy in ($INLINE_POLICIES -split '\s+')) {
                aws iam delete-role-policy --role-name $roleName --policy-name $policy
            }
        }
        
        # Delete role
        aws iam delete-role --role-name $roleName
    }
}
```

### Method 3: AWS Console (Last Resort)

If CLI methods fail, use the AWS Console:

1. **ECS**: Go to ECS → Clusters → ca-a2a-cluster → Delete all services → Delete cluster
2. **RDS**: Go to RDS → Databases → Delete both Aurora clusters (skip final snapshot)
3. **S3**: Go to S3 → Find ca-a2a buckets → Empty → Delete
4. **EC2**: Go to EC2 → Load Balancers → Delete ca-a2a-alb
5. **EC2**: Go to EC2 → Target Groups → Delete ca-a2a target groups
6. **ECR**: Go to ECR → Repositories → Delete all ca-a2a repos
7. **CloudWatch**: Go to CloudWatch → Log groups → Delete /ecs/ca-a2a-* groups
8. **Secrets Manager**: Go to Secrets Manager → Delete ca-a2a secrets
9. **VPC**: Go to VPC → Delete endpoints, NAT gateways, subnets, route tables, internet gateway, VPC
10. **IAM**: Go to IAM → Roles → Delete ca-a2a roles
11. **Cloud Map**: Go to Cloud Map → Delete ca-a2a.local namespace
12. **SQS**: Go to SQS → Delete ca-a2a queues

## Verification

After deletion, verify all resources are gone:

```powershell
# Check ECS
aws ecs describe-clusters --clusters ca-a2a-cluster --region eu-west-3

# Check RDS
aws rds describe-db-clusters --region eu-west-3 --query 'DBClusters[?contains(DBClusterIdentifier, `ca-a2a`)]'

# Check S3
aws s3 ls | grep ca-a2a

# Check Load Balancers
aws elbv2 describe-load-balancers --region eu-west-3 --query 'LoadBalancers[?contains(LoadBalancerName, `ca-a2a`)]'
```

All commands should return empty results or "resource not found" errors.

## Troubleshooting

### Issue: "Resource has dependent objects"
**Solution:** Delete dependent resources first (e.g., delete services before cluster)

### Issue: "Cannot delete VPC - has dependencies"
**Solution:** Ensure all ENIs, endpoints, NAT gateways are deleted first

### Issue: "UnrecognizedClientException"
**Solution:** Configure valid AWS credentials (see Prerequisites section)

### Issue: RDS deletion takes too long
**Solution:** This is normal. RDS clusters can take 10-20 minutes to delete

## Estimated Total Time

- **Automated script:** 10-15 minutes
- **Manual CLI commands:** 30-40 minutes
- **AWS Console:** 60-90 minutes

## Post-Deletion

After successful deletion:

1. Verify no unexpected charges appear in AWS billing
2. Remove any local references to the deployment
3. Update documentation to reflect the deletion
4. Consider whether any backups need to be retained or deleted

## Rollback

**There is no rollback for this operation.** Once deleted, resources cannot be recovered. If you need the deployment again, you must redeploy from scratch using the deployment scripts.

## Support

If you encounter issues during deletion:

1. Check AWS CloudTrail for detailed error messages
2. Review AWS support documentation for specific resource types
3. Contact AWS Support if resources cannot be deleted

---

**Document Created:** January 29, 2026  
**Last Updated:** January 29, 2026  
**Author:** Jaafar Benabderrazak
