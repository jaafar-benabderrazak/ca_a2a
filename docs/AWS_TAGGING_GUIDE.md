# AWS Resource Tagging Guide for CA A2A Project

## Overview
This document describes the tagging strategy for all AWS resources in the CA A2A (Agent-Based Architecture) project. Consistent tagging enables cost tracking, resource management, and compliance monitoring.

## Mandatory Tags

All resources **must** include these tags:

| Tag Key | Tag Value | Purpose |
|---------|-----------|---------|
| `Project` | `CA-A2A` | Identifies resources belonging to this project |
| `Environment` | `Production` / `Staging` / `Development` | Deployment environment |
| `Owner` | `j.benabderrazak@reply.com` | Resource owner/contact |
| `ManagedBy` | `Terraform` | Infrastructure management method |
| `CostCenter` | `CA-Reply` | Cost allocation tracking |
| `Application` | `Agent-Based-Architecture` | Application identifier |
| `Version` | `1.0.0` | Application version |

## Optional Tags

Additional tags for enhanced tracking:

| Tag Key | Tag Value | Purpose |
|---------|-----------|---------|
| `DeploymentDate` | `YYYY-MM-DD` | Initial deployment date |
| `BackupPolicy` | `Daily` / `Weekly` | Backup schedule |
| `Compliance` | `GDPR` | Compliance requirements |
| `DataClassification` | `Confidential` / `Public` | Data sensitivity level |

## Resource-Specific Tags

### ECS Services
```json
{
  "Component": "Compute",
  "ServiceType": "Agent",
  "AgentName": "orchestrator|extractor|classifier|qa_agent",
  "AgentRole": "coordinator|data-extraction|document-classification|quality-assurance"
}
```

### RDS Database
```json
{
  "Component": "Database",
  "DatabaseEngine": "PostgreSQL",
  "BackupRetention": "30-days",
  "MultiAZ": "true",
  "PerformanceInsights": "Enabled"
}
```

### S3 Buckets
```json
{
  "Component": "Storage",
  "DataType": "Documents",
  "Encryption": "AES256",
  "Versioning": "Enabled",
  "Lifecycle": "90-days-to-Glacier"
}
```

### Application Load Balancer
```json
{
  "Component": "LoadBalancer",
  "InternetFacing": "true",
  "Protocol": "HTTPS"
}
```

### VPC & Network Resources
```json
{
  "Component": "Network",
  "NetworkTier": "Production",
  "CIDR": "10.0.0.0/16"
}
```

## Tagging Scripts

### PowerShell Scripts

1. **General Tagging Script**: `scripts/tag-aws-resources.ps1`
   - Tags all resources in the region
   - Uses Resource Groups Tagging API

2. **Resource-Specific Script**: `scripts/tag-specific-resources.ps1`
   - Tags resources by type (ECS, RDS, S3, ALB, etc.)
   - More granular control

### Usage

```powershell
# Tag all resources
.\scripts\tag-aws-resources.ps1

# Tag specific resource types
.\scripts\tag-specific-resources.ps1
```

### Terraform Integration

Include the `terraform/tags.tf` file in your Terraform configuration:

```hcl
# In your main.tf or resource files
resource "aws_ecs_cluster" "main" {
  name = "ca-a2a-cluster"
  tags = local.ecs_tags
}

resource "aws_ecs_service" "orchestrator" {
  name    = "orchestrator"
  cluster = aws_ecs_cluster.main.id
  tags    = local.orchestrator_tags
}
```

## Cost Allocation Tags

Enable these tags in AWS Billing Console for cost tracking:
- `Project`
- `Environment`
- `CostCenter`
- `Owner`
- `Component`
- `AgentName`

### Steps to Enable Cost Allocation Tags:

1. Go to AWS Billing Console
2. Navigate to Cost Allocation Tags
3. Activate the tags listed above
4. Wait 24 hours for tags to appear in Cost Explorer

## Tag Enforcement

### AWS Config Rules

Consider implementing AWS Config rules to enforce tagging:

```json
{
  "ConfigRuleName": "required-tags",
  "Description": "Ensures all resources have required tags",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "REQUIRED_TAGS"
  },
  "InputParameters": {
    "tag1Key": "Project",
    "tag2Key": "Environment",
    "tag3Key": "Owner",
    "tag4Key": "CostCenter"
  }
}
```

### Tag Policies (AWS Organizations)

If using AWS Organizations, create a tag policy:

```json
{
  "tags": {
    "Project": {
      "tag_key": {
        "@@assign": "Project"
      },
      "enforced_for": {
        "@@assign": [
          "ec2:instance",
          "rds:db",
          "s3:bucket",
          "ecs:cluster",
          "ecs:service"
        ]
      }
    }
  }
}
```

## Querying Resources by Tags

### AWS CLI Examples

```bash
# List all resources with Project=CA-A2A
aws resourcegroupstaggingapi get-resources \
  --region eu-west-3 \
  --tag-filters "Key=Project,Values=CA-A2A"

# List resources by environment
aws resourcegroupstaggingapi get-resources \
  --region eu-west-3 \
  --tag-filters "Key=Environment,Values=Production"

# Find all orchestrator resources
aws resourcegroupstaggingapi get-resources \
  --region eu-west-3 \
  --tag-filters "Key=AgentName,Values=orchestrator"
```

### PowerShell Examples

```powershell
# Get all CA-A2A resources
$resources = aws resourcegroupstaggingapi get-resources `
  --region eu-west-3 `
  --tag-filters "Key=Project,Values=CA-A2A" | ConvertFrom-Json

# Group by resource type
$resources.ResourceTagMappingList | Group-Object {
  if ($_.ResourceARN -match "arn:aws:([^:]+):") { $matches[1] }
} | Select-Object Name, Count
```

## Best Practices

1. ✅ **Apply tags at creation time** - Include tags when creating resources
2. ✅ **Use consistent naming** - Follow the tag schema exactly
3. ✅ **Automate tagging** - Use Terraform or CloudFormation
4. ✅ **Regular audits** - Review tags quarterly
5. ✅ **Cost allocation** - Enable tags in billing console
6. ✅ **Documentation** - Keep this guide updated
7. ✅ **Validation** - Use AWS Config or Tag Policies
8. ✅ **Team training** - Ensure all team members follow standards

## Tag Validation Checklist

Before deploying resources, verify:

- [ ] All mandatory tags are present
- [ ] Tag values follow naming conventions
- [ ] Cost allocation tags are enabled
- [ ] Resource-specific tags are applied
- [ ] Tags are applied via Terraform (if using IaC)
- [ ] Documentation is updated

## Monitoring and Reporting

### CloudWatch Metrics by Tags

Create CloudWatch dashboards filtering by tags:

```bash
aws cloudwatch get-metric-statistics \
  --namespace AWS/ECS \
  --metric-name CPUUtilization \
  --dimensions Name=ServiceName,Value=orchestrator \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z \
  --period 3600 \
  --statistics Average
```

### Cost Explorer Reports

1. Go to AWS Cost Explorer
2. Filter by tags: `Project = CA-A2A`
3. Group by: `Environment`, `Component`, `AgentName`
4. Create monthly reports

## Troubleshooting

### Tags Not Appearing in Billing

**Solution**: Tags can take up to 24 hours to appear after activation in the billing console.

### Unable to Tag Resource

**Solution**: Ensure you have appropriate IAM permissions:
```json
{
  "Effect": "Allow",
  "Action": [
    "tag:GetResources",
    "tag:TagResources",
    "tag:UntagResources"
  ],
  "Resource": "*"
}
```

### Inconsistent Tags Across Resources

**Solution**: Run the tagging scripts to standardize:
```powershell
.\scripts\tag-specific-resources.ps1
```

## Support

For questions or issues with tagging:
- **Owner**: j.benabderrazak@reply.com
- **Documentation**: This file
- **Scripts Location**: `scripts/` directory
- **Terraform Config**: `terraform/tags.tf`

---

**Last Updated**: 2024-12-14  
**Version**: 1.0.0  
**Maintained By**: CA Reply Team

