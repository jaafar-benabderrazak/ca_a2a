# AWS Tags Configuration for CA A2A Project
# Include this file in your Terraform configurations to ensure consistent tagging

locals {
  # Common tags applied to all resources
  common_tags = {
    Project             = "CA-A2A"
    Environment         = var.environment # or "Production"
    Owner               = "j.benabderrazak@reply.com"
    ManagedBy           = "Terraform"
    CostCenter          = "CA-Reply"
    Application         = "Agent-Based-Architecture"
    Version             = "1.0.0"
    DeploymentDate      = formatdate("YYYY-MM-DD", timestamp())
    BackupPolicy        = "Daily"
    Compliance          = "GDPR"
    DataClassification  = "Confidential"
  }

  # ECS-specific tags
  ecs_tags = merge(local.common_tags, {
    Component   = "Compute"
    ServiceType = "Agent"
  })

  # RDS-specific tags
  rds_tags = merge(local.common_tags, {
    Component        = "Database"
    DatabaseEngine   = "PostgreSQL"
    BackupRetention  = "30-days"
    MultiAZ          = "true"
    PerformanceInsights = "Enabled"
  })

  # S3-specific tags
  s3_tags = merge(local.common_tags, {
    Component    = "Storage"
    DataType     = "Documents"
    Encryption   = "AES256"
    Versioning   = "Enabled"
    Lifecycle    = "90-days-to-Glacier"
  })

  # ALB-specific tags
  alb_tags = merge(local.common_tags, {
    Component       = "LoadBalancer"
    InternetFacing  = "true"
    Protocol        = "HTTPS"
  })

  # VPC-specific tags
  vpc_tags = merge(local.common_tags, {
    Component    = "Network"
    NetworkTier  = "Production"
    CIDR         = "10.0.0.0/16"
  })

  # CloudWatch-specific tags
  cloudwatch_tags = merge(local.common_tags, {
    Component      = "Monitoring"
    LogRetention   = "30-days"
  })

  # ECR-specific tags
  ecr_tags = merge(local.common_tags, {
    Component      = "Container-Registry"
    ImageScanning  = "Enabled"
  })

  # IAM-specific tags
  iam_tags = merge(local.common_tags, {
    Component    = "Security"
    AccessLevel  = "Service"
  })

  # Agent-specific tags (for ECS services)
  orchestrator_tags = merge(local.ecs_tags, {
    AgentName = "orchestrator"
    AgentRole = "coordinator"
  })

  extractor_tags = merge(local.ecs_tags, {
    AgentName = "extractor"
    AgentRole = "data-extraction"
  })

  classifier_tags = merge(local.ecs_tags, {
    AgentName = "classifier"
    AgentRole = "document-classification"
  })

  qa_agent_tags = merge(local.ecs_tags, {
    AgentName = "qa-agent"
    AgentRole = "quality-assurance"
  })
}

# Example usage in Terraform resources:
#
# resource "aws_ecs_cluster" "main" {
#   name = "ca-a2a-cluster"
#   tags = local.ecs_tags
# }
#
# resource "aws_db_instance" "postgres" {
#   identifier = "ca-a2a-db"
#   tags       = local.rds_tags
# }
#
# resource "aws_s3_bucket" "documents" {
#   bucket = "ca-a2a-documents"
#   tags   = local.s3_tags
# }

