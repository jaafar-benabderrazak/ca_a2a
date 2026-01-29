#!/usr/bin/env python3
"""
CA-A2A Multi-Agent System - AWS CDK Deployment
Production-ready infrastructure with full security implementation

Usage:
    cdk deploy -c project_name=ca-a2a -c environment=prod -c region=eu-west-3

Context Options:
    project_name:         Project name prefix (default: ca-a2a)
    environment:          Environment name (default: prod)
    region:               AWS region (default: eu-west-3)
    existing_vpc_id:      Import existing VPC instead of creating new
    existing_cluster_name: Import existing ECS cluster
    skip_secrets:         Skip creating secrets (use existing)
    skip_rds:             Skip creating RDS databases
"""

import os
import aws_cdk as cdk
from stacks.ca_a2a_stack import CaA2aStack

app = cdk.App()

# Get configuration from context or environment
project_name = app.node.try_get_context("project_name") or os.getenv("PROJECT_NAME", "ca-a2a")
environment = app.node.try_get_context("environment") or os.getenv("ENVIRONMENT", "prod")
region = app.node.try_get_context("region") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION", "eu-west-3")

# Get AWS account from environment (CDK will resolve this)
account = os.getenv("CDK_DEFAULT_ACCOUNT") or os.getenv("AWS_ACCOUNT_ID")

# Create the main stack
stack = CaA2aStack(
    app,
    f"{project_name}-{environment}",
    stack_name=f"{project_name}-{environment}",
    description="CA-A2A Multi-Agent System - Complete Infrastructure with Security",
    env=cdk.Environment(
        region=region,
        account=account,
    ),
    project_name=project_name,
    env_name=environment,
)

# Apply standard tags
cdk.Tags.of(stack).add("Project", project_name)
cdk.Tags.of(stack).add("Environment", environment)
cdk.Tags.of(stack).add("ManagedBy", "aws-cdk")
cdk.Tags.of(stack).add("Version", "5.2.0")
cdk.Tags.of(stack).add("Security", "full-implementation")
cdk.Tags.of(stack).add("Owner", "Jaafar-Benabderrazak")

app.synth()
