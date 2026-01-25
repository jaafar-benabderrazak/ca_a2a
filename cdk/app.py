#!/usr/bin/env python3
"""
CA-A2A Multi-Agent System - AWS CDK Deployment
Production-ready infrastructure with full security implementation
"""

import aws_cdk as cdk
from stacks.ca_a2a_stack import CaA2aStack

app = cdk.App()

# Get configuration from context or use defaults
project_name = app.node.try_get_context("project_name") or "ca-a2a"
environment = app.node.try_get_context("environment") or "prod"
region = app.node.try_get_context("region") or "us-east-1"

# Create the main stack
CaA2aStack(
    app, 
    f"{project_name}-{environment}",
    stack_name=f"{project_name}-{environment}",
    description="CA-A2A Multi-Agent System - Complete Infrastructure with Security",
    env=cdk.Environment(
        region=region,
        account=app.account
    ),
    project_name=project_name,
    environment=environment,
    tags={
        "Project": project_name,
        "Environment": environment,
        "ManagedBy": "aws-cdk",
        "Version": "5.1.0",
        "Security": "full-implementation",
        "Owner": "Jaafar-Benabderrazak"
    }
)

app.synth()

