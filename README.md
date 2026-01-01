# CA-A2A - Intelligent Document Processing Pipeline

**Version:** 1.0  
**Status:** ✅ Production Ready  
**Last Updated:** December 18, 2025

---

## 🎯 Overview

CA-A2A is a cloud-native, multi-agent document processing pipeline built on AWS. It automatically extracts, validates, and archives data from PDF and CSV documents using a distributed agent architecture.

### Key Features

- ✅ **Multi-Format Support:** PDF, CSV, TXT
- ✅ **Cloud-Native:** Built on AWS (ECS, RDS, S3, ALB)
- ✅ **Multi-Agent Architecture:** Orchestrator, Extractor, Validator, Archivist
- ✅ **Resilient:** Circuit breakers, retries, auto-recovery
- ✅ **Scalable:** Horizontal scaling, load balancing
- ✅ **Secure:** SSL/TLS, IAM roles, Secrets Manager, private networking

---

## 🚀 Quick Start

### Prerequisites

- AWS Account with SSO configured
- AWS CLI installed
- Access to AWS Console (eu-west-3 region)

### Test the System

1. Open **AWS CloudShell** in eu-west-3 region
2. Run this command:

```bash
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health | jq '.'
```

**Expected Response:**
```json
{
  "status": "healthy",
  "agent": "Orchestrator",
  "version": "1.0.0"
}
```

### Process a Document

```bash
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/process \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/sample_invoice.pdf"}'
```

---

## 📚 Documentation

### Core Documentation

| Document | Description | When to Use |
|----------|-------------|-------------|
| [📖 End-to-End Demo](./END_TO_END_DEMO.md) | Complete walkthrough with examples | **Start here** for first-time users |
| [🏗️ AWS Architecture](./AWS_ARCHITECTURE.md) | Infrastructure details and diagrams | Understanding the technical setup |
| [🎭 Scenario Flows](./SCENARIO_FLOWS.md) | Processing workflows and use cases | Understanding document processing |
| [🧪 Testing Guide](./TESTING_GUIDE.md) | AWS CloudShell & CLI testing | Testing and validation |

### Operational Documentation

| Document | Description |
|----------|-------------|
| [📋 API Testing Guide](./API_TESTING_GUIDE.md) | API endpoints and examples |
| [🧪 Test Results](./TEST_RESULTS.md) | Comprehensive test report (62/62 passed) |
| [📊 Demo Results](./FINAL_DEMO_RESULTS.md) | Latest deployment status |
| [✅ Deployment Success](./DEPLOYMENT_SUCCESS.md) | Issues fixed during deployment |
| [🏛️ Technical Architecture](./TECHNICAL_ARCHITECTURE.md) | A2A protocol and agent details |

### Supporting Documentation

| Document | Description |
|----------|-------------|
| [📄 Documentation Index](./DOCUMENTATION.md) | Complete documentation reference |
| [🏷️ AWS Tagging Guide](./docs/AWS_TAGGING_GUIDE.md) | Resource tagging strategy |
| [🎬 Demo Guide](./demo/DEMO_GUIDE.md) | Presentation-ready demo script |
| [📝 Pre-Demo Checklist](./demo/pre-demo-checklist.md) | Pre-flight checks |

---

## 🏗️ Architecture

```
┌──────────┐
│  Users   │
└────┬─────┘
     │
     ▼
┌────────────────┐
│ Application LB │ ← Internet-facing
└────┬───────────┘
     │
     ▼
┌────────────────┐
│  Orchestrator  │ ← Coordinates workflow
└────┬───────────┘
     │
     ├─────────┬──────────┐
     ▼         ▼          ▼
┌─────────┐ ┌────────┐ ┌──────────┐
│Extractor│ │Validator││Archivist │
└────┬────┘ └───┬────┘ └────┬─────┘
     │          │           │
     └──────────┴───────────┘
                │
        ┌───────┴────────┐
        ▼                ▼
    ┌──────┐      ┌──────────┐
    │  S3  │      │PostgreSQL│
    └──────┘      └──────────┘
```

---

## 🎯 Use Cases

### 1. Invoice Processing
- Extract invoice data (number, date, amounts, line items)
- Validate calculations (subtotal + tax = total)
- Archive to appropriate folder
- **Time:** 10-15 seconds

### 2. Contract Review
- Extract contract metadata (parties, dates, terms)
- Validate required clauses
- Check compliance
- **Time:** 15-20 seconds

### 3. Bulk CSV Processing
- Parse structured data
- Validate formats and ranges
- Store validated records
- **Time:** 5-10 seconds

---

## 💻 Technology Stack

### AWS Services
- **Compute:** ECS Fargate (8 tasks)
- **Storage:** S3, RDS PostgreSQL
- **Networking:** VPC, ALB, VPC Endpoints
- **Monitoring:** CloudWatch Logs & Metrics
- **Security:** IAM, Secrets Manager, Security Groups

### Application Stack
- **Language:** Python 3.9
- **Framework:** aiohttp (async)
- **Database:** asyncpg
- **Protocols:** A2A (JSON-RPC 2.0), MCP
- **Document Processing:** PyPDF2, pdfplumber, pandas

---

## 📊 Current Deployment

**Status:** ✅ All systems operational  
**Region:** eu-west-3 (Paris)  
**Account:** 555043101106  

| Component | Status | Count |
|-----------|--------|-------|
| ECS Services | ✅ ACTIVE | 4 |
| ECS Tasks | ✅ Running | 8 |
| ALB Targets | ✅ Healthy | 2 |
| RDS Instance | ✅ Available | 1 |
| S3 Buckets | ✅ Active | 1 |

---

## 🚦 Getting Started

1. **Read the Demo Guide:** [END_TO_END_DEMO.md](./END_TO_END_DEMO.md)
2. **Understand the Architecture:** [AWS_ARCHITECTURE.md](./AWS_ARCHITECTURE.md)
3. **Test via CloudShell:** [TESTING_GUIDE.md](./TESTING_GUIDE.md)
4. **Review Scenarios:** [SCENARIO_FLOWS.md](./SCENARIO_FLOWS.md)

---

## 💰 Cost

**Estimated Monthly Cost:** ~$80

- ECS Fargate: $40
- RDS PostgreSQL: $15
- Application Load Balancer: $16
- VPC Endpoints: $7.50
- S3 & CloudWatch: $1.50

*Can be optimized to ~$52/month by reducing task count*

---

## 🔒 Security

- ✅ Private subnets (no public IPs)
- ✅ VPC endpoints (no NAT gateway needed)
- ✅ SSL/TLS encryption in transit
- ✅ RDS encryption at rest
- ✅ IAM roles (no hard-coded credentials)
- ✅ Secrets Manager for passwords

---

## 📞 Support

- **AWS Account:** 555043101106
- **Region:** eu-west-3 (Paris)
- **Project:** CA-A2A
- **Contact:** j.benabderrazak@reply.com

---

## 📈 Metrics

- **Processing Time:** 5-20 seconds per document
- **Success Rate:** 95-99% depending on document type
- **Availability:** 99.9% (multi-AZ deployment)
- **Concurrent Processing:** Up to 8 documents simultaneously

---

## 🎓 Learn More

- [A2A Protocol Specification](./TECHNICAL_ARCHITECTURE.md#a2a-protocol)
- [MCP (Model Context Protocol)](./TECHNICAL_ARCHITECTURE.md#mcp)
- [Agent Architecture](./TECHNICAL_ARCHITECTURE.md#agent-architecture)
- [Deployment History](./AWS_DEPLOYMENT.md)

---

**Last Deployed:** December 18, 2025  
**Version:** 1.0  
**Status:** ✅ Production Ready
