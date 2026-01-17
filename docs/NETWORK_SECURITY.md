# CA-A2A Network Security

**Version:** 6.0  
**Last Updated:** January 17, 2026

---

## VPC Architecture

**CIDR:** 10.0.0.0/16  
**Region:** eu-west-3 (Paris)  
**Availability Zones:** 2 (eu-west-3a, eu-west-3b)

### Subnets

| Subnet | CIDR | Type | Purpose |
|--------|------|------|---------|
| Public 1 | 10.0.1.0/24 | Public | ALB, NAT Gateway (AZ-a) |
| Public 2 | 10.0.2.0/24 | Public | ALB, NAT Gateway (AZ-b) |
| Private 1 | 10.0.11.0/24 | Private | ECS agents (AZ-a) |
| Private 2 | 10.0.12.0/24 | Private | ECS agents (AZ-b) |

---

## Security Groups

### ALB Security Group
- **Inbound:** 0.0.0.0/0:443 (HTTPS), 0.0.0.0/0:80 (HTTP redirect)
- **Outbound:** Orchestrator SG:8001

### Orchestrator Security Group
- **Inbound:** ALB SG:8001
- **Outbound:** Extractor:8002, Validator:8003, Archivist:8004, Keycloak:8080, MCP:8000

### Agent Security Groups (Extractor/Validator/Archivist)
- **Inbound:** Orchestrator SG (respective ports)
- **Outbound:** Keycloak:8080, MCP:8000

### Keycloak Security Group
- **Inbound:** All agent SGs:8080
- **Outbound:** RDS:5432

### MCP Server Security Group
- **Inbound:** All agent SGs:8000
- **Outbound:** RDS:5432, 0.0.0.0/0:443 (S3)

### RDS Security Group
- **Inbound:** Keycloak SG:5432, MCP SG:5432
- **Outbound:** DENY (no outbound needed)

---

## Network Isolation

✅ **Private Subnets Only:** No public IPs for agents  
✅ **NAT Gateway:** Outbound-only internet access  
✅ **VPC Endpoints:** S3, Secrets Manager, CloudWatch (no internet routing)  
✅ **Service Discovery:** AWS Cloud Map (*.ca-a2a.local)

---

**Related:** [System Architecture](SYSTEM_ARCHITECTURE.md), [Security Layers](SECURITY_LAYERS_DEFENSE_IN_DEPTH.md)
