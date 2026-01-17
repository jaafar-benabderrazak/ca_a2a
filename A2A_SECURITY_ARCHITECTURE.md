# CA-A2A Security Architecture Documentation

**Version:** 6.0  
**Last Updated:** January 17, 2026  
**Aythor:** Jaafar BENABDERRAZAK
**Environment:** AWS ECS Fargate

---

## 📢 Documentation Structure Update

**This document has been reorganized for better maintainability and navigation.**

All detailed content is now in focused section documents:

👉 **[View Full Documentation Index →](docs/security/README.md)**

---

## Executive Summary

The CA-A2A (Crédit Agricole Agent-to-Agent) system implements enterprise-grade security through a defense-in-depth architecture with 10 independent security layers. The system is deployed on AWS ECS Fargate in a private VPC with Keycloak OAuth2/OIDC for centralized authentication, MCP Server for resource access control, and role-based access control.

**Key Security Features:**
- ✅ OAuth2/OIDC Authentication (Keycloak RS256 JWT)
- ✅ Token Binding (RFC 8473) - Cryptographic binding to TLS layer
- ✅ Centralized Resource Access (MCP Server for S3/RDS)
- ✅ Role-Based Access Control (RBAC) with fine-grained permissions
- ✅ Token Revocation with hybrid storage (PostgreSQL + in-memory cache)
- ✅ Replay Protection via JWT jti claim tracking
- ✅ Rate Limiting (300 req/min per principal)
- ✅ Network Isolation (Private VPC, Security Groups)
- ✅ Encryption at Rest & In Transit (TLS 1.2+, AES-256)
- ✅ Comprehensive Audit Logging (CloudWatch)
- ✅ Constant-Time Comparison (Timing attack prevention)

---

## Documentation Sections

### Core Architecture
1. **[System Architecture](docs/security/01-SYSTEM_ARCHITECTURE.md)** - Production deployment, component overview
2. **[Security Layers (Defense-in-Depth)](docs/security/02-SECURITY_LAYERS.md)** - 10-layer security model

### Authentication & Access Control
3. **[Authentication & Authorization](docs/security/03-AUTHENTICATION_AUTHORIZATION.md)** - Keycloak OAuth2, JWT, RBAC, token revocation
4. **[Resource Access Layer (MCP Server)](docs/security/04-RESOURCE_ACCESS_LAYER.md)** - Centralized S3/RDS gateway

### Infrastructure Security
5. **[Network Security](docs/security/05-NETWORK_SECURITY.md)** - VPC, security groups, network isolation
6. **[Data Security](docs/security/06-DATA_SECURITY.md)** - Encryption at rest/in-transit, secrets management

### Protocol & Application Security
7. **[Protocol Security (A2A)](docs/security/07-PROTOCOL_SECURITY.md)** - JSON-RPC 2.0, message validation, token binding, constant-time comparison

### Operations & Monitoring
8. **[Monitoring & Audit](docs/security/08-MONITORING_AUDIT.md)** - CloudWatch logs, security events
9. **[Threat Model & Defenses](docs/security/09-THREAT_MODEL_DEFENSES.md)** - Threat analysis, attack scenarios
10. **[Security Operations](docs/security/10-SECURITY_OPERATIONS.md)** - Incident response, token revocation workflows

### Reference
11. **[Implementation Reference](docs/security/11-IMPLEMENTATION_REFERENCE.md)** - File structure, configuration, glossary

---

## Quick Start

**New to the project?** Start here:
1. [System Architecture](docs/security/01-SYSTEM_ARCHITECTURE.md) - Understand the overall system
2. [Security Layers](docs/security/02-SECURITY_LAYERS.md) - Learn the defense-in-depth model
3. [Authentication & Authorization](docs/security/03-AUTHENTICATION_AUTHORIZATION.md) - See how auth works

**Looking for something specific?**
- JWT validation → [Section 3](docs/security/03-AUTHENTICATION_AUTHORIZATION.md#32-jwt-token-structure)
- Security groups → [Section 5](docs/security/05-NETWORK_SECURITY.md#52-security-groups)
- Token binding → [Section 7](docs/security/07-PROTOCOL_SECURITY.md#713-token-binding-rfc-8473)
- Incident response → [Section 10](docs/security/10-SECURITY_OPERATIONS.md)

---

## Document Maintenance

**Version Control:** All documentation is tracked in git. Version history available via `git log`.

**Structure:** Individual sections can be updated independently without affecting the entire documentation.

**Feedback:** For improvements or corrections, please create a pull request.

---

**End of Document**
