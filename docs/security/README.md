# CA-A2A Security Architecture Documentation

**Version:** 6.0  
**Last Updated:** January 17, 2026  
**Status:** Production Deployed  
**Region:** eu-west-3 (Paris)  
**Environment:** AWS ECS Fargate

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

## Documentation Structure

This security architecture documentation is split into focused sections for better maintainability and navigation:

### Core Architecture

1. **[System Architecture](01-SYSTEM_ARCHITECTURE.md)**
   - Production deployment diagram
   - Component overview (Orchestrator, Extractor, Validator, Archivist, Keycloak, MCP Server)
   - AWS infrastructure setup

2. **[Security Layers (Defense-in-Depth)](02-SECURITY_LAYERS.md)**
   - 10-layer defense-in-depth model
   - Layer responsibilities and threat mitigation
   - Complete request security flow with all checkpoints

### Authentication & Access Control

3. **[Authentication & Authorization](03-AUTHENTICATION_AUTHORIZATION.md)**
   - Keycloak OAuth2/OIDC flow
   - JWT token structure and validation
   - Role-Based Access Control (RBAC) mapping
   - Token revocation architecture (hybrid PostgreSQL + in-memory cache)

4. **[Resource Access Layer (MCP Server)](04-RESOURCE_ACCESS_LAYER.md)**
   - MCP Server architecture and benefits
   - PostgreSQL connection pool management
   - S3 access management
   - Circuit breaker and retry logic

### Infrastructure Security

5. **[Network Security](05-NETWORK_SECURITY.md)**
   - VPC architecture (10.0.0.0/16)
   - Security groups configuration for all components
   - Private subnets and network isolation
   - VPC endpoints (Secrets Manager, S3, CloudWatch)
   - NAT Gateway setup

6. **[Data Security](06-DATA_SECURITY.md)**
   - Encryption at rest (AES-256, AWS KMS)
   - Encryption in transit (TLS 1.2+)
   - Secrets management (AWS Secrets Manager)
   - Key rotation policies

### Protocol & Application Security

7. **[Protocol Security (A2A)](07-PROTOCOL_SECURITY.md)**
   - Why JSON-RPC 2.0?
   - Protocol encapsulation (TLS → HTTP → JSON-RPC → Business Logic)
   - Message structure and anatomy
   - JSON Schema validation
   - Message size limits
   - Defense-in-depth at protocol level
   - Security Groups: Network-level enforcement
   - Token Binding (RFC 8473)
   - Constant-time comparison (timing attack prevention)
   - Security decorator pattern (future enhancement)

### Operations & Monitoring

8. **[Monitoring & Audit](08-MONITORING_AUDIT.md)**
   - CloudWatch Logs configuration
   - Security event logging
   - Query examples for security analysis
   - Metrics and dashboards

9. **[Threat Model & Defenses](09-THREAT_MODEL_DEFENSES.md)**
   - Identified threats and attack vectors
   - Defense mechanisms per threat
   - Attack scenario analysis
   - Security testing procedures

10. **[Security Operations](10-SECURITY_OPERATIONS.md)**
    - Incident response procedures
    - Token revocation workflows
    - Security patching and updates
    - Access control management
    - Audit log analysis

### Reference

11. **[Implementation Reference](11-IMPLEMENTATION_REFERENCE.md)**
    - File structure and key modules
    - Configuration examples
    - Environment variables reference
    - API endpoints for security operations
    - Glossary of security terms

---

## Quick Navigation by Topic

### Looking for specific information?

**Authentication:**
- JWT validation → [Section 3: Authentication & Authorization](03-AUTHENTICATION_AUTHORIZATION.md#32-jwt-token-structure)
- Keycloak setup → [Section 3: Authentication & Authorization](03-AUTHENTICATION_AUTHORIZATION.md#31-keycloak-oauth2oidc-flow)
- Token revocation → [Section 3: Authentication & Authorization](03-AUTHENTICATION_AUTHORIZATION.md#34-token-revocation)

**Network Security:**
- Security groups → [Section 5: Network Security](05-NETWORK_SECURITY.md#52-security-groups)
- VPC configuration → [Section 5: Network Security](05-NETWORK_SECURITY.md#51-vpc-architecture)

**Protocol Security:**
- JSON-RPC 2.0 → [Section 7: Protocol Security](07-PROTOCOL_SECURITY.md#71-why-json-rpc-20)
- Message validation → [Section 7: Protocol Security](07-PROTOCOL_SECURITY.md#74-json-schema-validation)
- Token binding → [Section 7: Protocol Security](07-PROTOCOL_SECURITY.md#713-token-binding-rfc-8473)

**Operations:**
- Incident response → [Section 10: Security Operations](10-SECURITY_OPERATIONS.md)
- Monitoring → [Section 8: Monitoring & Audit](08-MONITORING_AUDIT.md)
- Threat analysis → [Section 9: Threat Model & Defenses](09-THREAT_MODEL_DEFENSES.md)

---

## Document Maintenance

**Version Control:** All documentation is tracked in git. Version history is available via `git log`.

**Updates:** Each section maintains its own update history. Check individual files for section-specific changes.

**Feedback:** For documentation improvements or corrections, please create a pull request or contact the security team.

---

**End of Index**
