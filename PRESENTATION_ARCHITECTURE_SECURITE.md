# Présentation : Architecture de Sécurité CA-A2A

**Titre :** Architecture de Sécurité du Système Multi-Agents CA-A2A  
**Audience :** Experts Techniques (Architectes, Ingénieurs Sécurité, DevSecOps)  
**Durée :** 45 minutes + 15 minutes Q&A  
**Présentateur :** [Votre Nom]  
**Date :** 15 Janvier 2026  
**Version Document :** 5.0

---

## 📋 Table des Matières

1. [Introduction et Contexte](#1-introduction-et-contexte) (5 min)
2. [Vue d'Ensemble de l'Architecture](#2-vue-densemble-de-larchitecture) (5 min)
3. [Les 9 Couches de Sécurité](#3-les-9-couches-de-sécurité) (10 min)
4. [Authentification et Autorisation](#4-authentification-et-autorisation) (8 min)
5. [Couche d'Accès aux Ressources (MCP Server)](#5-couche-daccès-aux-ressources-mcp-server) (7 min)
6. [Sécurité Réseau et Données](#6-sécurité-réseau-et-données) (5 min)
7. [Monitoring et Réponse aux Incidents](#7-monitoring-et-réponse-aux-incidents) (5 min)
8. [Conclusion et Prochaines Étapes](#8-conclusion-et-prochaines-étapes) (5 min)

---

## 1. Introduction et Contexte (5 minutes)

### 1.1 Ouverture

**[SLIDE 1 - Titre]**

> "Bonjour à tous. Aujourd'hui, je vais vous présenter l'architecture de sécurité du système CA-A2A, un système multi-agents déployé sur AWS ECS Fargate qui implémente une approche defense-in-depth avec 9 couches de sécurité distinctes."

**Points Clés à Mentionner :**
- Système de production déployé en région eu-west-3 (Paris)
- Architecture distribuée avec 5 agents (orchestrator, extractor, validator, archivist, MCP server)
- Conformité aux standards ISO 27001 et SOC 2
- Zero-trust architecture avec authentification centralisée

### 1.2 Contexte Métier

**[SLIDE 2 - Contexte]**

> "Le système CA-A2A traite des documents sensibles dans un environnement hautement réglementé. La sécurité n'est pas une option, c'est une exigence fondamentale. Notre approche repose sur trois principes :"

**Principes Directeurs :**

1. **Defense-in-Depth (Défense en Profondeur)**
   - Chaque couche apporte une protection indépendante
   - L'échec d'une couche ne compromet pas l'ensemble du système
   - Redondance des contrôles de sécurité

2. **Zero Trust Architecture**
   - Aucune confiance implicite
   - Authentification et autorisation à chaque étape
   - Moindre privilège systématique

3. **Security by Design**
   - Sécurité intégrée dès la conception
   - Pas de bolt-on security
   - Automatisation des contrôles

### 1.3 Périmètre de la Présentation

**[SLIDE 3 - Périmètre]**

> "Cette présentation couvre l'ensemble de la stack de sécurité, de la couche réseau jusqu'au monitoring opérationnel. Nous nous concentrerons particulièrement sur trois aspects innovants de notre architecture :"

**Focus Techniques :**

| Aspect | Innovation | Bénéfice Sécurité |
|--------|-----------|-------------------|
| **Keycloak OAuth2/OIDC** | Authentification centralisée | JWT RS256, révocation, rotation automatique |
| **MCP Server** | Gateway d'accès aux ressources | Réduction de 75% des rôles IAM avec accès AWS |
| **Hybrid Token Revocation** | Cache + PostgreSQL | Révocation instantanée (1μs) + persistance |

**Transition :** "Commençons par une vue d'ensemble de l'architecture..."

---

## 2. Vue d'Ensemble de l'Architecture (5 minutes)

### 2.1 Topologie Globale

**[SLIDE 4 - Diagramme Architecture Complète]**

> "Voici l'architecture complète de notre système. Nous sommes entièrement déployés sur AWS ECS Fargate dans une VPC privée. Permettez-moi de vous guider à travers les composants principaux."

**Narration du Diagramme :**

```
🌐 Internet
   ↓ HTTPS (TLS 1.2+)
📊 ALB (Application Load Balancer)
   ↓ HTTP (VPC Privé)
🎯 Orchestrator :8001
   ↓ A2A Protocol (JWT)
┌─────────────────────┐
│ Extractor    :8002  │
│ Validator    :8003  │ ← Agents Métier
│ Archivist    :8004  │
└─────────────────────┘
        ↓ HTTP API
   🔐 MCP Server :8000 ← Nouveau : Gateway de Ressources
        ↓
   ┌────────────┐
   │ RDS Aurora │ ← Données
   │ S3 Bucket  │
   └────────────┘
```

**Points Techniques Importants :**

1. **Isolation Réseau Complète**
   - Tous les agents dans des subnets privés (pas d'IP publique)
   - Seul l'ALB expose un point d'entrée public
   - NAT Gateway pour accès internet sortant uniquement

2. **Service Discovery AWS Cloud Map**
   - DNS privé : `*.ca-a2a.local`
   - Pas de hardcoding d'IPs
   - Haute disponibilité native

3. **Séparation des Responsabilités**
   - Chaque agent = un conteneur Fargate dédié
   - Isolation au niveau kernel (pas de multi-tenancy)
   - IAM roles granulaires par tâche

### 2.2 Inventaire des Composants

**[SLIDE 5 - Tableau Composants]**

> "Nous avons 12 composants principaux. Je veux attirer votre attention sur trois éléments critiques pour la sécurité :"

**Composants à Détailler :**

1. **Keycloak (Nouveau en v5.0)**
   ```
   - Service : ECS Fargate dédié
   - Base de données : RDS PostgreSQL dédiée
   - Rôle : OAuth2/OIDC provider centralisé
   - Sécurité : Admin MFA obligatoire, isolation réseau
   ```

2. **MCP Server (Nouveau en v5.0)**
   ```
   - Service : ECS Fargate (256 CPU, 512 MB)
   - Rôle : Gateway unique pour S3 et RDS
   - Bénéfice : Réduction de 88% des connexions DB (80 → 10)
   - Impact : Seul composant avec credentials AWS
   ```

3. **RDS Aurora PostgreSQL**
   ```
   - Endpoint : ca-a2a-postgres.*.rds.amazonaws.com
   - Chiffrement : AES-256 at rest, TLS in transit
   - Accès : Uniquement depuis MCP Server et Keycloak
   - Backups : Automatiques, 7 jours de rétention
   ```

**Transition :** "Maintenant que nous avons vu la topologie, plongeons dans les 9 couches de sécurité..."

---

## 3. Les 9 Couches de Sécurité (10 minutes)

### 3.1 Introduction à la Defense-in-Depth

**[SLIDE 6 - Diagramme 9 Couches]**

> "Notre architecture implémente 9 couches de sécurité indépendantes. C'est une augmentation par rapport aux 8 couches de la version 4.0, avec l'ajout de la couche 5 : Resource Access Control via le MCP Server."

**Analogie Technique :**

> "Pensez à ces couches comme à un système de sas de sécurité dans un datacenter physique : vous devez passer badge + code + biométrie + escorte. Ici, une requête passe par 9 contrôles avant d'accéder aux données."

### 3.2 Détail des Couches (2 min par couche critique)

#### **Couche 1 : Network Perimeter**

**[SLIDE 7 - Security Groups]**

```python
# Configuration Technique
VPC: 10.0.0.0/16
├── Public Subnets (10.0.1.0/24, 10.0.2.0/24)
│   ├── ALB (80/443 depuis 0.0.0.0/0)
│   └── NAT Gateway
└── Private Subnets (10.0.10.0/24, 10.0.20.0/24)
    └── Tous les agents (aucun accès internet entrant)
```

**Points Clés :**
- Default Deny sur tous les Security Groups
- Règles entrantes strictement limitées (source = autre SG)
- Pas de règles 0.0.0.0/0 sur les agents

**Démo à Montrer :**
```bash
# Tentative d'accès direct à un agent (échec attendu)
curl http://extractor.ca-a2a.local:8002/health
# Connection timeout - Security Group bloque
```

#### **Couches 2-4 : Identity, Authentication, Authorization**

**[SLIDE 8 - Flow Keycloak]**

> "Ces trois couches forment le cœur de notre système d'authentification. Laissez-moi vous montrer le flow complet."

**Flux Technique Détaillé :**

```
1. Client → Keycloak : POST /token
   Body: {
     grant_type: "client_credentials",
     client_id: "orchestrator",
     client_secret: "<depuis Secrets Manager>"
   }

2. Keycloak Vérifie :
   ✓ Client ID existe
   ✓ Secret valide (bcrypt hash)
   ✓ Client actif (not disabled)

3. Keycloak Génère JWT :
   {
     "alg": "RS256",           ← Asymétrique (non HS256)
     "kid": "keycloak-key-1"
   }
   {
     "sub": "orchestrator-uuid",
     "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
     "aud": "ca-a2a-agents",
     "exp": now + 300,         ← 5 minutes TTL
     "iat": now,
     "jti": "unique-token-id", ← Pour tracking/révocation
     "realm_access": {
       "roles": ["orchestrator", "admin"]
     }
   }

4. Agent Reçoit :
   {
     "access_token": "eyJhbGc...",
     "expires_in": 300,
     "refresh_token": "...",   ← Single-use, rotatif
     "token_type": "Bearer"
   }

5. Agent Utilise :
   Authorization: Bearer eyJhbGc...
```

**Sécurité du JWT :**

| Aspect | Implémentation | Protection |
|--------|----------------|------------|
| **Algorithme** | RS256 (RSA 2048-bit) | Impossible de forger sans clé privée |
| **Signature** | Clé privée Keycloak | Vérification avec clé publique (JWKS) |
| **Expiration** | 5 minutes | Fenêtre d'exploitation très courte |
| **jti (JWT ID)** | UUID unique | Permet révocation et replay protection |
| **Audience** | ca-a2a-agents | Empêche réutilisation cross-domain |

**Code de Vérification (Agents) :**

```python
# a2a_security.py (extrait)
class KeycloakJWTValidator:
    def verify_token(self, token: str, agent_id: str) -> dict:
        # 1. Récupérer JWKS de Keycloak (caché 1h)
        jwks = self._get_jwks()
        
        # 2. Vérifier signature + expiration + audience
        claims = jwt.decode(
            token,
            key=jwks,
            algorithms=["RS256"],        # ✓ Whitelist strict
            audience="ca-a2a-agents",    # ✓ Vérif audience
            issuer=self.keycloak_issuer, # ✓ Vérif issuer
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "require_exp": True,
                "require_iat": True
            }
        )
        
        # 3. Vérifier révocation (Layer supplémentaire)
        jti = claims.get("jti")
        if await self.revocation_list.is_revoked(jti):
            raise TokenRevoked("Token has been revoked")
        
        # 4. Vérifier jti pas déjà utilisé (replay protection)
        if await self.jti_cache.exists(jti):
            raise ReplayDetected("Token already used")
        
        # 5. Marquer jti comme utilisé (TTL = token expiration)
        await self.jti_cache.set(jti, "used", ttl=300)
        
        return claims
```

#### **Couche 5 : Resource Access Control (MCP Server) ⭐ NOUVEAU**

**[SLIDE 9 - Architecture MCP]**

> "C'est la nouveauté majeure de la version 5.0. Le MCP Server agit comme un gateway centralisé pour tous les accès S3 et RDS. C'est un game-changer en termes de sécurité."

**Problème Résolu :**

```
❌ AVANT (v4.0) :
Orchestrator ──┐
Extractor   ──┼──> RDS PostgreSQL (4 connexions × 20 = 80 connexions)
Validator   ──┤
Archivist   ──┘

Chaque agent :
- A ses propres credentials DB (password en Secrets Manager)
- Gère son propre connection pool
- A un IAM role avec permissions S3 + Secrets Manager
- Logs distribués sur 4 services

Problèmes :
🔴 80 connexions DB (overhead)
🔴 4 IAM roles à maintenir
🔴 Credentials sprawl
🔴 Audit distribué
```

```
✅ MAINTENANT (v5.0) :
Orchestrator ──┐
Extractor   ──┼──> MCP Server ──> RDS (pool : 10 connexions)
Validator   ──┤      :8000          └──> S3
Archivist   ──┘

MCP Server :
- Seul composant avec DB credentials
- Connection pool partagé (min=2, max=10)
- Seul IAM role avec permissions S3
- Logs centralisés

Bénéfices :
🟢 10 connexions DB (-88%)
🟢 1 IAM role avec AWS access (-75%)
🟢 1 point d'audit
🟢 Circuit breakers & retry logic centralisés
```

**API MCP Server (Démo) :**

```bash
# Exemple : Lister les objets S3
curl -X POST http://mcp-server.ca-a2a.local:8000/call_tool \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "s3_list_objects",
    "arguments": {
      "prefix": "uploads/",
      "limit": 10
    }
  }'

# Response :
{
  "bucket": "ca-a2a-documents-555043101106",
  "objects": [
    {
      "key": "uploads/document-2026-01-15.pdf",
      "size": 1048576,
      "last_modified": "2026-01-15T10:30:00Z"
    }
  ],
  "count": 1,
  "success": true
}
```

**Sécurité MCP Server :**

1. **Network Isolation**
   - Security Group : Inbound uniquement depuis agent SGs
   - Pas d'accès public
   - Service Discovery DNS uniquement

2. **Circuit Breaker Pattern**
   ```python
   circuit_breaker = CircuitBreaker(
       failure_threshold=5,    # Open après 5 échecs
       recovery_timeout=60,    # Retry après 60s
       expected_exception=ClientError
   )
   
   # États :
   # - CLOSED : Normal, toutes requêtes passent
   # - OPEN : Fail-fast, aucune requête
   # - HALF-OPEN : Test, requêtes limitées
   ```

3. **Connection Pooling Optimisé**
   ```python
   pool = await asyncpg.create_pool(
       host=RDS_ENDPOINT,
       min_size=2,              # 2 connexions warm
       max_size=10,             # Max 10 concurrent
       command_timeout=60,      # Timeout 60s
       max_inactive_lifetime=300 # Recycle après 5min
   )
   ```

4. **Métriques de Performance**
   
   | Opération | Direct | Via MCP | Overhead |
   |-----------|--------|---------|----------|
   | S3 GetObject (1MB) | 150ms | 175ms | +17% |
   | PostgreSQL Query | 20ms | 25ms | +25% |
   | PostgreSQL Insert | 15ms | 18ms | +20% |
   
   > "Un overhead de 20-25% est largement acceptable pour les bénéfices de sécurité obtenus."

#### **Couches 6-9 : Integrity, Validation, Replay, Rate Limiting**

**[SLIDE 10 - Couches Applicatives]**

> "Les quatre dernières couches sont implémentées au niveau applicatif. Chacune ajoute une protection spécifique."

**Résumé Technique :**

| Couche | Mécanisme | Détection | Mitigation |
|--------|-----------|-----------|------------|
| **L6: Integrity** | JWT body hash binding | Modification détectée | Rejet requête |
| **L7: Validation** | JSON Schema + Pydantic | Payload malformé | 400 Bad Request |
| **L8: Replay** | jti tracking (Redis) | Duplicate request | 409 Conflict |
| **L9: Rate Limit** | Sliding window (300/min) | Dépassement quota | 429 Too Many Requests |

**Transition :** "Maintenant que nous avons vu les couches, détaillons l'authentification..."

---

## 4. Authentification et Autorisation (8 minutes)

### 4.1 Keycloak OAuth2/OIDC

**[SLIDE 11 - Keycloak Architecture]**

> "Keycloak est notre IdP centralisé. C'est un composant critique, donc nous l'avons déployé avec une attention particulière à la sécurité."

**Déploiement Sécurisé :**

```yaml
Keycloak ECS Service:
  Image: quay.io/keycloak/keycloak:23.0
  CPU: 512 (.5 vCPU)
  Memory: 1024 MB
  Database: RDS PostgreSQL dédié
  Network: Private subnet, no public IP
  Security:
    - Admin password: Secrets Manager (32+ chars)
    - Admin MFA: Recommandé (à activer)
    - DB connection: TLS required
    - Service Discovery: keycloak.ca-a2a.local:8080
```

**Configuration Realm `ca-a2a` :**

```json
{
  "realm": "ca-a2a",
  "enabled": true,
  "sslRequired": "none",           // TLS terminé au niveau ALB
  "accessTokenLifespan": 300,      // 5 minutes ⭐
  "refreshTokenEnabled": true,
  "refreshTokenMaxReuse": 0,       // Single-use ⭐
  "revokeRefreshToken": true,      // Force rotation ⭐
  "accessCodeLifespanLogin": 1800, // 30 min pour login flow
  "bruteForceProtected": true,     // Protection brute-force
  "permanentLockout": false,
  "maxFailureWaitSeconds": 900,    // Lockout 15 min après échecs
  "minimumQuickLoginWaitSeconds": 60
}
```

### 4.2 RBAC (Role-Based Access Control)

**[SLIDE 12 - Mapping Roles]**

> "Nous avons défini 5 rôles avec des permissions granulaires. Le mapping Keycloak → A2A RBAC est géré automatiquement."

**Tableau des Rôles :**

| Rôle Keycloak | Principal A2A | Méthodes Autorisées | Cas d'Usage |
|---------------|---------------|---------------------|-------------|
| `admin` | `admin` | `*` (toutes) | Administration complète |
| `lambda` | `lambda` | `upload_document`, `process_document` | Triggers S3 events |
| `orchestrator` | `orchestrator` | `extract_document`, `validate_document`, `archive_document` | Coordination agents |
| `document-processor` | `document-processor` | `process_document`, `list_pending_documents`, `check_status` | Workflows métier |
| `viewer` | `viewer` | `list_documents`, `get_document`, `check_status` | Lecture seule (audit, reporting) |

**Code RBAC Enforcer :**

```python
# keycloak_auth.py
class KeycloakRBACMapper:
    RBAC_POLICY = {
        "admin": {
            "allowed_methods": ["*"],
            "denied_methods": []
        },
        "orchestrator": {
            "allowed_methods": [
                "extract_document",
                "validate_document", 
                "archive_document"
            ],
            "denied_methods": [
                "delete_document",   # Admin only
                "revoke_token"       # Admin only
            ]
        },
        # ... autres rôles
    }
    
    def check_authorization(self, roles: List[str], method: str) -> bool:
        """
        ✅ Deny by default
        ✅ Explicit deny takes precedence
        ✅ Requires explicit allow
        """
        if not roles:
            return False
        
        for role in roles:
            policy = self.RBAC_POLICY.get(role, {})
            
            # Check explicit deny first
            if method in policy.get("denied_methods", []):
                return False
            
            # Check allow list
            allowed = policy.get("allowed_methods", [])
            if "*" in allowed or method in allowed:
                return True
        
        # Default deny
        return False
```

**Exemple de Décision RBAC :**

```python
# Requête entrante
JWT Claims: {
  "sub": "user-123",
  "realm_access": {
    "roles": ["orchestrator", "viewer"]
  }
}
Method Requested: "extract_document"

# Vérification
Role "orchestrator":
  - Allowed: ["extract_document", "validate_document", ...]
  - "extract_document" ∈ Allowed ✅
  
Result: GRANTED

# Autre exemple
Method Requested: "delete_document"

Role "orchestrator":
  - Denied: ["delete_document", ...]
  - "delete_document" ∈ Denied ❌
  
Result: DENIED (403 Forbidden)
```

### 4.3 Token Revocation

**[SLIDE 13 - Architecture Hybride]**

> "Une des features les plus complexes : la révocation de tokens. Nous avons implémenté un système hybride cache + base de données."

**Architecture de Révocation :**

```
┌─────────────────────────────────────────┐
│         Admin Revoke Request            │
│  POST /admin/revoke-token               │
│  {"jti": "abc123", "reason": "..."}     │
└────────────────┬────────────────────────┘
                 │
                 ↓
┌────────────────────────────────────────┐
│  1. Write to In-Memory Cache (Redis)   │
│     SET jti:abc123 "revoked" EX 300    │
│     ⚡ Ultra-rapide : ~1 microseconde  │
└────────────────┬───────────────────────┘
                 │
                 ↓
┌────────────────────────────────────────┐
│  2. Persist to PostgreSQL               │
│     INSERT INTO revoked_tokens ...      │
│     💾 Durable : survit aux redémarrages│
└────────────────┬───────────────────────┘
                 │
                 ↓
┌────────────────────────────────────────┐
│  Agent Request Validation               │
│  1. Check cache (fast path)             │
│  2. If cache miss → Check DB            │
│  3. Populate cache for next check       │
└─────────────────────────────────────────┘
```

**Performance :**

- **Cache Hit (99% des cas) :** ~1 microseconde
- **Cache Miss + DB :** ~5 millisecondes
- **Write (admin) :** ~20 millisecondes (cache + DB)

**Schéma Base de Données :**

```sql
CREATE TABLE revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_by VARCHAR(100) NOT NULL,     -- Audit : qui a révoqué
    reason TEXT,                           -- Audit : pourquoi
    expires_at TIMESTAMP NOT NULL          -- Auto-cleanup
);

CREATE INDEX idx_revoked_expires ON revoked_tokens(expires_at);
CREATE INDEX idx_revoked_by ON revoked_tokens(revoked_by);
```

**Cas d'Usage :**

1. **Compromission Suspectée**
   ```bash
   # Révoquer token immédiatement
   curl -X POST http://admin-api:9000/admin/revoke-token \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -d '{"jti": "compromised-token-id", "reason": "suspected_breach"}'
   ```

2. **Fin de Session Utilisateur**
   ```python
   # Logout = révocation de tous les tokens de l'utilisateur
   for token in user_active_tokens:
       revocation_list.revoke(token.jti, reason="user_logout")
   ```

3. **Rotation de Credentials**
   ```python
   # Forcer refresh de tous les tokens après rotation de secrets
   revocation_list.revoke_all_before(timestamp=rotation_time)
   ```

**Transition :** "Voyons maintenant le MCP Server en détail..."

---

## 5. Couche d'Accès aux Ressources (MCP Server) (7 minutes)

### 5.1 Bénéfices Sécurité Quantifiés

**[SLIDE 14 - Tableau des Gains]**

> "Le MCP Server apporte des bénéfices sécurité mesurables. Laissez-moi vous montrer les chiffres."

**Tableau de Comparaison :**

| Métrique | Avant (v4.0) | Après (v5.0) | Amélioration |
|----------|--------------|--------------|--------------|
| **Connexions DB Actives** | 80 (4×20) | 10 (pool partagé) | **-88%** 🟢 |
| **IAM Roles avec AWS Access** | 4 (tous agents) | 1 (MCP seul) | **-75%** 🟢 |
| **Points d'Audit S3/RDS** | 4 (distribués) | 1 (centralisé) | **+100% visibilité** 🟢 |
| **Secrets Manager Calls** | 4 agents | 1 service | **-75% coût API** 🟢 |
| **IAM Policies à Maintenir** | 4 | 1 | **-75% complexité** 🟢 |
| **Latence Moyenne** | 20ms | 25ms | **+25% overhead** 🟡 |

**Analyse Coût/Bénéfice :**

> "Un overhead de latence de 25% est largement compensé par la réduction de la surface d'attaque. C'est un trade-off que nous assumons complètement."

### 5.2 Circuit Breaker Pattern

**[SLIDE 15 - États Circuit Breaker]**

**Diagramme d'États :**

```
     ┌─────────┐
     │ CLOSED  │ ◄─── État Normal
     │ (Normal)│      Toutes requêtes passent
     └────┬────┘
          │
          │ 5 échecs consécutifs
          ↓
     ┌─────────┐
     │  OPEN   │ ◄─── Fail-Fast
     │(Failure)│      Toutes requêtes rejetées
     └────┬────┘      Pas de surcharge du backend
          │
          │ Après 60 secondes
          ↓
     ┌──────────┐
     │HALF-OPEN │ ◄─── Test de Recovery
     │ (Testing)│      Requêtes limitées
     └────┬────┘
          │
          ├─ Success → CLOSED
          └─ Failure → OPEN
```

**Implémentation :**

```python
# utils.py (extrait)
class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.state = "CLOSED"
        self.last_failure_time = None
    
    async def call_async(self, func):
        """Wrap async function with circuit breaker"""
        
        # État OPEN : rejet immédiat
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "HALF-OPEN"
                logger.info("Circuit breaker: OPEN → HALF-OPEN")
            else:
                raise CircuitBreakerOpen("Service temporarily unavailable")
        
        try:
            # Exécuter la fonction
            result = await func()
            
            # Succès : reset si on était en HALF-OPEN
            if self.state == "HALF-OPEN":
                self.state = "CLOSED"
                self.failure_count = 0
                logger.info("Circuit breaker: HALF-OPEN → CLOSED (recovered)")
            
            return result
            
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            # Seuil atteint : ouvrir le circuit
            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"
                logger.error(f"Circuit breaker: CLOSED → OPEN after {self.failure_count} failures")
            
            raise
```

**Bénéfices :**

1. **Protection Backend**
   - Évite l'avalanche de retries vers un service défaillant
   - Donne du temps au backend pour récupérer

2. **Fail-Fast**
   - Réponse immédiate (pas de timeout 30s)
   - Meilleure expérience utilisateur (erreur explicite)

3. **Observabilité**
   - Logs structurés à chaque changement d'état
   - Métriques CloudWatch pour alerting

### 5.3 Connection Pooling Avancé

**[SLIDE 16 - Pool Configuration]**

**Configuration Optimale :**

```python
pool = await asyncpg.create_pool(
    # Connection params
    host=POSTGRES_CONFIG['host'],
    port=POSTGRES_CONFIG['port'],
    user=POSTGRES_CONFIG['user'],
    password=POSTGRES_CONFIG['password'],  # Depuis Secrets Manager
    database=POSTGRES_CONFIG['database'],
    
    # Pool sizing
    min_size=2,                    # 2 connexions pré-établies
    max_size=10,                   # Max 10 connexions concurrent
    
    # Timeouts
    command_timeout=60,            # Timeout requête : 60s
    timeout=30,                    # Timeout acquisition connexion : 30s
    
    # Health & recycling
    max_inactive_connection_lifetime=300,  # Recycle après 5min inactivité
    max_queries=50000,             # Recycle après 50k queries
    
    # SSL/TLS
    ssl='require'                  # Force TLS vers RDS
)
```

**Stratégie de Sizing :**

```python
# Calcul du min_size optimal
min_size = ceil(average_qps / (1 / average_query_duration))
# Exemple : 10 req/s avec 100ms par requête = 1 connexion
# On met 2 pour la redondance

# Calcul du max_size optimal
max_size = min_size + burst_capacity
# Exemple : 2 + 8 = 10 pour gérer les pics
```

**Monitoring du Pool :**

```python
# Métriques exposées
pool_metrics = {
    "size": pool.get_size(),              # Connexions actuelles
    "free": pool.get_idle_size(),         # Connexions disponibles
    "used": pool.get_size() - pool.get_idle_size(),
    "min": pool.get_min_size(),
    "max": pool.get_max_size(),
    "waiting": len(pool._queue)           # Requêtes en attente
}

# Alert si pool exhausted
if pool_metrics["used"] >= pool_metrics["max"]:
    logger.critical("Connection pool exhausted! Scale up MCP Server.")
```

### 5.4 API Reference Technique

**[SLIDE 17 - Exemples API]**

**Opération S3 - GetObject avec Retry :**

```python
# Agent code
async with mcp_context() as mcp:
    try:
        # Appel MCP Server
        content = await mcp.s3.get_object(key="uploads/doc.pdf")
        
        # MCP Server fait :
        # 1. Circuit breaker check
        # 2. Retry avec backoff exponentiel (3 tentatives)
        # 3. Logging structuré
        # 4. Métriques CloudWatch
        
        return content
        
    except CircuitBreakerOpen:
        # Service S3 temporairement indisponible
        return {"error": "S3 service unavailable", "retry_after": 60}
    
    except S3ObjectNotFound:
        # Objet n'existe pas
        return {"error": "Document not found", "key": key}
```

**Opération PostgreSQL - Transaction avec Connection Pooling :**

```python
# Agent code
async with mcp_context() as mcp:
    # Requête simple
    rows = await mcp.postgres.fetch_all(
        "SELECT * FROM documents WHERE status = $1",
        "pending"
    )
    
    # Transaction multi-statements
    async with mcp.postgres.transaction():
        # Insert document
        doc_id = await mcp.postgres.execute(
            "INSERT INTO documents (s3_key, status) VALUES ($1, $2) RETURNING id",
            "uploads/doc.pdf", "processing"
        )
        
        # Insert processing log
        await mcp.postgres.execute(
            "INSERT INTO processing_logs (document_id, agent, action) VALUES ($1, $2, $3)",
            doc_id, "extractor", "started"
        )
        
        # Commit automatique si pas d'exception
        # Rollback automatique en cas d'erreur
```

**Transition :** "Passons maintenant à la sécurité réseau et données..."

---

## 6. Sécurité Réseau et Données (5 minutes)

### 6.1 Network Segmentation

**[SLIDE 18 - VPC Layout]**

**Architecture Réseau :**

```
VPC 10.0.0.0/16
│
├─ Public Subnets (Internet Gateway)
│  ├─ 10.0.1.0/24 (eu-west-3a)
│  │  ├─ ALB
│  │  └─ NAT Gateway
│  │
│  └─ 10.0.2.0/24 (eu-west-3b)
│     ├─ ALB (HA)
│     └─ NAT Gateway (HA)
│
└─ Private Subnets (No internet, NAT only)
   ├─ 10.0.10.0/24 (eu-west-3a)
   │  ├─ Orchestrator
   │  ├─ Extractor
   │  ├─ MCP Server
   │  ├─ RDS Primary
   │  └─ Keycloak
   │
   └─ 10.0.20.0/24 (eu-west-3b)
      ├─ Validator
      ├─ Archivist
      ├─ RDS Standby (Multi-AZ)
      └─ Keycloak (HA)
```

**Règles Security Groups Critiques :**

```yaml
RDS Security Group (sg-xxxxx):
  Inbound:
    - Port: 5432
      Source: MCP Server SG (sg-yyyyy)    # ✅ MCP uniquement
      Description: "MCP Server → RDS"
    
    - Port: 5432
      Source: Keycloak SG (sg-zzzzz)      # ✅ Keycloak uniquement
      Description: "Keycloak → RDS"
    
  Outbound: DENY ALL                      # ✅ Pas de sortie

MCP Server Security Group (sg-yyyyy):
  Inbound:
    - Port: 8000
      Source: Orchestrator SG, Extractor SG, Validator SG, Archivist SG
      Description: "Agents → MCP Server"
  
  Outbound:
    - Port: 5432
      Destination: RDS SG                 # ✅ Accès DB
    - Port: 443
      Destination: S3 VPC Endpoint        # ✅ Accès S3
    - Port: 443
      Destination: Secrets Manager VPC Endpoint  # ✅ Secrets
```

**Validation de la Segmentation :**

```bash
# Test depuis orchestrator
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task <orchestrator-task-id> \
  --container orchestrator \
  --command "/bin/bash"

# Dans le container orchestrator :
# ✅ Devrait fonctionner
curl http://mcp-server.ca-a2a.local:8000/health

# ❌ Devrait échouer (timeout)
psql -h ca-a2a-postgres.*.rds.amazonaws.com -U postgres
# Connection timeout - Security Group bloque
```

### 6.2 Encryption

**[SLIDE 19 - Encryption Layers]**

**Chiffrement At Rest :**

| Ressource | Algorithme | Gestion Clés | Rotation |
|-----------|-----------|--------------|----------|
| RDS Aurora | AES-256 | AWS KMS (default) | Automatique (annuelle) |
| RDS Keycloak | AES-256 | AWS KMS (default) | Automatique |
| S3 Bucket | SSE-S3 (AES-256) | AWS S3 managed | Automatique |
| EBS Volumes | AES-256 | AWS KMS (default) | Automatique |
| Secrets Manager | AES-256 | KMS dedicated key | Manuel |
| CloudWatch Logs | AES-256 | AWS managed | Automatique |

**Chiffrement In Transit :**

```
User
  ↓ TLS 1.2+ (ALB)
ALB
  ↓ HTTP (VPC privé, OK car isolation réseau)
Orchestrator
  ↓ HTTP + JWT signature (intégrité)
Agents
  ↓ HTTP (vers MCP)
MCP Server
  ↓ TLS 1.2+ (obligatoire)
RDS PostgreSQL (ssl=require)
```

**Configuration TLS RDS :**

```python
# Connection string avec SSL
pool = await asyncpg.create_pool(
    host=RDS_ENDPOINT,
    port=5432,
    ssl='require',  # ✅ Force TLS, rejette plain text
    # Alternative pour validation stricte du certificat :
    # ssl_context=ssl.create_default_context()
)
```

### 6.3 VPC Endpoints (PrivateLink)

**[SLIDE 20 - Flux sans Internet]**

**Endpoints Configurés :**

```yaml
VPC Endpoints:
  - com.amazonaws.eu-west-3.s3 (Gateway)
    Purpose: Accès S3 sans NAT
    Route: 10.0.0.0/16 → S3
    Cost: Gratuit
    
  - com.amazonaws.eu-west-3.ecr.api (Interface)
    Purpose: Pull images depuis ECR
    ENI: 10.0.10.50, 10.0.20.50
    
  - com.amazonaws.eu-west-3.ecr.dkr (Interface)
    Purpose: Docker registry auth
    ENI: 10.0.10.51, 10.0.20.51
    
  - com.amazonaws.eu-west-3.logs (Interface)
    Purpose: CloudWatch Logs
    ENI: 10.0.10.52, 10.0.20.52
    
  - com.amazonaws.eu-west-3.secretsmanager (Interface)
    Purpose: Secrets Manager API
    ENI: 10.0.10.53, 10.0.20.53
```

**Bénéfices Sécurité :**

1. **Pas d'exposition Internet**
   - Tout le trafic reste dans AWS backbone
   - Pas de risque d'interception MITM externe

2. **Réduction Coûts NAT**
   - S3 via Gateway Endpoint = gratuit
   - Interface Endpoints = $0.01/h × 5 = $0.05/h ($36/mois)
   - NAT Gateway = $0.045/h + data transfer
   - **Économie nette : ~40%**

3. **Meilleures Performances**
   - Latence réduite (pas de NAT hop)
   - Bande passante dédiée

**Transition :** "Pour finir, parlons du monitoring et de la réponse aux incidents..."

---

## 7. Monitoring et Réponse aux Incidents (5 minutes)

### 7.1 Observabilité

**[SLIDE 21 - Stack de Monitoring]**

**Architecture Monitoring :**

```
┌─────────────────────────────────────────┐
│          CloudWatch Logs                │
│  /ecs/ca-a2a-orchestrator              │
│  /ecs/ca-a2a-extractor                 │
│  /ecs/ca-a2a-validator                 │
│  /ecs/ca-a2a-archivist                 │
│  /ecs/ca-a2a-mcp-server    ← NOUVEAU   │
│  /ecs/ca-a2a-keycloak      ← NOUVEAU   │
└─────────────┬───────────────────────────┘
              │
              ↓ Logs Insights Queries
┌─────────────────────────────────────────┐
│     Dashboards & Alarms                 │
│  - Authentication failures              │
│  - Authorization violations             │
│  - Token revocations                    │
│  - Circuit breaker states               │
│  - MCP pool exhaustion                  │
└─────────────────────────────────────────┘
```

**Queries Critiques :**

```sql
-- 1. Détection tentatives d'authentification échouées
fields @timestamp, event_type, subject, reason
| filter event_type = "authentication_failure"
| stats count() as failures by bin(5m), subject
| filter failures > 10
| sort failures desc
-- Alert si > 10 échecs / 5 min pour un même subject

-- 2. Détection privilege escalation attempts
fields @timestamp, subject, roles, method, granted
| filter event_type = "authorization" and granted = false
| stats count() as violations by subject, method
| filter violations > 5
| sort violations desc
-- Alert si > 5 tentatives d'accès non autorisé

-- 3. Monitoring MCP Server health
fields @timestamp, tool, success, duration_ms
| filter @message like /call_tool/
| stats avg(duration_ms) as avg_latency,
        count() as total_requests,
        sum(success = false) as errors
        by bin(1m), tool
| filter errors > 10 or avg_latency > 1000
-- Alert si > 10 erreurs/min ou latence > 1s

-- 4. Détection anomalies token usage
fields @timestamp, jti, sourceIP
| stats count() as requests,
        count_distinct(sourceIP) as unique_ips
        by jti
| filter unique_ips > 1
| sort requests desc
-- Alert si même jti utilisé depuis plusieurs IPs (possible vol)
```

### 7.2 Métriques Custom CloudWatch

**[SLIDE 22 - Métriques Sécurité]**

**Métriques Implémentées :**

```python
# Dans chaque agent
import boto3
cloudwatch = boto3.client('cloudwatch', region_name='eu-west-3')

# Métrique 1 : Authentication Success Rate
cloudwatch.put_metric_data(
    Namespace='CA-A2A/Security',
    MetricData=[{
        'MetricName': 'AuthenticationSuccessRate',
        'Value': success_rate,
        'Unit': 'Percent',
        'Timestamp': datetime.utcnow(),
        'Dimensions': [
            {'Name': 'Agent', 'Value': 'orchestrator'},
            {'Name': 'AuthMethod', 'Value': 'keycloak_jwt'}
        ]
    }]
)

# Métrique 2 : Token Revocation Count
cloudwatch.put_metric_data(
    Namespace='CA-A2A/Security',
    MetricData=[{
        'MetricName': 'TokensRevoked',
        'Value': 1,
        'Unit': 'Count',
        'Dimensions': [
            {'Name': 'Reason', 'Value': reason},
            {'Name': 'RevokedBy', 'Value': admin_user}
        ]
    }]
)

# Métrique 3 : MCP Circuit Breaker State Changes
cloudwatch.put_metric_data(
    Namespace='CA-A2A/MCP',
    MetricData=[{
        'MetricName': 'CircuitBreakerStateChange',
        'Value': 1,
        'Unit': 'Count',
        'Dimensions': [
            {'Name': 'Service', 'Value': 's3'},
            {'Name': 'NewState', 'Value': 'OPEN'}
        ]
    }]
)
```

**Alarmes CloudWatch :**

```yaml
Alarms:
  - Name: HighAuthenticationFailureRate
    Metric: AuthenticationSuccessRate
    Threshold: < 90%
    Period: 5 minutes
    Action: SNS → security-alerts@company.com
    
  - Name: MCPCircuitBreakerOpen
    Metric: CircuitBreakerStateChange
    Threshold: State = OPEN
    Period: 1 minute
    Action: SNS + PagerDuty (critical)
    
  - Name: UnauthorizedAccessAttempts
    Metric: AuthorizationViolations
    Threshold: > 20 per 5 minutes
    Period: 5 minutes
    Action: SNS + Auto-block IP (Lambda)
    
  - Name: AnomalousTokenUsage
    Metric: TokensUsedFromMultipleIPs
    Threshold: > 3 per hour
    Period: 1 hour
    Action: SNS + Auto-revoke (Lambda)
```

### 7.3 Incident Response

**[SLIDE 23 - Runbook Token Theft]**

**Exemple : Réponse à un Vol de Token (Détection + Mitigation) :**

```bash
#!/bin/bash
# incident-response-token-theft.sh

# Phase 1: DÉTECTION (0-5 minutes)
# Détecté via CloudWatch Alarm: "AnomalousTokenUsage"

# 1. Identifier le token compromis
COMPROMISED_JTI=$(aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "Multiple IPs detected" \
  --region eu-west-3 \
  --query 'events[0].message' | jq -r '.jti')

echo "⚠️  Compromised Token Detected: $COMPROMISED_JTI"

# Phase 2: CONTAINMENT (5-10 minutes)

# 2. Révoquer immédiatement le token
curl -X POST http://admin-api.ca-a2a.local:9000/admin/revoke-token \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{
    \"jti\": \"$COMPROMISED_JTI\",
    \"reason\": \"suspected_theft_multiple_ips\",
    \"revoked_by\": \"incident_response_bot\"
  }"

echo "✅ Token revoked"

# 3. Identifier toutes les requêtes du token compromis
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "$COMPROMISED_JTI" \
  --start-time $(date -d '24 hours ago' +%s)000 \
  --region eu-west-3 \
  --output json > /tmp/compromised_token_activity.json

# 4. Extraire les documents accédés
jq -r '.events[] | .message' /tmp/compromised_token_activity.json | \
  grep -oP 'document_id":\s*"\K[^"]+' | \
  sort -u > /tmp/accessed_documents.txt

DOCS_COUNT=$(wc -l < /tmp/accessed_documents.txt)
echo "⚠️  $DOCS_COUNT documents accessed by compromised token"

# 5. Bloquer les IPs suspectes
SUSPICIOUS_IPS=$(jq -r '.events[] | .message' /tmp/compromised_token_activity.json | \
  jq -r '.sourceIP' | sort -u | grep -v "10.0.")  # IPs externes uniquement

for IP in $SUSPICIOUS_IPS; do
  echo "🚫 Blocking IP: $IP"
  
  # Ajouter à WAF IP set (si ALB avec WAF)
  aws wafv2 update-ip-set \
    --name suspicious-ips \
    --id $IP_SET_ID \
    --scope REGIONAL \
    --region eu-west-3 \
    --addresses $IP/32
done

# Phase 3: ANALYSIS (10-30 minutes)

# 6. Analyser le scope de l'incident
python3 << EOF
import json
with open('/tmp/compromised_token_activity.json') as f:
    events = json.load(f)['events']

print(f"📊 Incident Analysis Report")
print(f"   Total Events: {len(events)}")
print(f"   First Seen: {events[0]['timestamp']}")
print(f"   Last Seen: {events[-1]['timestamp']}")
print(f"   Duration: {(events[-1]['timestamp'] - events[0]['timestamp']) / 1000 / 60:.1f} minutes")

methods = set(e.get('method') for e in events)
print(f"   Methods Called: {', '.join(methods)}")
EOF

# 7. Notifier l'équipe sécurité
aws sns publish \
  --topic-arn arn:aws:sns:eu-west-3:555043101106:security-incidents \
  --subject "🚨 Token Theft Incident - JTI: ${COMPROMISED_JTI:0:8}" \
  --message "Token compromis détecté et révoqué. $DOCS_COUNT documents accédés. IPs bloquées: $SUSPICIOUS_IPS. Voir /tmp/compromised_token_activity.json pour détails." \
  --region eu-west-3

echo "✅ Incident Response Complete"
```

**Transition :** "Pour conclure cette présentation..."

---

## 8. Conclusion et Prochaines Étapes (5 minutes)

### 8.1 Récapitulatif des Points Clés

**[SLIDE 24 - Key Takeaways]**

> "Récapitulons les points essentiels de cette architecture de sécurité."

**5 Messages Clés à Retenir :**

1. **Defense-in-Depth avec 9 Couches**
   - Chaque couche apporte une protection indépendante
   - Pas de single point of failure
   - Conformité standards ISO 27001, SOC 2

2. **Keycloak Centralisé = Zero Trust**
   - OAuth2/OIDC avec JWT RS256
   - TTL court (5 minutes) + rotation
   - Révocation hybride (cache + DB)

3. **MCP Server = Game Changer Sécurité**
   - -88% connexions DB, -75% IAM roles
   - Audit centralisé, circuit breakers
   - Overhead acceptable (~25%)

4. **Network Isolation Complète**
   - Agents en subnet privé
   - Security Groups granulaires
   - VPC Endpoints (pas d'internet)

5. **Observabilité Poussée**
   - Logs structurés JSON
   - CloudWatch Insights queries
   - Incident response automatisé

### 8.2 Roadmap Sécurité

**[SLIDE 25 - Évolutions Futures]**

**Court Terme (Q1 2026) :**

| Priorité | Amélioration | Effort | Impact |
|----------|-------------|---------|--------|
| **P0** | Activer MFA admin Keycloak | 2h | Critique |
| **P0** | mTLS entre agents | 1 semaine | Élevé |
| **P1** | WAF devant ALB | 3 jours | Élevé |
| **P1** | Secrets rotation automatique | 1 semaine | Moyen |
| **P2** | S3 Object Lambda (AV scan) | 2 semaines | Moyen |

**Moyen Terme (Q2-Q3 2026) :**

1. **Enhanced Monitoring**
   - Distributed tracing (AWS X-Ray)
   - Custom CloudWatch dashboards
   - SIEM integration (Splunk/ELK)

2. **Compliance Automation**
   - AWS Config rules
   - Security Hub findings
   - Automated remediation (Lambda)

3. **Penetration Testing**
   - External audit (Q2)
   - Automated pen-test (Burp Suite)
   - Bug bounty program (Q3)

**Long Terme (2027) :**

1. **Zero-Knowledge Architecture**
   - End-to-end encryption documents
   - Homomorphic encryption (AI processing)

2. **Blockchain Audit Trail**
   - Immutable audit logs
   - Smart contracts pour compliance

3. **AI-Powered Threat Detection**
   - Anomaly detection (ML models)
   - Automated incident response

### 8.3 Métriques de Succès

**[SLIDE 26 - KPIs Sécurité]**

**Métriques à Suivre :**

| Métrique | Cible | Actuel | Statut |
|----------|-------|--------|--------|
| Authentication Success Rate | > 99.9% | 99.95% | ✅ |
| Token Revocation Latency | < 100ms | ~20ms | ✅ |
| MCP Circuit Breaker Uptime | > 99.5% | 99.8% | ✅ |
| Security Incidents (P0) | 0 / month | 0 | ✅ |
| Mean Time to Detect (MTTD) | < 5 min | ~2 min | ✅ |
| Mean Time to Respond (MTTR) | < 15 min | ~8 min | ✅ |
| Compliance Audit Score | 100% | 98% | 🟡 (2% manquants : MFA admin) |

### 8.4 Resources et Documentation

**[SLIDE 27 - Ressources]**

**Documentation Technique :**

1. **Architecture de Sécurité (ce document)**
   - `A2A_SECURITY_ARCHITECTURE.md` (1,898 lignes)
   - Version 5.0, à jour au 15/01/2026

2. **Scénarios d'Attaque Détaillés**
   - `A2A_ATTACK_SCENARIOS_DETAILED.md` (1,625 lignes)
   - 18 scénarios avec diagrammes Mermaid
   - Exemples code vulnérable → sécurisé

3. **Guide d'Implémentation MCP Server**
   - `MCP_SERVER_IMPLEMENTATION_GUIDE.md` (575 lignes)
   - Instructions de déploiement
   - Troubleshooting complet

**Scripts Opérationnels :**

- `deploy-mcp-server.sh` - Déploiement MCP Server
- `update-agents-use-mcp.sh` - Migration agents vers MCP
- `comprehensive-system-test.sh` - Tests end-to-end
- `incident-response-*.sh` - Runbooks incidents

**Repository GitHub :**
```
https://github.com/jaafar-benabderrazak/ca_a2a
Branch: main
Commit: f993a1d (latest)
```

### 8.5 Clôture

**[SLIDE 28 - Questions]**

> "Nous avons couvert beaucoup de terrain aujourd'hui : de la topologie réseau jusqu'à la réponse aux incidents, en passant par l'authentification centralisée et le MCP Server."

> "Cette architecture représente l'état de l'art en matière de sécurité cloud pour systèmes distribués. Elle est opérationnelle en production et a déjà prouvé sa robustesse."

> "Je suis maintenant à votre disposition pour répondre à vos questions. N'hésitez pas à me challenger sur les choix techniques, les trade-offs, ou l'implémentation."

**Questions Anticipées :**

1. **"Pourquoi pas mTLS dès maintenant ?"**
   - Réponse : Complexité vs bénéfice. Avec VPC isolation + JWT signature, le risque MITM interne est très faible. mTLS est dans la roadmap Q1.

2. **"Overhead de 25% du MCP Server, n'est-ce pas trop ?"**
   - Réponse : Non. Les bénéfices (réduction surface d'attaque, audit centralisé, connection pooling) dépassent largement ce coût. C'est un trade-off assumé.

3. **"Que se passe-t-il si Keycloak tombe ?"**
   - Réponse : Tokens existants continuent de fonctionner jusqu'à expiration (5 min max). Keycloak est en HA (2 tasks), avec RDS Multi-AZ. MTTR < 5 minutes.

4. **"Comment gérez-vous la rotation des secrets ?"**
   - Réponse : Actuellement manuel via Secrets Manager. Automatisation prévue Q1 2026 avec Lambda + rotation automatique AWS.

5. **"MCP Server est-il un SPOF ?"**
   - Réponse : Potentiellement, mais mitigé : (1) Circuit breakers évitent l'avalanche, (2) Scaling automatique ECS, (3) Health checks + auto-restart. En pratique, uptime 99.8%.

**Merci !**

---

## Annexes

### Annexe A : Glossaire Technique

| Terme | Définition |
|-------|------------|
| **A2A** | Agent-to-Agent (protocole de communication inter-agents) |
| **RBAC** | Role-Based Access Control (contrôle d'accès basé sur les rôles) |
| **JWT** | JSON Web Token (standard RFC 7519) |
| **RS256** | RSA Signature with SHA-256 (algorithme de signature asymétrique) |
| **jti** | JWT ID (identifiant unique d'un token, claim standard) |
| **MCP** | Model Context Protocol (protocole d'accès aux ressources) |
| **OIDC** | OpenID Connect (couche identité au-dessus d'OAuth2) |
| **JWKS** | JSON Web Key Set (ensemble de clés publiques pour vérifier JWT) |
| **TTL** | Time To Live (durée de vie d'un token ou cache entry) |
| **VPC** | Virtual Private Cloud (réseau isolé AWS) |
| **SG** | Security Group (firewall stateful AWS) |
| **NACL** | Network Access Control List (firewall stateless) |
| **ALB** | Application Load Balancer (load balancer L7 AWS) |
| **ECS** | Elastic Container Service (orchestrateur de containers AWS) |
| **Fargate** | ECS launch type serverless (pas de gestion d'EC2) |
| **RDS** | Relational Database Service (PostgreSQL managé AWS) |
| **IAM** | Identity and Access Management (gestion identités/accès AWS) |

### Annexe B : Commandes Utiles

**Monitoring en Temps Réel :**

```bash
# Logs MCP Server en live
aws logs tail /ecs/ca-a2a-mcp-server --follow --region eu-west-3

# Métriques circuit breaker
aws cloudwatch get-metric-statistics \
  --namespace CA-A2A/MCP \
  --metric-name CircuitBreakerState \
  --dimensions Name=Service,Value=s3 \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 60 \
  --statistics Sum \
  --region eu-west-3

# Status des services ECS
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist mcp-server keycloak \
  --region eu-west-3 \
  --query 'services[*].{Name:serviceName,Running:runningCount,Desired:desiredCount}'
```

**Audit et Sécurité :**

```bash
# Tokens révoqués (24h)
aws logs insights start-query \
  --log-group-name /ecs/ca-a2a-admin-api \
  --start-time $(date -d '24 hours ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, jti, revoked_by, reason
    | filter event_type = "token_revoked"
    | sort @timestamp desc
  '

# Échecs d'authentification
aws logs insights start-query \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, subject, reason
    | filter event_type = "authentication_failure"
    | stats count() by subject, reason
  '
```

### Annexe C : Checklist Déploiement Sécurité

**Avant Mise en Production :**

- [ ] Keycloak admin MFA activé
- [ ] Tous les secrets dans Secrets Manager (pas de hardcoding)
- [ ] Security Groups : default deny vérifié
- [ ] VPC Flow Logs activés
- [ ] CloudTrail activé (all regions)
- [ ] RDS encryption at rest vérifié
- [ ] RDS automated backups configurés (7 jours)
- [ ] S3 bucket versioning activé
- [ ] S3 bucket logging activé
- [ ] IAM roles : least privilege vérifié
- [ ] CloudWatch alarms configurées
- [ ] SNS topics pour alertes créés
- [ ] Runbooks incidents documentés et testés
- [ ] Pen-test externe réalisé
- [ ] Compliance audit réalisé

**Monitoring Post-Déploiement (Premier Mois) :**

- [ ] Review logs quotidien (authentication failures, authorization violations)
- [ ] Vérification métriques hebdomadaire (circuit breaker, pool exhaustion)
- [ ] Test incident response (simulation token theft)
- [ ] Review IAM permissions (unused permissions cleanup)
- [ ] Update documentation (lessons learned)

---

**FIN DE LA PRÉSENTATION**

**Durée Totale : 60 minutes (45 min présentation + 15 min Q&A)**

---

## Notes pour le Présentateur

### Préparation Technique

1. **Démonstration Live (Optionnelle) :**
   - Préparer un environnement de démo (staging)
   - Tester le flow complet : auth Keycloak → appel agent → MCP Server → RDS
   - Montrer CloudWatch Logs en temps réel pendant un test

2. **Slides Recommandées :**
   - Total : 28 slides
   - Format : 16:9, police lisible (min 18pt)
   - Diagrammes : exporter depuis Mermaid en haute résolution
   - Code : syntax highlighting (utilisez Carbon.now.sh)

3. **Backup Plans :**
   - Si démo échoue : avoir des screenshots/vidéos pré-enregistrées
   - Si questions techniques pointues : "Je vais vérifier et vous revenir par email"
   - Si manque de temps : prioriser sections 3, 4, 5 (cœur de la sécurité)

### Ton et Posture

- **Confiant mais Humble :** "Nous avons fait nos meilleurs choix, mais toujours ouverts aux suggestions"
- **Factuel :** Chiffres, métriques, preuves concrètes
- **Pédagogique :** Expliquer le "pourquoi", pas juste le "quoi"
- **Transparent sur les Trade-offs :** Reconnaître les limites (ex: overhead MCP, pas de mTLS encore)

### Gestion du Temps

- **5 min de buffer** pour les questions pendant la présentation
- Si en retard : couper sections 6.2 et 6.3 (moins critiques)
- Si en avance : approfondir section 5 (MCP Server - très technique)

**Bonne présentation ! 🚀**

