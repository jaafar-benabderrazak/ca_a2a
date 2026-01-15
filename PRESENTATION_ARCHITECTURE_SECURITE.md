# Présentation : Architecture de Sécurité CA-A2A

**Titre :** Architecture de Sécurité du Système Multi-Agents CA-A2A  
**Audience :** Experts Techniques (Architectes, Ingénieurs Sécurité, DevSecOps)  
**Durée :** 60 minutes + 15 minutes Q&A  
**Présentateur :** [Votre Nom]  
**Date :** 15 Janvier 2026  
**Version Document :** 5.1  
**Basé sur :** A2A_SECURITY_ARCHITECTURE.md v5.1

---

## 📋 Table des Matières

**Structure Alignée avec A2A_SECURITY_ARCHITECTURE.md**

1. [Introduction](#1-introduction) (5 min)
2. [Section 1: System Architecture](#2-system-architecture) (8 min)
3. [Section 2: Security Layers](#3-security-layers) (8 min)
4. [Section 3: Authentication & Authorization](#4-authentication--authorization) (8 min)
5. [Section 4: Resource Access Layer (MCP Server)](#5-resource-access-layer-mcp-server) (6 min)
6. [Section 5: Network Security](#6-network-security) (5 min)
7. [Section 6: Data Security](#7-data-security) (3 min)
8. [Section 7: Protocol Security (A2A)](#8-protocol-security-a2a) (8 min)
9. [Section 8: Monitoring & Audit](#9-monitoring--audit) (4 min)
10. [Section 9: Threat Model & Defenses](#10-threat-model--defenses) (3 min)
11. [Conclusion](#11-conclusion) (2 min)

**Durée Totale : 75 minutes (60 min présentation + 15 min Q&A)**

---

## 1. Introduction (5 minutes)

### 1.1 Ouverture

**[SLIDE 1 - Titre]**

**💬 DISCOURS ORAL :**

"Bonjour à tous et merci d'être présents aujourd'hui. Je m'appelle [Votre Nom] et je vais vous présenter l'architecture de sécurité du système CA-A2A dans sa version 5.1.

Alors, pour commencer, qu'est-ce que CA-A2A ? C'est un système multi-agents déployé sur AWS ECS Fargate qui traite des documents sensibles. Et quand je dis 'multi-agents', je parle de 5 agents spécialisés qui communiquent entre eux : un orchestrateur, un extracteur, un validateur, un archiviste, et un serveur MCP qui centralise l'accès aux ressources.

Ce qui rend ce système particulièrement intéressant d'un point de vue sécurité, c'est qu'il implémente une approche defense-in-depth avec 9 couches de sécurité **indépendantes**. Et j'insiste sur le mot indépendantes : si une couche échoue, les 8 autres continuent de protéger le système. Il n'y a pas de single point of failure.

Le système est actuellement en production dans la région AWS eu-west-3, c'est-à-dire Paris. Nous avons choisi cette région pour des raisons de conformité RGPD et de latence pour nos utilisateurs européens.

Et justement, en parlant de conformité, ce système a été conçu dès le départ pour respecter les standards ISO 27001 et SOC 2. Ce n'est pas un ajout après coup, c'est vraiment dans l'ADN de l'architecture."

**📋 Points Clés :**
- Production : AWS ECS Fargate, région eu-west-3 (Paris)
- Architecture : 5 agents + Keycloak + MCP Server
- Conformité : ISO 27001, SOC 2
- Approche : Defense-in-Depth avec Zero-Trust

**🔧 REMARQUES TECHNIQUES :**
- ECS Fargate = serverless, pas de gestion de serveurs EC2
- Multi-AZ déployé sur eu-west-3a et eu-west-3b pour haute disponibilité
- Zero-Trust = "never trust, always verify" - pas de confiance implicite même à l'intérieur du VPC

### 1.2 Structure de la Présentation

**[SLIDE 2 - Structure]**

**💬 DISCOURS ORAL :**

"Maintenant, laissez-moi vous expliquer comment cette présentation est structurée. J'ai fait un choix délibéré : cette présentation suit **exactement** la structure du document technique A2A_SECURITY_ARCHITECTURE.md. Pourquoi ? Parce que je veux que vous puissiez facilement faire le lien entre ce que je vous présente aujourd'hui et la documentation détaillée que vous pourrez consulter après.

Donc regardez ce tableau : chaque section de cette présentation correspond **à la lettre** à une section du document. Section 2 de la présentation = Section 1 du document architecture. Section 3 = Section 2. Et ainsi de suite.

Nous allons couvrir 11 sections en 60 minutes, ce qui nous donne entre 2 et 8 minutes par section selon la complexité. J'ai prévu 15 minutes supplémentaires pour les questions à la fin, mais n'hésitez pas à m'interrompre si quelque chose n'est pas clair.

Les sections les plus longues sont Authentication & Authorization, et Protocol Security - parce que c'est là où il se passe le plus de choses intéressantes côté sécurité. Les sections les plus courtes comme Data Security et Threat Model sont plus des vues d'ensemble que je détaille moins, mais tout est dans le document pour approfondir."

**📊 11 Sections :**

| Section | Contenu | Temps |
|---------|---------|-------|
| **1** | System Architecture | 8 min |
| **2** | Security Layers (9 couches) | 8 min |
| **3** | Authentication & Authorization | 8 min |
| **4** | Resource Access Layer (MCP) | 6 min |
| **5** | Network Security | 5 min |
| **6** | Data Security | 3 min |
| **7** | Protocol Security (A2A) | 8 min |
| **8** | Monitoring & Audit | 4 min |
| **9** | Threat Model & Defenses | 3 min |
| **10** | Security Operations | 3 min |
| **11** | Conclusion | 2 min |

**🔧 REMARQUES TECHNIQUES :**
- Document source : 2,577 lignes, 11 sections, version 5.1
- Cette présentation = version "speaker notes" du document
- Tous les diagrammes et tableaux sont extraits directement du document
- Références de section explicites pour faciliter la navigation

**💡 CONSEIL PRÉSENTATEUR :**
"Avoir le document ouvert sur un second écran pour référence rapide en cas de questions détaillées"

**Transition :** "Parfait, maintenant que vous savez où nous allons, commençons par la Section 1 du document : System Architecture..."

---

## 2. System Architecture (8 minutes) → **Section 1 du document**

### 2.1 Production Deployment (Doc Section 1.1)

**[SLIDE 3 - Architecture Diagram]**

**💬 DISCOURS ORAL :**

"Alors, voici l'architecture complète telle qu'elle est déployée en production. Ce diagramme correspond exactement à celui de la Section 1.1 du document. Laissez-moi vous guider de haut en bas.

**En haut, vous avez Internet** - c'est le monde extérieur, les utilisateurs, les systèmes clients. Ils communiquent en HTTPS avec TLS 1.2 minimum. C'est important, on n'accepte pas de TLS 1.0 ou 1.1 qui sont obsolètes.

**Première ligne de défense : l'ALB**, l'Application Load Balancer. C'est le **seul** composant qui a une IP publique. Tout le reste est dans des subnets privés. L'ALB fait la terminaison TLS, et ensuite il route le trafic vers l'orchestrateur en HTTP. Pourquoi HTTP et pas HTTPS à l'intérieur ? Parce qu'on est dans un VPC isolé, et on a d'autres mécanismes de sécurité - on en reparlera dans la section Network Security.

**L'Orchestrator sur le port 8001**, c'est le chef d'orchestre. Il reçoit les requêtes, les authentifie, les autorise, et les distribue aux agents spécialisés. Il communique avec eux via le protocole A2A - c'est un protocole JSON-RPC 2.0 sécurisé par JWT.

**Les trois agents métier** : Extractor (8002), Validator (8003), et Archivist (8004). Chacun a une responsabilité unique :
- L'Extractor extrait le contenu des documents PDF, images, etc.
- Le Validator vérifie que le contenu respecte les règles métier
- L'Archivist stocke les documents validés pour archivage long terme

**Le MCP Server sur le port 8000** - c'est une nouveauté de la version 5.0. MCP signifie Model Context Protocol. C'est un gateway qui centralise **tous** les accès aux ressources AWS. Avant, chaque agent avait ses propres credentials AWS. Maintenant, il n'y a que le MCP Server qui a accès à RDS et S3. C'est un énorme gain en sécurité, on va le détailler dans la Section 4.

**En bas, les ressources** : RDS Aurora pour les métadonnées des documents, S3 pour les fichiers eux-mêmes, et Keycloak pour l'authentification centralisée OAuth2.

Point important : **regardez les flèches**. Le flux est unidirectionnel de haut en bas. Les agents ne peuvent pas initier de connexions vers l'ALB. C'est une architecture en 'push' controlé."

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
   🔐 MCP Server :8000 ← Gateway de Ressources
        ↓
   ┌────────────┐
   │ RDS Aurora │ ← Données
   │ S3 Bucket  │
   │ Keycloak   │ ← IAM
   └────────────┘
```

**🔧 REMARQUES TECHNIQUES :**
- ALB = seul point d'entrée public, terminaison TLS
- VPC isolation complète pour tous les agents (0.0.0.0/0 interdit)
- Service Discovery via AWS Cloud Map (DNS privé ca-a2a.local)
- Communication agent-to-agent via DNS privé (ex: `extractor.ca-a2a.local:8002`)
- RDS Aurora = PostgreSQL 15.8 compatible, multi-AZ avec réplication synchrone
- Keycloak = instance dédiée pour éviter le partage de l'IAM avec d'autres systèmes

### 2.2 Component Overview (Doc Section 1.2)

**[SLIDE 4 - Component Inventory]**

**💬 DISCOURS ORAL :**

"Maintenant, regardons le tableau d'inventaire complet des composants. Ce tableau vient directement de la Section 1.2 du document.

**Les agents ECS Fargate** - nous avons 4 agents métier, et remarquez qu'ils tournent tous en **2 instances**. Pourquoi 2 ? Pour la haute disponibilité. Si une instance tombe, l'autre prend le relais. Ils sont répartis sur deux zones de disponibilité différentes - eu-west-3a et eu-west-3b.

**Ports dédiés** - chaque agent a son propre port. Ce n'est pas juste pour l'organisation, c'est aussi pour la sécurité. Avec les Security Groups AWS, on peut dire 'l'orchestrator peut appeler l'extractor sur le port 8002, mais pas l'archivist'. C'est du micro-segmentation au niveau réseau.

**Keycloak** - une seule instance pour l'instant, mais c'est prévu de passer à 2 pour la haute disponibilité. C'est notre OAuth2/OIDC provider. Tous les tokens JWT sont émis par Keycloak.

**MCP Server** - aussi une seule instance. C'est le gateway pour S3 et RDS. On l'a introduit en version 5.0 et ça a été un game changer. Avant, on avait 4 agents × 10 connexions = 40 connexions PostgreSQL simultanées. Maintenant, le MCP Server mutualise avec un pool de 10 connexions max. On a divisé la charge sur RDS par 4.

**L'ALB** - c'est un service géré AWS, donc multi-AZ par défaut. Il écoute sur les ports 80 et 443. Le port 80 redirige automatiquement vers 443, donc en pratique c'est du HTTPS only.

**Les bases de données** - deux RDS : RDS Aurora pour les documents, et un RDS PostgreSQL standard pour Keycloak. Pourquoi deux bases séparées ? Pour l'isolation. Si Keycloak a un problème, ça n'impacte pas les données des documents. Et vice-versa."

**📋 Tableau des Composants (Doc Table 1.2) :**

| Component | Type | Port | Purpose | Instances |
|-----------|------|------|---------|-----------|
| **Orchestrator** | ECS Fargate | 8001 | Request coordination | 2 |
| **Extractor** | ECS Fargate | 8002 | Document extraction | 2 |
| **Validator** | ECS Fargate | 8003 | Content validation | 2 |
| **Archivist** | ECS Fargate | 8004 | Document archival | 2 |
| **Keycloak** | ECS Fargate | 8080 | OAuth2/OIDC Provider | 1 |
| **MCP Server** | ECS Fargate | 8000 | Resource Gateway | 2 |
| **ALB** | AWS Service | 80/443 | Load balancing | Multi-AZ |
| **RDS Aurora** | Managed DB | 5432 | Document metadata | Multi-AZ |
| **RDS Postgres** | Managed DB | 5432 | Keycloak data | Multi-AZ |

**🔧 REMARQUES TECHNIQUES :**
- **ECS Fargate CPU/RAM** : Orchestrator = 1 vCPU / 2GB, autres agents = 0.5 vCPU / 1GB
- **ALB Target Groups** : Health checks toutes les 30 secondes avec /health endpoint
- **RDS Aurora** : db.t4g.medium, 20GB storage, backup automatique quotidien, retention 7 jours
- **RDS Postgres (Keycloak)** : db.t4g.medium, 20GB, encryption at rest activée
- **Service Discovery** : DNS privé ca-a2a.local géré par AWS Cloud Map
- **Network mode** : awsvpc pour tous les agents (chaque tâche a son propre ENI)

**💡 DÉTAIL IMPORTANT :**
Le MCP Server a été mis à jour à 2 instances depuis la version initiale pour améliorer la résilience. Cela signifie que même si une instance MCP tombe, tous les agents peuvent continuer à accéder à S3 et RDS via l'autre instance.

**Message Clé :** 

> "Tous les agents dans des subnets privés. Seul l'ALB expose un point d'entrée public. C'est un principe fondamental : minimize the attack surface."

**Transition :** "Bien, maintenant que vous connaissez les composants, voyons comment ils se protègent mutuellement avec les 9 couches de sécurité - c'est la Section 2 du document..."

---

## 3. Security Layers (8 minutes) → **Section 2 du document**

### 3.1 Defense-in-Depth Architecture (Doc Section 2.1)

**[SLIDE 5 - 9 Security Layers Diagram]**

**💬 DISCOURS ORAL :**

"Nous arrivons maintenant au cœur de la présentation : les 9 couches de sécurité. Ce diagramme vient de la Section 2.1 du document. Et je veux vraiment insister sur un point : ces couches sont **indépendantes**.

Qu'est-ce que ça veut dire concrètement ? Ça veut dire que si un attaquant arrive à bypasser la couche 3 - disons qu'il a volé un JWT valide - il doit encore passer les couches 4, 5, 6, 7, 8 et 9. C'est ça, le defense-in-depth : multiplier les barrières.

**Couche 1 : Network Isolation** - C'est le VPC, les Security Groups, les NACLs. C'est le niveau le plus bas. Si vous n'êtes pas sur le bon réseau, vous ne pouvez même pas établir une connexion TCP.

**Couche 2 : Identity & Access** - C'est Keycloak. Vous devez prouver qui vous êtes avant d'obtenir un token. OAuth2/OIDC standard.

**Couche 3 : Authentication** - OK, vous avez un JWT, mais est-il valide ? On vérifie la signature RS256 avec la clé publique de Keycloak. Si la signature ne matche pas, vous êtes rejeté immédiatement.

**Couche 4 : Authorization** - Votre token est valide, mais avez-vous le **droit** de faire cette action ? C'est le RBAC. Un utilisateur avec le rôle 'viewer' ne peut pas appeler la méthode 'delete_document'. Point.

**Couche 5 : Resource Access Control** - **Nouvelle couche en v5.0.** Même si vous êtes autorisé, vous ne pouvez pas accéder directement à RDS ou S3. Vous devez passer par le MCP Server. C'est un gateway qui applique ses propres règles.

**Couche 6 : Message Integrity** - On calcule un hash du body de la requête et on le lie au JWT. Si quelqu'un modifie la requête en transit, le hash ne matche plus, et on rejette. Ça protège contre les attaques man-in-the-middle même à l'intérieur du VPC.

**Couche 7 : Input Validation** - **Nouvelle en v5.1.** JSON Schema + Pydantic. Avant d'exécuter le code métier, on valide que les paramètres respectent le schéma. Protection contre les injections SQL, path traversal, etc.

**Couche 8 : Replay Protection** - Chaque JWT a un identifiant unique - le 'jti'. On le track dans un cache. Si on voit le même jti deux fois, c'est une attaque par rejeu. On bloque.

**Couche 9 : Rate Limiting** - Dernier filet de sécurité. Maximum 300 requêtes par minute par principal (utilisateur ou service). Si vous dépassez, vous êtes throttled. Ça protège contre les DoS.

Remarquez les deux étoiles : les couches 5 et 7 sont nouvelles. La couche 5 est apparue en version 5.0 avec le MCP Server. La couche 7 en version 5.1. On améliore continuellement."

```
Layer 1: Network Isolation (VPC, SG, NACLs)
    ↓
Layer 2: Identity & Access (Keycloak OAuth2/OIDC)
    ↓
Layer 3: Authentication (JWT RS256 Verification)
    ↓
Layer 4: Authorization (RBAC with Keycloak Roles)
    ↓
Layer 5: Resource Access Control (MCP Server Gateway) ⭐ NOUVEAU v5.0
    ↓
Layer 6: Message Integrity (JWT Body Hash Binding)
    ↓
Layer 7: Input Validation (JSON Schema, Pydantic) ⭐ NOUVEAU v5.1
    ↓
Layer 8: Replay Protection (JWT jti Tracking)
    ↓
Layer 9: Rate Limiting (300 req/min per Principal)
```

**🔧 REMARQUES TECHNIQUES :**
- **Indépendance des couches** : Chaque couche peut être testée et auditée séparément
- **Ordre logique** : Du plus externe (réseau) au plus interne (rate limiting applicatif)
- **Performance** : Impact cumulé ~50ms par requête (vs. 0ms sans sécurité)
  - L1 (network): ~0ms (matériel)
  - L2-L3 (JWT verify): ~10ms (crypto)
  - L4 (RBAC): ~1ms (lookup)
  - L5 (MCP): ~25ms (HTTP call)
  - L6 (hash): ~1ms (compute)
  - L7 (validation): ~5ms (schema check)
  - L8 (replay): ~1ms (cache lookup)
  - L9 (rate limit): ~1ms (counter)
- **Trade-off accepté** : 50ms de latence pour 9 couches de protection
- **Bypass impossible** : Pas de "backdoor" ou endpoint non protégé

**💡 ÉVOLUTION HISTORIQUE :**
- v1.0-3.0 : 6 couches (L1-L4, L6, L8-L9)
- v4.0 : Ajout Keycloak (renforcement L2-L3)
- v5.0 : Ajout MCP Server (nouvelle L5)
- v5.1 : Ajout JSON Schema/Pydantic (nouvelle L7)

###3.2 Layer Responsibilities (Doc Section 2.2)

**[SLIDE 6 - Layer Responsibilities Table]**

**💬 DISCOURS ORAL :**

"Maintenant, détaillons ce que fait chaque couche et surtout **quelle menace** elle mitige. Parce que c'est bien beau d'avoir 9 couches, mais il faut que chacune ait un objectif précis.

**Layer 1 - Network Isolation** avec VPC, Security Groups, NACLs. Elle protège contre les attaques réseau classiques et les DDoS au niveau transport. Si quelqu'un essaie de scanner vos ports depuis Internet, il ne verra même pas les agents - ils sont dans des subnets privés.

**Layer 2 - Identity & Access** avec Keycloak. Elle force l'authentification centralisée. Plus de hardcoded passwords, plus de tokens statiques. Tout passe par Keycloak. Menace mitigée : unauthorized access.

**Layer 3 - Authentication** avec JWT RS256. On vérifie cryptographiquement que le token vient bien de Keycloak. Menace : impersonation et forged tokens. Si quelqu'un essaie de créer un faux JWT, la signature ne matchera pas.

**Layer 4 - Authorization** avec RBAC. OK, vous êtes authentifié, mais qu'avez-vous le droit de faire ? Un 'viewer' ne peut pas delete. Un'extractor' ne peut pas accéder directement à l'archivist. Menace : privilege escalation.

**Layer 5 - MCP Server** - c'est ma préférée. Elle centralise **tous** les accès à S3 et RDS. Avant, chaque agent avait ses credentials AWS. Maintenant, zéro agent n'a accès direct. Si un agent est compromis, l'attaquant ne peut pas dump la base de données. Il doit passer par le MCP qui applique ses propres règles. Menace mitigée : direct AWS access, credential sprawl. On est passé de 4 IAM roles à 1 seul. C'est 75% de réduction de la surface d'attaque.

**Layer 6 - Message Integrity** avec JWT body hash. On calcule un SHA-256 du body de la requête et on le stocke dans le JWT. Si quelqu'un intercepte la requête et modifie le body, le hash ne matchera plus. Menace : Man-in-the-middle, tampering.

**Layer 7 - JSON Schema + Pydantic**. Double validation des inputs. JSON Schema pour le format standard, Pydantic pour les règles Python type-safe. En production, on bloque environ 400 tentatives d'injection par jour grâce à cette couche. Menace : injection attacks, DoS par malformed input.

**Layer 8 - Replay Protection** avec le jti tracking. Chaque JWT a un ID unique. On le met dans un cache Redis (enfin, en mémoire Python pour l'instant). Si on voit le même jti deux fois, c'est louche. Quelqu'un essaie de rejouer une requête valide. On bloque. Menace : replay attacks.

**Layer 9 - Rate Limiting**. 300 requêtes par minute par principal. Si vous dépassez, vous avez un 429 - Too Many Requests. Pourquoi 300 ? Parce qu'en usage normal, personne ne dépasse 100. On a mis une marge. Mais un attaquant qui essaie de flooder ? Il est stoppé net. Menace : resource exhaustion, DoS applicatif.

Et regardez la dernière colonne - chaque couche utilise une technologie différente. On ne met pas tous les œufs dans le même panier. Si AWS Security Groups ont un bug, on a encore 8 autres couches."

**📋 Tableau du Document (Section 2.2) :**

| Layer | Purpose | Technology | Threat Mitigated |
|-------|---------|------------|------------------|
| **L1** | Isolation, segmentation | VPC, SG, NACL | Network attacks, DDoS |
| **L2** | Centralized authentication | Keycloak | Unauthorized access |
| **L3** | Token verification | JWT RS256 | Impersonation, forged tokens |
| **L4** | Permission enforcement | RBAC | Privilege escalation |
| **L5** | Centralized S3/RDS gateway | **MCP Server** | Direct AWS access, credential sprawl |
| **L6** | Message tampering detection | JWT body hash | MITM, tampering |
| **L7** | Malformed input rejection | JSON Schema, Pydantic | Injection attacks, DoS |
| **L8** | Duplicate request detection | JWT jti + TTL cache | Replay attacks |
| **L9** | Abuse prevention | Sliding window | Resource exhaustion, DoS |

**🔧 REMARQUES TECHNIQUES :**
- **L1 Performance** : Filtrage matériel AWS, latence < 1ms
- **L2-L3 Performance** : JWT verify avec cache JWKS, ~10ms cold, ~1ms warm
- **L4 Mapping** : Keycloak roles → A2A principals via table statique (pas de DB lookup)
- **L5 Impact** : +25ms latence mais -88% connexions DB (trade-off positif)
- **L6 Algorithm** : SHA-256 du JSON body canonicalisé (whitespace normalisé)
- **L7 Stats Production** : ~400 blocks/jour, 95% avant code métier
- **L8 Cache** : TTL = exp du JWT (max 5 min), cleanup automatique
- **L9 Algorithm** : Sliding window avec Redis (future), in-memory dict (actuel)

**💡 CONSEIL ARCHITECTURE :**
"Ne jamais compter sur une seule couche. Defense-in-depth signifie redondance intentionnelle. Exemple : même avec VPC isolation (L1), on fait quand même JWT signature check (L3). Même avec RBAC (L4), on valide les inputs (L7)."

### 3.3 Complete Request Security Flow (Doc Section 2.3)

**[SLIDE 7 - Visual Security Flow]**

> "Le document Section 2.3 montre le parcours complet d'une requête. Voici le diagramme simplifié pour la présentation."

**Points de Contrôle par Couche (Doc Table 2.3) :**

| Couche | Contrôle | Critère Pass | Réponse Échec |
|--------|----------|--------------|---------------|
| **L1** | Réseau | IP/VPC autorisée | Connection refused |
| **L2** | Identité | JWT présent | 401 Unauthorized |
| **L3** | Auth | Signature RS256 valide | 401 Invalid Token |
| **L4** | Authz | Rôle RBAC correct | 403 Forbidden |
| **L5** | Ressources | MCP opérationnel | 503 Service Unavailable |
| **L6** | Intégrité | Hash match | 403 Tampering |
| **L7** | Validation | Schema valide | 400 Invalid Params |
| **L8** | Replay | jti unique | 403 Replay Detected |
| **L9** | Rate | < 300/min | 429 Rate Limit |

**Transition :** "Détaillons l'authentification (Section 3)..."

---

## 4. Authentication & Authorization (8 minutes) → **Section 3 du document**

### 4.1 Keycloak OAuth2/OIDC Flow (Doc Section 3.1)

**[SLIDE 8 - Keycloak Flow Diagram]**

> "Le diagramme de la Section 3.1 montre le flux complet Keycloak."

**Étapes :**

1. **Client → Keycloak** : POST /token avec {client_id, client_secret}
2. **Keycloak → Client** : Retourne JWT (access_token + refresh_token)
3. **Client → Orchestrator** : Request avec Authorization: Bearer JWT
4. **Orchestrator → Keycloak** : Vérifie JWT via JWKS
5. **Orchestrator** : Extrait roles, map RBAC, check permissions
6. **Orchestrator → Agent** : Forward request si autorisé

### 4.2 JWT Token Structure (Doc Section 3.2)

**[SLIDE 9 - JWT Structure]**

**Structure du Document :**

```json
{
  "header": {"alg": "RS256", "typ": "JWT", "kid": "keycloak-key-id"},
  "payload": {
    "exp": 1737845500,
    "iat": 1737845200,
    "jti": "abc123-token-id",
    "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
    "aud": "ca-a2a-agents",
    "sub": "user-uuid-1234",
    "realm_access": {
      "roles": ["admin", "orchestrator", "document-processor"]
    }
  }
}
```

**Claims Clés :**
- `exp`: Expiration (TTL 5 minutes)
- `jti`: JWT ID (pour replay protection)
- `realm_access.roles`: Rôles Keycloak

### 4.3 Role-Based Access Control (Doc Section 3.3)

**[SLIDE 10 - RBAC Mapping Table]**

**Tableau du Document (Section 3.3) :**

| Keycloak Role | A2A Principal | Allowed Methods | Use Case |
|---------------|---------------|-----------------|----------|
| `admin` | `admin` | `*` (all methods) | Full system access |
| `lambda` | `lambda` | `upload_document`, `process_document` | S3 events |
| `orchestrator` | `orchestrator` | `extract_document`, `validate_document`, `archive_document` | Agent coordination |
| `document-processor` | `document-processor` | `process_document`, `list_pending_documents`, `check_status` | Processing workflows |
| `viewer` | `viewer` | `list_documents`, `get_document`, `check_status` | Read-only |

### 4.4 Token Revocation (Doc Section 3.4)

**[SLIDE 11 - Hybrid Revocation Architecture]**

**Architecture du Document :**

```
Admin API
    ↓
1. Write to Cache (In-Memory) → ~1μs
2. Persist to PostgreSQL → ~10ms
    ↓
Request Validation
    ↓
1. Check Cache (99% hits) → ~1μs
2. If miss, check DB → ~10ms
3. Populate cache → Next check fast
```

**Table Schema (Doc Section 3.4) :**

```sql
CREATE TABLE revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,
    revoked_at TIMESTAMP,
    revoked_by VARCHAR(100),
    reason TEXT,
    expires_at TIMESTAMP
);
```

**Transition :** "Passons au MCP Server (Section 4)..."

---

## 5. Resource Access Layer - MCP Server (6 minutes) → **Section 4 du document**

### 5.1 Architecture Overview (Doc Section 4.1)

**[SLIDE 12 - MCP Server Gateway]**

> "La Section 4 du document introduit le MCP Server, la 5ème couche de sécurité."

**Avant (v4.0) vs Après (v5.0) :**

```
❌ AVANT:
Orchestrator ──┐
Extractor   ──┼──> RDS (80 connexions)
Validator   ──┤    S3  (4 IAM roles)
Archivist   ──┘

✅ MAINTENANT:
Orchestrator ──┐
Extractor   ──┼──> MCP Server :8000 ──> RDS (10 connexions)
Validator   ──┤                      └──> S3  (1 IAM role)
Archivist   ──┘
```

### 5.2 Security Benefits (Doc Section 4.2)

**[SLIDE 13 - Security Benefits Table]**

**Tableau du Document (Section 4.2) :**

| Benefit | Description | Impact |
|---------|-------------|--------|
| **Reduced Attack Surface** | Only MCP has AWS credentials | -75% IAM roles |
| **Centralized Audit** | All S3/RDS access in one place | +100% visibility |
| **Connection Pooling** | Shared PostgreSQL pool (max 10) | -88% DB connections |
| **Consistent Security** | Uniform retry, circuit breakers | Standardized |
| **Easier IAM Management** | Single task role to update | -4 policy updates/change |
| **Credential Isolation** | Agents never see passwords | Reduced sprawl |

### 5.3 Available Operations (Doc Section 4.4)

**[SLIDE 14 - MCP API Examples]**

**S3 Operations (Doc examples) :**

```bash
# List objects
POST /call_tool {"tool": "s3_list_objects", "arguments": {"prefix": "uploads/"}}

# Get object
POST /call_tool {"tool": "s3_get_object", "arguments": {"key": "doc.pdf"}}

# Put object
POST /call_tool {"tool": "s3_put_object", "arguments": {"key": "...", "body": "..."}}
```

**PostgreSQL Operations :**

```bash
# Query
POST /call_tool {"tool": "postgres_query", "arguments": {"query": "SELECT...", "params": []}}

# Execute
POST /call_tool {"tool": "postgres_execute", "arguments": {"query": "INSERT...", "params": []}}
```

**Transition :** "Voyons la sécurité réseau (Section 5)..."

---

## 6. Network Security (5 minutes) → **Section 5 du document**

### 6.1 VPC Architecture (Doc Section 5.1 renumbered as 4.1 in doc)

**[SLIDE 15 - VPC Layout]**

**Architecture du Document :**

```
VPC: 10.0.0.0/16
├── Public Subnets
│   ├── 10.0.1.0/24 (AZ-a) - ALB, NAT
│   └── 10.0.2.0/24 (AZ-b) - ALB
└── Private Subnets
    ├── 10.0.10.0/24 (AZ-a) - ECS Tasks
    └── 10.0.20.0/24 (AZ-b) - ECS Tasks, RDS
```

**Security Implications :**
- ✅ Zero public IPs on agents
- ✅ Outbound only via NAT
- ✅ Multi-AZ redundancy
- ✅ Private DNS (service discovery)

### 6.2 Security Groups (Doc Section 5.2 renumbered as 4.2)

**[SLIDE 16 - Security Groups Rules]**

**Tableau du Document :**

| Security Group | Inbound Rules | Purpose |
|----------------|---------------|---------|
| **ALB-SG** | 80/443 from 0.0.0.0/0 | Public HTTP/HTTPS |
| **Orchestrator-SG** | 8001 from ALB-SG | ALB → Orchestrator only |
| **Extractor-SG** | 8002 from Orch-SG | Orchestrator → Extractor |
| **Validator-SG** | 8003 from Orch-SG | Orchestrator → Validator |
| **Archivist-SG** | 8004 from Orch-SG | Orchestrator → Archivist |
| **Keycloak-SG** | 8080 from Agent-SGs | All agents → Keycloak |
| **MCP-SG** | 8000 from Agent-SGs | All agents → MCP |
| **RDS-SG** | 5432 from MCP-SG + KC-SG | Database access |

**Default Deny:** Toutes les SG ont implicit deny-all.

### 6.3 VPC Endpoints (Doc Section 5.3 renumbered as 4.3)

**[SLIDE 17 - VPC Endpoints Table]**

**Tableau du Document :**

| Service | Type | Purpose |
|---------|------|---------|
| **ecr.api** | Interface | Pull container images |
| **ecr.dkr** | Interface | Docker registry auth |
| **s3** | Gateway | S3 object storage |
| **logs** | Interface | CloudWatch Logs |
| **secretsmanager** | Interface | Secrets Manager |

**Bénéfice :** Trafic reste dans le réseau AWS (pas d'internet public).

**Transition :** "Parlons du chiffrement des données (Section 6)..."

---

## 7. Data Security (3 minutes) → **Section 6 du document**

### 7.1 Encryption at Rest (Doc Section 6.1 renumbered as 5.1)

**[SLIDE 18 - Encryption at Rest Table]**

**Tableau du Document :**

| Resource | Encryption | Key Management |
|----------|-----------|----------------|
| **RDS Aurora** | AES-256 | AWS KMS (default) |
| **RDS Postgres (Keycloak)** | AES-256 | AWS KMS (default) |
| **S3 Bucket** | SSE-S3 (AES-256) | AWS-managed |
| **EBS Volumes** | AES-256 | AWS KMS (default) |
| **Secrets Manager** | AES-256 | AWS KMS (dedicated) |
| **CloudWatch Logs** | AES-256 | AWS-managed |

### 7.2 Encryption in Transit (Doc Section 6.2 renumbered as 5.2)

**[SLIDE 19 - Encryption in Transit]**

**État Actuel (du Document) :**

- ✅ User → ALB: HTTPS (TLS 1.2+)
- ⚠️ ALB → Orchestrator: HTTP (dans VPC) - Risque faible
- ⚠️ Agent-to-Agent: HTTP (dans VPC) - Protégé par JWT
- ✅ Agents → RDS: TLS 1.2 (asyncpg avec SSL)
- ✅ Agents → AWS Services: HTTPS (boto3 default)

**Recommandation du Document :** Activer TLS entre ALB et agents pour defense-in-depth.

### 7.3 Secrets Management (Doc Section 6.3 renumbered as 5.3)

**[SLIDE 20 - Secrets Manager]**

**Secrets du Document :**

| Secret Name | Purpose | Rotation |
|-------------|---------|----------|
| `ca-a2a/db-password` | RDS Aurora master | Manual |
| `ca-a2a/keycloak-admin-password` | Keycloak admin | Manual |
| `ca-a2a/keycloak-db-password` | Keycloak RDS | Manual |
| `ca-a2a/keycloak-client-secret` | OAuth2 client | Manual |

**Aucun secret hardcodé** - Tous récupérés au runtime.

**Transition :** "Détaillons le protocole A2A (Section 7)..."

---

## 8. Protocol Security (A2A) (8 minutes) → **Section 7 du document**

### 8.1 JSON-RPC 2.0 Format (Doc Section 7.1)

**[SLIDE 21 - JSON-RPC Format]**

**Format du Document :**

```json
// Request
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "method": "process_document",
  "params": {"document_id": "doc-789", "s3_key": "uploads/invoice.pdf"}
}

// Response
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "result": {"status": "success", ...},
  "_meta": {"correlation_id": "...", "duration_ms": 250}
}
```

### 8.2 HTTP Headers Schema (Doc Section 7.2)

**[SLIDE 22 - Required Headers Table]**

**Tableau du Document (Section 7.2) :**

| Header | Type | Required | Description | Example |
|--------|------|----------|-------------|---------|
| `Content-Type` | String | ✅ Yes | Must be `application/json` | `application/json` |
| `Authorization` | String | ✅ Yes | Bearer JWT from Keycloak | `Bearer eyJhbGc...` |
| `X-Correlation-ID` | String | ⚠️ Optional | Request tracing ID | `2026-01-15T10:30:00Z...` |
| `User-Agent` | String | ⚠️ Optional | Client identifier | `CA-A2A-Client/1.0` |

### 8.3 JSON Schema Validation (Doc Section 7.3)

**[SLIDE 23 - JSON Schema Example]**

**Schema du Document (Section 7.3.1) :**

```json
// process_document schema
{
  "type": "object",
  "properties": {
    "s3_key": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9/_-][a-zA-Z0-9/_.-]*$",
      "not": {"pattern": "\\.\\."},  // ✓ Bloque ../
      "minLength": 1,
      "maxLength": 1024
    },
    "priority": {
      "type": "string",
      "enum": ["low", "normal", "high"]
    }
  },
  "required": ["s3_key"],
  "additionalProperties": false
}
```

**Sécurité :**
- ✅ Path traversal protection (`..` bloqué)
- ✅ Length limits (max 1024)
- ✅ No additional properties (mass assignment prevention)

### 8.4 Pydantic Models (Doc Section 7.4)

**[SLIDE 24 - Pydantic Example]**

**Code du Document (Section 7.4.1) :**

```python
class ProcessDocumentRequest(BaseModel):
    s3_key: str = Field(..., min_length=1, max_length=1024)
    priority: Literal["low", "normal", "high"] = Field(default="normal")
    
    @field_validator('s3_key')
    @classmethod
    def validate_s3_key(cls, v: str) -> str:
        if ".." in v:
            raise ValueError("Path traversal not allowed")
        if not v[0].isalnum():
            raise ValueError("Must start with alphanumeric")
        return v.strip()
```

**Double Validation :** JSON Schema (standard) + Pydantic (type-safe Python)

### 8.5 Content Validation Rules (Doc Section 7.5)

**[SLIDE 25 - Validation Flow Diagram]**

**6 Couches de Validation (du Document) :**

```
1. HTTP Headers → Valid?
2. JSON Parsing → Valid syntax?
3. JSON-RPC Structure → jsonrpc, id, method present?
4. JSON Schema → Pattern, type, length valid?
5. Pydantic Model → Type-safe, custom validators?
6. Business Rules → Application logic valid?
    ↓
Execute Method
```

**Statistiques Production (du Document) :**
- ~400 injections bloquées par jour
- 95% des erreurs détectées avant code métier

### 8.6 Error Code Reference (Doc Section 7.6)

**[SLIDE 26 - Error Codes Table]**

**Codes du Document (Section 7.6) :**

**JSON-RPC 2.0 Standard :**

| Code | Meaning | Trigger |
|------|---------|---------|
| `-32700` | Parse error | Invalid JSON syntax |
| `-32600` | Invalid Request | Missing jsonrpc field |
| `-32601` | Method not found | Unknown method |
| `-32602` | Invalid params | Schema/type validation failed |
| `-32603` | Internal error | Server exception |

**Security Custom :**

| Code | Meaning | Trigger |
|------|---------|---------|
| `-32010` | Unauthorized | JWT invalid/expired |
| `-32011` | Forbidden | RBAC insufficient |
| `-32012` | Rate limit exceeded | > 300 req/min |
| `-32013` | Replay detected | Duplicate jti |
| `-32014` | Token revoked | Blacklisted JWT |

**Transition :** "Voyons le monitoring (Section 8)..."

---

## 9. Monitoring & Audit (4 minutes) → **Section 8 du document**

### 9.1 CloudWatch Logs (Doc Section 8.1)

**[SLIDE 27 - Log Groups Table]**

**Tableau du Document :**

| Log Group | Purpose | Retention |
|-----------|---------|-----------|
| `/ecs/ca-a2a-orchestrator` | Orchestrator logs | 7 days |
| `/ecs/ca-a2a-extractor` | Extractor logs | 7 days |
| `/ecs/ca-a2a-validator` | Validator logs | 7 days |
| `/ecs/ca-a2a-archivist` | Archivist logs | 7 days |
| `/ecs/ca-a2a-keycloak` | Keycloak logs | 7 days |
| `/ecs/ca-a2a-mcp-server` | MCP Server logs | 7 days |

**Format Structuré (JSON) :**

```json
{
  "timestamp": "2026-01-15T10:30:00Z",
  "level": "INFO",
  "agent": "orchestrator",
  "event_type": "request",
  "correlation_id": "2026-01-15T10:30:00Z-a1b2c3d4",
  "method": "process_document",
  "principal": "document-processor",
  "duration_ms": 250,
  "success": true
}
```

### 9.2 Security Events Logged (Doc Section 8.2)

**[SLIDE 28 - Security Events Table]**

**Événements du Document :**

| Event Type | Trigger | Log Level |
|------------|---------|-----------|
| `authentication_success` | Valid JWT | INFO |
| `authentication_failure` | Invalid JWT | WARN |
| `authorization_failure` | Insufficient permissions | WARN |
| `rate_limit_exceeded` | Too many requests | WARN |
| `replay_detected` | Duplicate jti | WARN |
| `token_revoked` | Revoked token used | WARN |
| `invalid_input` | Schema validation failed | WARN |
| `method_executed` | Successful call | INFO |

**Queries CloudWatch Insights disponibles dans le document.**

### 9.3 Metrics Recommandées (Doc Section 8.3)

**[SLIDE 29 - Metrics Table]**

**Métriques du Document :**

| Metric | Unit | Dimensions | Purpose |
|--------|------|------------|---------|
| `RequestLatency` | Milliseconds | Agent, Method | Performance |
| `ErrorCount` | Count | Agent, ErrorType | Error tracking |
| `RequestCount` | Count | Agent | Throughput |
| `AuthenticationFailures` | Count | Agent | Security monitoring |
| `RateLimitViolations` | Count | Principal | Abuse detection |
| `TokenRevocationChecks` | Count | Agent | Revocation usage |

**Transition :** "Analysons le modèle de menaces (Section 9)..."

---

## 10. Threat Model & Defenses (3 minutes) → **Section 9 du document**

### 10.1 STRIDE Analysis (Doc Section 9.1)

**[SLIDE 30 - STRIDE Table]**

**Tableau du Document :**

| Threat | Attack Vector | Defense Layer | Mitigation |
|--------|---------------|---------------|------------|
| **Spoofing** | Impersonate agent/user | L2, L3 | Keycloak + JWT RS256 |
| **Tampering** | Modify request/response | L6 | JWT body hash |
| **Repudiation** | Deny actions | L8 | Audit logs with correlation IDs |
| **Information Disclosure** | Intercept traffic | L1, Data | VPC isolation + TLS |
| **Denial of Service** | Flood requests | L7, L9 | Input validation + rate limiting |
| **Elevation of Privilege** | Bypass RBAC | L4 | Keycloak roles + RBAC enforcement |

### 10.2 Key Attack Scenarios (Doc Section 9.2)

**[SLIDE 31 - Attack Scenarios Summary]**

**18 Scénarios Détaillés dans le Document :**

1. **Token Theft** → Défense : TTL 5 min, révocation, replay protection
2. **Replay Attack** → Défense : jti tracking, TTL cache
3. **Privilege Escalation** → Défense : RBAC enforcement, audit logs
4. **DDoS** → Défense : Rate limiting 300/min, ALB Shield, auto-scaling
5. **SQL Injection** → Défense : Parameterized queries, JSON Schema, Pydantic
6. **MITM** → Défense : VPC isolation, JWT signature, TLS
7. **JWT Algorithm Confusion** → Défense : Algorithm enforcement (RS256 only)
8. **Keycloak Compromise** → Défense : Strong password, network isolation, MFA
9. **Agent Impersonation** → Défense : Service discovery, JWT audience check, SG
10. **Time-Based Attacks** → Défense : Clock skew tolerance (30s), freshness check

...et 8 autres scénarios détaillés dans A2A_ATTACK_SCENARIOS_DETAILED.md

**Transition :** "Terminons avec la conclusion..."

---

## 11. Conclusion (2 minutes)

### 11.1 Récapitulatif

**[SLIDE 32 - Key Takeaways]**

**5 Messages Clés (alignés avec le document) :**

1. **Defense-in-Depth avec 9 Couches**
   - Chaque couche protège indépendamment
   - Pas de single point of failure
   - Conformité ISO 27001, SOC 2

2. **Keycloak Centralisé = Zero Trust**
   - OAuth2/OIDC avec JWT RS256
   - TTL court (5 minutes) + rotation
   - Révocation hybride (cache + DB)

3. **MCP Server = Game Changer Sécurité**
   - -88% connexions DB, -75% IAM roles
   - Audit centralisé, circuit breakers
   - Overhead acceptable (~25%)

4. **Validation Multi-Couches (v5.1)**
   - JSON Schema + Pydantic = double sécurité
   - Bloque ~400 injections/jour en production
   - 95% des erreurs détectées avant code métier

5. **Observabilité Poussée**
   - Logs structurés JSON avec correlation IDs
   - CloudWatch Insights queries
   - Incident response automatisé

### 11.2 Documentation Complète

**[SLIDE 33 - Resources]**

**Documentation Technique :**

1. **Architecture de Sécurité (ce document)**
   - `A2A_SECURITY_ARCHITECTURE.md` (2,577 lignes)
   - Version 5.1, à jour au 15/01/2026
   - 11 sections couvrant tous les aspects

2. **Scénarios d'Attaque Détaillés**
   - `A2A_ATTACK_SCENARIOS_DETAILED.md` (1,625 lignes)
   - 18 scénarios avec diagrammes Mermaid
   - Exemples code vulnérable → sécurisé

3. **Guide d'Implémentation MCP Server**
   - `MCP_SERVER_IMPLEMENTATION_GUIDE.md` (575 lignes)
   - Instructions de déploiement
   - Troubleshooting complet

4. **Présentation Technique (ce document)**
   - `PRESENTATION_ARCHITECTURE_SECURITE.md`
   - Aligné strictement avec A2A_SECURITY_ARCHITECTURE.md
   - Structure section par section

### 11.3 Questions & Réponses

**[SLIDE 34 - Questions]**

> "Merci pour votre attention. Je suis maintenant disponible pour répondre à vos questions."

**Questions Anticipées :**

1. **Q:** Pourquoi HTTP entre agents dans le VPC ?  
   **R:** Isolation VPC + signature JWT = sécurisé. TLS inter-agent recommandé pour defense-in-depth (Section 5.2).

2. **Q:** Performance du MCP Server ?  
   **R:** Overhead +25% latence, mais -88% connexions DB. Trade-off sécurité vs. performance accepté (Section 4.2).

3. **Q:** Gestion des tokens révoqués à grande échelle ?  
   **R:** Architecture hybride : cache (1μs) + PostgreSQL. Auto-cleanup toutes les 5 minutes. Testé à 10K révocations (Section 3.4).

4. **Q:** Plan disaster recovery ?  
   **R:** RDS snapshots quotidiens, multi-AZ, backup Keycloak DB. Détails dans Section 10 (Security Operations).

5. **Q:** Conformité RGPD ?  
   **R:** Chiffrement AES-256, audit trail, accès contrôlé RBAC. Droit à l'oubli nécessite implémentation API (Section 10.3).

---

**FIN DE LA PRÉSENTATION**

**Durée Totale : 75 minutes (60 min + 15 min Q&A)**

**Structure : 100% alignée avec A2A_SECURITY_ARCHITECTURE.md v5.1**
