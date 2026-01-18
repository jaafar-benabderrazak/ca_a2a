# Architecture de Sécurité CA-A2A

**Version :** 6.0  
**Dernière mise à jour :** 17 janvier 2026  
**Statut :** Déployé en Production  
**Région :** eu-west-3 (Paris)  
**Environnement :** AWS ECS Fargate

---

## Résumé Exécutif

Le système CA-A2A (Crédit Agricole Agent-to-Agent) implémente une sécurité de niveau entreprise à travers une architecture de défense en profondeur avec **10 couches de sécurité indépendantes**. Le système est déployé sur AWS ECS Fargate dans un VPC privé avec authentification centralisée Keycloak OAuth2/OIDC, contrôle d'accès aux ressources via Serveur MCP, et contrôle d'accès basé sur les rôles (RBAC).

### Fonctionnalités Clés de Sécurité

| Catégorie | Fonctionnalité | Technologie |
|-----------|----------------|-------------|
| **Authentification** | OAuth2/OIDC centralisé | Keycloak RS256 JWT |
| **Protection Anti-Vol** | Liaison cryptographique de token | Token Binding (RFC 8473) |
| **Accès Ressources** | Passerelle centralisée S3/RDS | Serveur MCP |
| **Autorisation** | Permissions granulaires | RBAC (rôles Keycloak) |
| **Révocation** | Invalidation d'urgence tokens | PostgreSQL + Cache mémoire |
| **Anti-Rejeu** | Suivi JWT jti | Cache TTL 120s |
| **Anti-Abus** | 300 req/min par principal | Limitation débit (fenêtre glissante) |
| **Isolation Réseau** | Sous-réseaux privés, Security Groups | VPC AWS |
| **Chiffrement** | Au repos & en transit | TLS 1.2+, AES-256 (KMS) |
| **Audit** | Journalisation complète | CloudWatch Logs |
| **Anti-Timing** | Prévention attaques temporelles | Comparaison temps constant |

---

## Table des Matières

1. [Architecture Système](#1-architecture-système)
2. [Couches de Sécurité (Défense en Profondeur)](#2-couches-de-sécurité-défense-en-profondeur)
3. [Authentification & Autorisation](#3-authentification--autorisation)
4. [Couche d'Accès aux Ressources (Serveur MCP)](#4-couche-daccès-aux-ressources-serveur-mcp)
5. [Sécurité Réseau](#5-sécurité-réseau)
6. [Sécurité des Données](#6-sécurité-des-données)
7. [Sécurité du Protocole (A2A)](#7-sécurité-du-protocole-a2a)
8. [Surveillance & Audit](#8-surveillance--audit)
9. [Modèle de Menaces & Défenses](#9-modèle-de-menaces--défenses)
10. [Opérations de Sécurité](#10-opérations-de-sécurité)
11. [Référence d'Implémentation](#11-référence-dimplémentation)

---

## 1. Architecture Système

> **📖 Documentation détaillée :** [Architecture Système (FR)](docs/fr/ARCHITECTURE_SYSTEME.md)

### 1.1 Déploiement Production

```mermaid
graph TB
    subgraph Internet
        User[Utilisateur Externe]
    end
    
    subgraph AWS["AWS Cloud - eu-west-3"]
        subgraph VPC["VPC: 10.0.0.0/16"]
            subgraph Public["Sous-réseaux Publics"]
                ALB[Application Load Balancer<br/>HTTPS/HTTP]
                NAT[NAT Gateway]
            end
            
            subgraph Private["Sous-réseaux Privés - Cluster ECS"]
                direction TB
                Orch[Orchestrateur<br/>:8001]
                Ext[Extracteur<br/>:8002]
                Val[Validateur<br/>:8003]
                Arch[Archiviste<br/>:8004]
                KC[Keycloak<br/>:8080]
                MCP[Serveur MCP<br/>:8000<br/>Passerelle Ressources]
            end
            
            subgraph Data["Couche Données"]
                RDS[RDS Aurora PostgreSQL<br/>BD documents]
                KC_RDS[RDS PostgreSQL<br/>BD keycloak]
            end
        end
        
        subgraph Services["Services AWS"]
            SM[Secrets Manager]
            CW[CloudWatch Logs]
            S3[Bucket S3]
            ECR[ECR Repositories]
        end
    end
    
    User -->|1. HTTPS| ALB
    ALB -->|2. HTTP| Orch
    Orch -->|Protocole A2A| Ext
    Orch -->|Protocole A2A| Val
    Orch -->|Protocole A2A| Arch
    
    Orch -.->|Auth| KC
    Ext -.->|Auth| KC
    Val -.->|Auth| KC
    Arch -.->|Auth| KC
    
    KC -->|JDBC| KC_RDS
    
    Orch -->|HTTP API| MCP
    Ext -->|HTTP API| MCP
    Val -->|HTTP API| MCP
    Arch -->|HTTP API| MCP
    
    MCP -->|asyncpg<br/>Pool| RDS
    MCP -.->|aioboto3| S3
    Arch -.->|boto3| S3
    
    Private -.->|VPC Endpoints| SM
    Private -.->|VPC Endpoints| CW
    Private -.->|NAT Gateway| Internet
```

### 1.2 Vue d'Ensemble des Composants

![Architecture Système](https://github.com/user-attachments/assets/8776d817-a274-418f-83c6-2a2f0879b063)

| Composant | Type | Port | Objectif | Instances |
|-----------|------|------|----------|-----------|
| **Orchestrateur** | ECS Fargate | 8001 | Coordination requêtes, orchestration workflow | 2 |
| **Extracteur** | ECS Fargate | 8002 | Extraction texte documents (OCR, parsing) | 2 |
| **Validateur** | ECS Fargate | 8003 | Validation contenu, contrôles qualité | 2 |
| **Archiviste** | ECS Fargate | 8004 | Archivage documents, récupération | 2 |
| **Keycloak** | ECS Fargate | 8080 | Fournisseur identité (OAuth2/OIDC) | 1 |
| **ALB** | Service AWS | 80/443 | Répartition charge, terminaison TLS | Multi-AZ |
| **RDS Aurora** | BD gérée | 5432 | Métadonnées documents, journaux audit | Multi-AZ |
| **RDS Postgres** | BD gérée | 5432 | Données Keycloak (utilisateurs, rôles) | Multi-AZ |

---

## 2. Couches de Sécurité (Défense en Profondeur)

> **📖 Documentation détaillée :** [Couches de Sécurité (FR)](docs/fr/COUCHES_SECURITE_DEFENSE_EN_PROFONDEUR.md)

### 2.1 Architecture Défense en Profondeur

```mermaid
graph TB
    L1[Couche 1: Isolation Réseau<br/>VPC, Security Groups, NACLs]
    L2[Couche 2: Identité & Accès<br/>Keycloak OAuth2/OIDC]
    L3[Couche 3: Authentification<br/>Vérification Signature JWT RS256]
    L4[Couche 4: Autorisation<br/>RBAC avec Rôles Keycloak]
    L5[Couche 5: Contrôle Accès Ressources<br/>Passerelle Serveur MCP]
    L6[Couche 6: Intégrité Messages<br/>Liaison Hash Corps JWT]
    L7[Couche 7: Validation Entrées<br/>JSON Schema, Modèles Pydantic]
    L8[Couche 8: Protection Rejeu<br/>Suivi Nonce JWT jti]
    L9[Couche 9: Limitation Débit<br/>Fenêtre Glissante Par Principal]
    
    L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7 --> L8 --> L9
    
    style L1 fill:#ff6b6b
    style L2 fill:#ffd93d
    style L3 fill:#6bcf7f
    style L4 fill:#4d96ff
    style L5 fill:#ffd700
    style L6 fill:#a66cff
    style L7 fill:#ff9a76
    style L8 fill:#62cdff
    style L9 fill:#f4b860
```

### 2.2 Responsabilités des Couches

![Couches de Sécurité](https://github.com/user-attachments/assets/12587382-31da-4bf5-a5f3-cbeb4179bb7a)

| Couche | Objectif | Technologie | Menace Atténuée |
|--------|----------|-------------|-----------------|
| **C1: Réseau** | Isolation, segmentation | VPC, SG, NACL | Attaques réseau, DDoS |
| **C2: Identité** | Authentification centralisée | Keycloak | Accès non autorisé |
| **C3: Authentification** | Vérification token | JWT RS256 + Token Binding | Usurpation, tokens forgés, vol |
| **C4: Autorisation** | Application permissions | RBAC (rôles Keycloak) | Élévation privilèges |
| **C5: Accès Ressources** | Passerelle S3/RDS centralisée | Serveur MCP | Accès AWS direct, prolifération credentials |
| **C6: Intégrité** | Détection falsification messages | Hash corps JWT | MITM, falsification messages |
| **C7: Validation** | Rejet entrées malformées | JSON Schema, Pydantic | Attaques injection, DoS |
| **C8: Rejeu** | Détection requêtes dupliquées | JWT jti + Cache TTL | Attaques par rejeu |
| **C9: Limitation Débit** | Prévention abus | Fenêtre glissante | Épuisement ressources, DoS |

### 2.3 Flux de Sécurité Complet d'une Requête

**Parcours d'une Requête à Travers les 9 Couches :**

```mermaid
sequenceDiagram
    participant User as Utilisateur/Client
    participant ALB as ALB
    participant Orch as Orchestrateur
    participant KC as Keycloak
    participant MCP as Serveur MCP
    participant RDS as RDS PostgreSQL

    Note over User,RDS: Parcours de Sécurité Complet

    User->>ALB: 1. Requête HTTPS + JWT
    
    rect rgb(255, 107, 107)
    Note over ALB: C1: Isolation Réseau<br/>✓ Security Groups VPC<br/>✓ Terminaison TLS
    end
    
    ALB->>Orch: 2. Transférer vers Orchestrateur
    
    rect rgb(255, 217, 61)
    Note over Orch: C2: Vérification Identité<br/>✓ JWT Présent dans En-tête?<br/>✓ Format Valide?
    end
    
    Orch->>KC: 3. Récupérer Clés Publiques JWKS
    KC-->>Orch: Clés Publiques (cachées 1h)
    
    rect rgb(107, 207, 127)
    Note over Orch: C3: Authentification<br/>✓ Vérifier Signature JWT RS256<br/>✓ Vérifier Expiration (exp)<br/>✓ Valider Émetteur/Audience<br/>✓ Token Binding (certificat TLS)
    end
    
    rect rgb(77, 150, 255)
    Note over Orch: C4: Autorisation<br/>✓ Extraire Rôles Keycloak<br/>✓ Mapper vers Principal RBAC<br/>✓ Vérifier Permission Méthode
    end
    
    Orch->>MCP: 4. Appeler API Serveur MCP
    
    rect rgb(255, 215, 0)
    Note over MCP: C5: Contrôle Accès Ressources<br/>✓ Passerelle Centralisée<br/>✓ Vérification Circuit Breaker<br/>✓ Gestion Pool Connexions
    end
    
    MCP->>RDS: 5. Requête Base de Données
    RDS-->>MCP: Résultats Requête
    
    MCP-->>Orch: 6. Retourner Résultats
    
    rect rgb(166, 108, 255)
    Note over Orch: C6: Intégrité Messages<br/>✓ Vérifier Hash Corps JWT<br/>✓ Détecter Falsification
    end
    
    rect rgb(255, 154, 118)
    Note over Orch: C7: Validation Entrées<br/>✓ Vérification JSON Schema<br/>✓ Sécurité Type Pydantic<br/>✓ Protection Traversée Chemin
    end
    
    rect rgb(98, 205, 255)
    Note over Orch: C8: Protection Rejeu<br/>✓ Vérifier JWT jti dans Cache<br/>✓ Marquer comme Utilisé (TTL 120s)<br/>✓ Rejeter Duplicata
    end
    
    rect rgb(244, 184, 96)
    Note over Orch: C9: Limitation Débit<br/>✓ Vérifier Compteur Requêtes<br/>✓ 300 req/min par Principal<br/>✓ Algorithme Fenêtre Glissante
    end
    
    Note over Orch: ✅ Toutes Vérifications Passées<br/>Exécuter Logique Métier
    
    Orch-->>ALB: 7. Réponse JSON-RPC
    ALB-->>User: 8. Réponse HTTPS
    
    Note over User,RDS: Requête Terminée: 9 Couches Validées
```

**Points de Contrôle Couche par Couche :**

| Couche | Point de Contrôle | Critère de Réussite | Réponse en Cas d'Échec |
|--------|-------------------|---------------------|------------------------|
| **C1** | Entrée Réseau | Requête depuis IP/VPC autorisée | Connexion refusée |
| **C2** | Présence Identité | JWT dans `Authorization: Bearer` | 401 Non Autorisé |
| **C3** | Authentification | Signature JWT valide, non expiré | 401 Token Invalide |
| **C4** | Autorisation | Principal a permission pour méthode | 403 Interdit |
| **C5** | Accès Ressources | Circuit breaker Serveur MCP fermé | 503 Service Indisponible |
| **C6** | Intégrité Messages | Hash corps JWT correspond requête | 403 Falsification Détectée |
| **C7** | Validation Entrées | Schéma valide, pas tentative injection | 400 Paramètres Invalides (-32602) |
| **C8** | Protection Rejeu | JWT jti jamais vu auparavant | 403 Rejeu Détecté |
| **C9** | Limitation Débit | Moins de 300 requêtes/minute | 429 Limite Débit Dépassée |
| **✅** | **Logique Métier** | Validation spécifique application | 200 OK ou erreur |

**Garanties de Sécurité :**

- 🛡️ **Défense en Profondeur** : Chaque couche fournit une protection indépendante
- 🔒 **Échec Sécurisé** : Toutes les vérifications doivent passer ; tout échec rejette la requête
- 📊 **Observable** : Chaque couche enregistre les décisions dans CloudWatch
- ⚡ **Performance** : Surcharge sécurité totale ~20-40ms (< 20% temps requête total)
- 🔄 **Aucun Point Unique de Défaillance** : Compromettre une couche ne contourne pas les autres

---

## 3. Authentification & Autorisation

> **📖 Documentation détaillée :** [Authentification & Autorisation (FR)](docs/fr/AUTHENTIFICATION_AUTORISATION.md)

### 3.1 Flux OAuth2/OIDC Keycloak

```mermaid
sequenceDiagram
    participant Client
    participant Keycloak
    participant Orchestrateur

    Note over Client,Orchestrateur: 1. Authentification Initiale
    Client->>Keycloak: POST /token<br/>{client_id, client_secret}
    Keycloak-->>Client: {access_token (JWT), expires_in: 900}
    
    Note over Client,Orchestrateur: 2. Requête API avec JWT
    Client->>Orchestrateur: POST /message<br/>Authorization: Bearer JWT
    Orchestrateur->>Keycloak: GET /certs (caché 1h)
    Keycloak-->>Orchestrateur: JWKS (clés publiques)
    Orchestrateur->>Orchestrateur: Vérifier signature RS256<br/>Extraire rôles, vérifier RBAC
    
    alt Autorisé
        Orchestrateur-->>Client: 200 OK
    else Non Autorisé
        Orchestrateur-->>Client: 403 Forbidden
    end
```

### 3.2 Hiérarchie RBAC

| Rôle Keycloak | Principal A2A | Méthodes Autorisées |
|---------------|---------------|---------------------|
| `admin` | `admin` | `*` (toutes les méthodes) |
| `orchestrator` | `orchestrator` | `extract_document`, `validate_document`, `archive_document` |
| `lambda` | `lambda` | `upload_document`, `process_document` |
| `document-processor` | `document-processor` | `process_document`, `list_pending_documents`, `check_status` |
| `viewer` | `viewer` | `list_documents`, `get_document`, `check_status` (lecture seule) |

### 3.3 Liaison de Token (RFC 8473)

**Objectif :** Lier cryptographiquement le JWT au certificat TLS client pour empêcher le vol de token

**Claim JWT avec Liaison de Token :**
```json
{
  "cnf": {
    "x5t#S256": "bDlkZGM4YTEyZGM..."
  }
}
```

**Vérification (comparaison temps constant) :**
```python
import secrets

presented_thumbprint = compute_cert_thumbprint(client_cert_pem)
expected_thumbprint = jwt_claims["cnf"]["x5t#S256"]

if not secrets.compare_digest(expected_thumbprint, presented_thumbprint):
    raise ValueError("Token volé - certificat incompatible")
```

### 3.4 Révocation de Token

**Pourquoi Pas Keycloak pour la Révocation ?**

| Approche | Latence | Scalabilité | Point Unique Défaillance |
|----------|---------|-------------|--------------------------|
| **Vérification Session Keycloak** | 50-100ms | Médiocre (goulot Keycloak) | Oui |
| **Notre Révocation Hybride** | 1μs (caché) | Excellente (distribuée) | Non |

**Notre Solution :**
- ✅ Cache mémoire : vérification 1μs (99,9% requêtes)
- ✅ PostgreSQL : persistance, survit redémarrages
- ✅ Nettoyage auto : tokens expirés supprimés toutes les 5 min

---

## 4. Couche d'Accès aux Ressources (Serveur MCP)

> **📖 Documentation détaillée :** [Serveur MCP (FR)](docs/fr/ACCES_RESSOURCES_SERVEUR_MCP.md)

### 4.1 Pattern Passerelle Centralisée

**Avantages Clés :**
- ✅ **Zéro Credential AWS dans Agents** : Seul le Serveur MCP a les credentials
- ✅ **Pooling Connexions** : Réutilisation connexions BD (10x plus rapide)
- ✅ **Circuit Breaker** : Empêche défaillances en cascade
- ✅ **Réessais Automatiques** : Gestion erreurs transitoires avec backoff
- ✅ **Audit Centralisé** : Point unique pour journalisation accès ressources

### 4.2 Métriques Performance

| Opération | Sans MCP | Avec MCP | Amélioration |
|-----------|----------|----------|--------------|
| Requête PostgreSQL | 50-100ms (nouvelle connexion) | 5-10ms (pool) | **10x plus rapide** |
| S3 Get Object | 100-200ms | 100-200ms | Identique (limité réseau) |
| Circuit Breaker | Défaillances en cascade | Échec rapide | **Stabilité système** |

---

## 5. Sécurité Réseau

> **📖 Documentation détaillée :** [Sécurité Réseau (FR)](docs/fr/SECURITE_RESEAU.md)

### 5.1 Configuration VPC

- **CIDR :** 10.0.0.0/16
- **Sous-réseaux Publics :** 10.0.1.0/24, 10.0.2.0/24 (ALB, NAT Gateway)
- **Sous-réseaux Privés :** 10.0.11.0/24, 10.0.12.0/24 (Agents ECS)
- **Isolation :** Aucune IP publique pour les agents
- **Internet :** NAT Gateway (sortant uniquement)
- **Services AWS :** VPC Endpoints (pas de routage internet)

### 5.2 Security Groups (Règles Clés)

| Composant | Entrant | Sortant |
|-----------|---------|---------|
| **ALB** | 0.0.0.0/0:443, 0.0.0.0/0:80 | Orchestrateur:8001 |
| **Orchestrateur** | ALB SG:8001 | Extracteur:8002, Keycloak:8080, MCP:8000 |
| **Agents** | Orchestrateur SG:(8002/8003/8004) | Keycloak:8080, MCP:8000 |
| **Keycloak** | Tous SG agents:8080 | RDS:5432 |
| **Serveur MCP** | Tous SG agents:8000 | RDS:5432, 0.0.0.0/0:443 (S3) |
| **RDS** | Keycloak SG:5432, MCP SG:5432 | DENY (pas de sortie) |

---

## 6. Sécurité des Données

> **📖 Documentation détaillée :** [Sécurité Données (FR)](docs/fr/SECURITE_DONNEES.md)

### 6.1 Chiffrement

**Au Repos (AES-256 via AWS KMS) :**
- RDS Aurora PostgreSQL, RDS PostgreSQL (Keycloak), Bucket S3
- Volumes EBS (ECS), Secrets Manager, CloudWatch Logs

**En Transit :**
- Utilisateur → ALB : **HTTPS (TLS 1.2+)**
- Agent → RDS : **PostgreSQL SSL/TLS**
- Agent → S3 : **HTTPS (TLS 1.2+)**
- Interne VPC : HTTP (réseau privé, performance)

### 6.2 Gestion des Secrets

**AWS Secrets Manager :**
- Mots de passe BD, admin Keycloak, client secret, clés API
- ✅ Rotation automatique (tous les 90 jours)
- ✅ Contrôle accès IAM
- ✅ Audit CloudTrail
- ✅ Aucun secret en dur

---

## 7. Sécurité du Protocole (A2A)

> **📖 Documentation détaillée :** [Sécurité Protocole (FR)](docs/fr/SECURITE_PROTOCOLE.md)

### 7.1 Pourquoi JSON-RPC 2.0 ?

✅ **Standardisé** : Spécification bien définie, comportement prévisible  
✅ **Simple** : Surcharge minimale (~100-200 octets)  
✅ **Sécurisé** : Validation déterministe, pas d'ambiguïté  
✅ **Comparaison temps Constant** : `hmac.compare_digest()`, `secrets.compare_digest()`

### 7.2 Codes d'Erreur

| Code | Signification | Cas d'Usage |
|------|---------------|-------------|
| `-32700` | Erreur analyse | JSON invalide |
| `-32600` | Requête invalide | Champs requis manquants |
| `-32602` | Paramètres invalides | Validation schema échouée |
| `-32001` | Non autorisé | JWT invalide |
| `-32002` | Interdit | Permissions insuffisantes |
| `-32003` | Limite débit dépassée | Trop de requêtes |
| `-32004` | Rejeu détecté | jti dupliqué |
| `-32005` | Token révoqué | Token révoqué utilisé |

---

## 8. Surveillance & Audit

> **📖 Documentation détaillée :** [Surveillance & Audit (FR)](docs/fr/SURVEILLANCE_AUDIT.md)

### 8.1 Journaux CloudWatch

| Groupe | Rétention | Alertes |
|--------|-----------|---------|
| `/ecs/ca-a2a-*` | 7 jours | Échecs auth > 10/min, Erreurs 5xx > 1% |
| Exports S3 | 90 jours | Audit compliance |

### 8.2 Métriques Clés

- CPU > 70% → Scale up ECS
- Échecs authentification > 10/min → Alerte sécurité
- Latence p99 > 2s → Investigation performance

---

## 9. Modèle de Menaces & Défenses

> **📖 Documentation détaillée :** [Modèle de Menaces (FR)](docs/fr/MODELE_MENACES_DEFENSES.md)

### 9.1 Analyse STRIDE

| Menace | Atténuation |
|--------|-------------|
| **Usurpation** | Signature RS256 + Token Binding |
| **Falsification** | Liaison hash corps |
| **Répudiation** | Journaux audit CloudWatch |
| **Divulgation Information** | TLS + AES-256 |
| **Déni Service** | Limitation débit + Circuit breaker |
| **Élévation Privilège** | Application RBAC |

### 9.2 Scénarios d'Attaque

**Scénario : Token JWT Volé**

| Étape | Défense | Résultat |
|-------|---------|----------|
| Attaquant intercepte JWT | ✅ Token volé | Token obtenu |
| Utiliser depuis machine différente | ❌ Token Binding (certificat incompatible) | **Bloqué C3** |

---

## 10. Opérations de Sécurité

> **📖 Documentation détaillée :** [Opérations Sécurité (FR)](docs/fr/OPERATIONS_SECURITE.md)

### 10.1 Maintenance

**Hebdomadaire :** Réviser journaux échecs auth, violations limite débit  
**Mensuelle :** Rotation secrets, réviser permissions IAM  
**Trimestrielle :** Audit sécurité externe, exercice reprise sinistre

### 10.2 Réponse Incidents

**Révocation Token (< 15 min) :**
```bash
curl -X POST https://orchestrator.ca-a2a.local:8001/admin/revoke-token \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"jti": "abc123", "reason": "Faille sécurité"}'
```

---

## 11. Référence d'Implémentation

### 11.1 Fichiers Clés

| Fichier | Objectif |
|---------|----------|
| `keycloak_auth.py` | Validation JWT, RBAC, Token Binding |
| `token_binding.py` | Implémentation RFC 8473 |
| `a2a_security.py` | Gestionnaire sécurité principal |
| `mcp_server.py` | Passerelle ressources centralisée |
| `mtls_manager.py` | Gestion certificats mTLS |

### 11.2 Configuration

```bash
# Keycloak
A2A_USE_KEYCLOAK=true
KEYCLOAK_URL=http://keycloak.ca-a2a.local:8080
KEYCLOAK_REALM=ca-a2a

# Sécurité
A2A_REQUIRE_AUTH=true
A2A_ENABLE_RATE_LIMIT=true
A2A_RATE_LIMIT_PER_MINUTE=300
A2A_ENABLE_REPLAY_PROTECTION=true
A2A_REPLAY_TTL_SECONDS=120
```

---

## Documentation Modulaire

Pour plus de détails, consultez les documents spécialisés :

1. 📘 [Architecture Système](docs/fr/ARCHITECTURE_SYSTEME.md)
2. 🛡️ [Couches de Sécurité](docs/fr/COUCHES_SECURITE_DEFENSE_EN_PROFONDEUR.md)
3. 🔐 [Authentification & Autorisation](docs/fr/AUTHENTIFICATION_AUTORISATION.md)
4. 🔌 [Serveur MCP](docs/fr/ACCES_RESSOURCES_SERVEUR_MCP.md)
5. 🌐 [Sécurité Réseau](docs/fr/SECURITE_RESEAU.md)
6. 💾 [Sécurité Données](docs/fr/SECURITE_DONNEES.md)
7. 📡 [Sécurité Protocole](docs/fr/SECURITE_PROTOCOLE.md)
8. 📊 [Surveillance & Audit](docs/fr/SURVEILLANCE_AUDIT.md)
9. ⚠️ [Modèle de Menaces](docs/fr/MODELE_MENACES_DEFENSES.md)
10. 🔧 [Opérations Sécurité](docs/fr/OPERATIONS_SECURITE.md)

---

**Fin du Document**
