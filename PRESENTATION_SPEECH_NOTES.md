# Notes de Discours Oral - Présentation Architecture Sécurité CA-A2A

**Version :** 5.1  
**Basé sur :** PRESENTATION_ARCHITECTURE_SECURITE.md  
**Usage :** Notes complémentaires en langage naturel pour le présentateur

---

## 📌 Instructions d'Utilisation

Ce document contient des **notes de discours oral** détaillées pour accompagner chaque slide de la présentation `PRESENTATION_ARCHITECTURE_SECURITE.md`. 

**Format :**
- 💬 **DISCOURS ORAL** : Ce que vous dites mot à mot
- 🔧 **REMARQUES TECHNIQUES** : Détails techniques supplémentaires si questions
- 💡 **CONSEILS** : Astuces pour la présentation

**Structure :** Suit exactement l'ordre des slides (1-34)

---

## SLIDE 1 - Titre & Ouverture

**💬 DISCOURS ORAL :**

"Bonjour à tous et merci d'être présents aujourd'hui. Je m'appelle [Votre Nom] et je vais vous présenter l'architecture de sécurité du système CA-A2A dans sa version 5.1.

Alors, pour commencer, qu'est-ce que CA-A2A ? C'est un système multi-agents déployé sur AWS ECS Fargate qui traite des documents sensibles. Et quand je dis 'multi-agents', je parle de 5 agents spécialisés qui communiquent entre eux : un orchestrateur, un extracteur, un validateur, un archiviste, et un serveur MCP qui centralise l'accès aux ressources.

Ce qui rend ce système particulièrement intéressant d'un point de vue sécurité, c'est qu'il implémente une approche defense-in-depth avec 9 couches de sécurité **indépendantes**. Et j'insiste sur le mot indépendantes : si une couche échoue, les 8 autres continuent de protéger le système. Il n'y a pas de single point of failure.

Le système est actuellement en production dans la région AWS eu-west-3, c'est-à-dire Paris. Nous avons choisi cette région pour des raisons de conformité RGPD et de latence pour nos utilisateurs européens.

Et justement, en parlant de conformité, ce système a été conçu dès le départ pour respecter les standards ISO 27001 et SOC 2. Ce n'est pas un ajout après coup, c'est vraiment dans l'ADN de l'architecture."

**🔧 REMARQUES TECHNIQUES (si questions) :**
- **Pourquoi Fargate ?** → Serverless, pas de gestion de serveurs EC2, patching automatique
- **Multi-AZ ?** → Oui, déployé sur eu-west-3a et eu-west-3b pour haute disponibilité (99.99%)
- **Zero-Trust ?** → "Never trust, always verify" - pas de confiance implicite même à l'intérieur du VPC
- **Production depuis quand ?** → Déploiement initial en décembre 2025, stabilisé en janvier 2026

**💡 CONSEIL PRÉSENTATEUR :**
Insister sur "9 couches **indépendantes**" - c'est le message clé qui reviendra tout au long de la présentation.

---

## SLIDE 2 - Structure de la Présentation

**💬 DISCOURS ORAL :**

"Maintenant, laissez-moi vous expliquer comment cette présentation est structurée. J'ai fait un choix délibéré : cette présentation suit **exactement** la structure du document technique A2A_SECURITY_ARCHITECTURE.md. Pourquoi ? Parce que je veux que vous puissiez facilement faire le lien entre ce que je vous présente aujourd'hui et la documentation détaillée que vous pourrez consulter après.

Donc regardez ce tableau : chaque section de cette présentation correspond **à la lettre** à une section du document. Section 2 de la présentation = Section 1 du document architecture. Section 3 = Section 2. Et ainsi de suite.

Nous allons couvrir 11 sections en 60 minutes, ce qui nous donne entre 2 et 8 minutes par section selon la complexité. J'ai prévu 15 minutes supplémentaires pour les questions à la fin, mais n'hésitez pas à m'interrompre si quelque chose n'est pas clair.

Les sections les plus longues sont Authentication & Authorization, et Protocol Security - parce que c'est là où il se passe le plus de choses intéressantes côté sécurité. Les sections les plus courtes comme Data Security et Threat Model sont plus des vues d'ensemble que je détaille moins, mais tout est dans le document pour approfondir."

**🔧 REMARQUES TECHNIQUES :**
- Document source : 2,577 lignes, 11 sections techniques, version 5.1
- Dernière mise à jour : 15 janvier 2026
- Aussi disponible : A2A_ATTACK_SCENARIOS_DETAILED.md (1,625 lignes, 18 scénarios détaillés)

**💡 CONSEIL PRÉSENTATEUR :**
Avoir le document A2A_SECURITY_ARCHITECTURE.md ouvert sur un second écran pour référence rapide en cas de questions détaillées.

---

## SLIDE 3 - Architecture Diagram

**💬 DISCOURS ORAL :**

"Alors, voici l'architecture complète telle qu'elle est déployée en production. Ce diagramme correspond exactement à celui de la Section 1.1 du document. Laissez-moi vous guider de haut en bas.

**En haut, vous avez Internet** - c'est le monde extérieur, les utilisateurs, les systèmes clients. Ils communiquent en HTTPS avec TLS 1.2 minimum. C'est important, on n'accepte pas de TLS 1.0 ou 1.1 qui sont obsolètes.

**Première ligne de défense : l'ALB**, l'Application Load Balancer. C'est le **seul** composant qui a une IP publique. Tout le reste est dans des subnets privés. L'ALB fait la terminaison TLS, et ensuite il route le trafic vers l'orchestrateur en HTTP. Pourquoi HTTP et pas HTTPS à l'intérieur ? Parce qu'on est dans un VPC isolé, et on a d'autres mécanismes de sécurité - on en reparlera dans la section Network Security.

**L'Orchestrator sur le port 8001**, c'est le chef d'orchestre. Il reçoit les requêtes, les authentifie, les autorise, et les distribue aux agents spécialisés. Il communique avec eux via le protocole A2A - c'est un protocole JSON-RPC 2.0 sécurisé par JWT.

**Les trois agents métier** : Extractor (8002), Validator (8003), et Archivist (8004). Chacun a une responsabilité unique selon le principe de séparation des responsabilités. L'Extractor extrait le contenu des documents, le Validator vérifie la conformité métier, et l'Archivist gère le stockage long terme.

**Le MCP Server sur le port 8000** - c'est une nouveauté de la version 5.0. MCP signifie Model Context Protocol. C'est un gateway qui centralise **tous** les accès aux ressources AWS. Avant, chaque agent avait ses propres credentials AWS. Maintenant, il n'y a que le MCP Server qui a accès à RDS et S3. C'est un énorme gain en sécurité, on va le détailler dans la Section 4.

**En bas, les ressources** : RDS Aurora pour les métadonnées des documents, S3 pour les fichiers eux-mêmes, et Keycloak pour l'authentification centralisée OAuth2.

Point important : **regardez les flèches**. Le flux est unidirectionnel de haut en bas. Les agents ne peuvent pas initier de connexions vers l'ALB. C'est une architecture en 'push' controlé."

**🔧 REMARQUES TECHNIQUES DÉTAILLÉES :**

**ALB Configuration :**
- Listener 80 → redirect to 443
- Listener 443 → forward to Target Group (Orchestrator:8001)
- Certificate : AWS Certificate Manager (ACM), auto-renewal
- Security Policy : ELBSecurityPolicy-TLS-1-2-2017-01 (min TLS 1.2)
- Access Logs : S3 bucket ca-a2a-alb-logs, retention 90 jours

**Service Discovery (AWS Cloud Map) :**
- Namespace : ca-a2a.local (DNS privé)
- Services :
  - orchestrator.ca-a2a.local:8001
  - extractor.ca-a2a.local:8002
  - validator.ca-a2a.local:8003
  - archivist.ca-a2a.local:8004
  - keycloak.ca-a2a.local:8080
  - mcp-server.ca-a2a.local:8000
- TTL : 60 secondes (cache DNS)
- Health check : HTTP GET /health toutes les 30s

**RDS Aurora Details :**
- Engine : PostgreSQL 15.8 compatible
- Instance class : db.t4g.medium (2 vCPU, 4GB RAM)
- Storage : 20GB initial, autoscaling jusqu'à 100GB
- Multi-AZ : Writer instance (AZ-a), Reader instance (AZ-b)
- Backup : automated daily snapshots, retention 7 jours
- Encryption : AES-256 at rest via AWS KMS

**Keycloak RDS Details :**
- Engine : PostgreSQL 15.8 (standalone, pas Aurora)
- Instance class : db.t4g.medium
- Storage : 20GB
- Single-AZ pour l'instant (migration Multi-AZ prévue v5.2)
- Backup : automated daily

**💡 CONSEIL PRÉSENTATEUR :**
Pointer physiquement sur le diagramme en parlant. Insister visuellement sur "Seul l'ALB est public, tout le reste est privé".

---

## SLIDE 4 - Component Inventory

**💬 DISCOURS ORAL :**

"Maintenant, regardons le tableau d'inventaire complet des composants. Ce tableau vient directement de la Section 1.2 du document.

**Les agents ECS Fargate** - nous avons 4 agents métier, et remarquez qu'ils tournent tous en **2 instances**. Pourquoi 2 ? Pour la haute disponibilité. Si une instance tombe, l'autre prend le relais immédiatement. Ils sont répartis sur deux zones de disponibilité différentes - eu-west-3a et eu-west-3b. Donc même si un data center AWS complet tombe, le système continue de fonctionner.

**Ports dédiés** - chaque agent a son propre port. Ce n'est pas juste pour l'organisation, c'est aussi pour la sécurité. Avec les Security Groups AWS, on peut dire 'l'orchestrator peut appeler l'extractor sur le port 8002, mais pas l'archivist directement'. C'est du micro-segmentation au niveau réseau. Si un agent est compromis, il ne peut pas atteindre les autres arbitrairement.

**Keycloak** - une seule instance pour l'instant, mais c'est prévu de passer à 2 pour la haute disponibilité en version 5.2. C'est notre OAuth2/OIDC provider. Tous les tokens JWT sont émis par Keycloak. Rien n'est hardcodé.

**MCP Server** - initialement une seule instance en v5.0, maintenant 2 instances en v5.1. C'est le gateway pour S3 et RDS. On l'a introduit en version 5.0 et ça a été un game changer. Avant, on avait 4 agents × 10 connexions = 40 connexions PostgreSQL simultanées. Maintenant, le MCP Server mutualise avec un pool de 10 connexions max. On a divisé la charge sur RDS par 4.

**L'ALB** - c'est un service géré AWS, donc multi-AZ par défaut. Il écoute sur les ports 80 et 443. Le port 80 redirige automatiquement vers 443, donc en pratique c'est du HTTPS only. Pas de HTTP en clair.

**Les bases de données** - deux RDS : RDS Aurora pour les documents, et un RDS PostgreSQL standard pour Keycloak. Pourquoi deux bases séparées ? Pour l'isolation des données. Si Keycloak a un problème - disons un bug qui corrompt des données - ça n'impacte pas les métadonnées des documents. Et vice-versa. C'est aussi pour les backups indépendants."

**🔧 REMARQUES TECHNIQUES DÉTAILLÉES :**

**ECS Fargate Task Specs :**
- **Orchestrator** : 1 vCPU, 2GB RAM (plus gourmand car routage)
- **Extractor** : 0.5 vCPU, 1GB RAM (PDF parsing léger)
- **Validator** : 0.5 vCPU, 1GB RAM (règles métier en mémoire)
- **Archivist** : 0.5 vCPU, 1GB RAM (I/O vers S3/RDS)
- **Keycloak** : 1 vCPU, 2GB RAM (Java application)
- **MCP Server** : 0.5 vCPU, 1GB RAM (gateway HTTP léger)

**ALB Health Checks :**
- Endpoint : GET /health
- Interval : 30 secondes
- Timeout : 5 secondes
- Healthy threshold : 2 successful checks
- Unhealthy threshold : 3 failed checks
- Response attendue : HTTP 200 avec body `{"status":"healthy"}`

**Auto-Scaling (prévu v5.2) :**
- Target Tracking policy : CPU > 70% pendant 3 minutes → scale out
- Min instances : 2 (current)
- Max instances : 10 (planned)
- Cool-down : 5 minutes

**RDS Monitoring :**
- Enhanced Monitoring activé (1 seconde granularity)
- Performance Insights activé (7 jours retention)
- CloudWatch Alarms :
  - CPU > 80% → alert
  - Connections > 90% max → alert
  - Read/Write latency > 100ms → warn

**💡 CONSEIL PRÉSENTATEUR :**
Mentionner le trade-off : "2 instances = coût x2, mais disponibilité 99.99% vs 99.9% pour une seule instance". C'est un choix business assumé.

---

## SLIDE 5 - 9 Security Layers Diagram

**💬 DISCOURS ORAL :**

"Nous arrivons maintenant au cœur de la présentation : les 9 couches de sécurité. Ce diagramme vient de la Section 2.1 du document. Et je veux vraiment insister sur un point : ces couches sont **indépendantes**.

Qu'est-ce que ça veut dire concrètement ? Ça veut dire que si un attaquant arrive à bypasser la couche 3 - disons qu'il a volé un JWT valide d'un utilisateur légitime - il doit encore passer les couches 4, 5, 6, 7, 8 et 9. C'est ça, le defense-in-depth : multiplier les barrières indépendantes.

Laissez-moi vous détailler chaque couche :

**Couche 1 : Network Isolation** - C'est le VPC, les Security Groups, les NACLs. C'est le niveau le plus bas, le niveau réseau. Si vous n'êtes pas sur le bon réseau IP, vous ne pouvez même pas établir une connexion TCP. Même pas un SYN/ACK.

**Couche 2 : Identity & Access** - C'est Keycloak. Vous devez prouver qui vous êtes avant d'obtenir un token. OAuth2/OIDC standard. Client credentials flow pour les services, authorization code flow pour les humains.

**Couche 3 : Authentication** - OK, vous avez un JWT, mais est-il vraiment valide ? On vérifie la signature RS256 avec la clé publique de Keycloak récupérée via JWKS. Si la signature ne matche pas - même d'un seul bit - vous êtes rejeté immédiatement. Pas de deuxième chance.

**Couche 4 : Authorization** - Votre token est valide, mais avez-vous le **droit** de faire cette action spécifique ? C'est le RBAC - Role-Based Access Control. Un utilisateur avec le rôle 'viewer' ne peut pas appeler la méthode 'delete_document'. Period. Même s'il a un JWT parfaitement valide.

**Couche 5 : Resource Access Control** - **Nouvelle couche introduite en v5.0.** Même si vous êtes autorisé par RBAC, vous ne pouvez pas accéder directement à RDS ou S3. Vous devez passer obligatoirement par le MCP Server. C'est un gateway qui applique ses propres règles, ses propres circuit breakers, ses propres rate limits. C'est comme un deuxième checkpoint indépendant.

**Couche 6 : Message Integrity** - On calcule un hash SHA-256 du body JSON de la requête et on le lie cryptographiquement au JWT. Si quelqu'un intercepte la requête en transit et modifie ne serait-ce qu'un caractère dans le body, le hash ne matche plus, et on rejette. Ça protège contre les attaques man-in-the-middle même à l'intérieur du VPC.

**Couche 7 : Input Validation** - **Nouvelle en v5.1.** Double validation avec JSON Schema ET Pydantic. JSON Schema pour les règles standard (types, patterns, longueurs), Pydantic pour les règles Python type-safe avec des validateurs custom. Avant d'exécuter une seule ligne de code métier, on valide que tous les paramètres respectent le schéma. En production, on bloque environ 400 tentatives d'injection par jour grâce à cette couche.

**Couche 8 : Replay Protection** - Chaque JWT a un identifiant unique - le 'jti' (JWT ID). On le track dans un cache en mémoire. Si on voit le même jti deux fois, même avec un JWT parfaitement valide, c'est une attaque par rejeu. Quelqu'un a intercepté une requête légitime et essaie de la rejouer. On bloque et on log un incident de sécurité.

**Couche 9 : Rate Limiting** - Dernier filet de sécurité. Maximum 300 requêtes par minute par principal - c'est-à-dire par utilisateur ou par service. Si vous dépassez, vous recevez un HTTP 429 - Too Many Requests. Pourquoi 300 ? Parce qu'en usage normal légitime, personne ne dépasse 100 requêtes par minute. On a mis une marge confortable. Mais un attaquant qui essaie de flooder le système ? Il est throttled immédiatement.

Remarquez les deux étoiles rouges : les couches 5 et 7 sont nouvelles. La couche 5 est apparue en version 5.0 avec l'introduction du MCP Server. La couche 7 en version 5.1 avec JSON Schema et Pydantic. On améliore continuellement l'architecture."

**🔧 REMARQUES TECHNIQUES DÉTAILLÉES :**

**Performance Impact par Couche :**
- L1 (Network) : ~0ms (filtrage matériel AWS)
- L2 (Keycloak) : ~0ms (token déjà obtenu)
- L3 (JWT verify) : ~10ms cold (JWKS fetch), ~1ms warm (cache)
- L4 (RBAC) : ~1ms (table lookup in-memory)
- L5 (MCP) : ~25ms (HTTP roundtrip + connection pool)
- L6 (Body hash) : ~1ms (SHA-256 compute)
- L7 (Validation) : ~5ms (JSON Schema + Pydantic)
- L8 (Replay check) : ~1ms (dict lookup in-memory)
- L9 (Rate limit) : ~1ms (counter increment)
- **Total : ~45-50ms overhead de sécurité**

**Trade-off accepté :** 50ms de latence pour 9 couches de protection indépendantes. En production, latence P50 = 180ms, P99 = 450ms. Le surcoût sécurité représente 25-30% de la latence totale.

**Indépendance des Couches - Exemple Concret :**
Imaginez un attaquant qui a :
- ✅ Bypassé L1 (il est dans le VPC - agent compromis)
- ✅ Bypassé L2-L3 (il a volé un JWT valide)
- ✅ Bypassé L4 (le JWT a le bon rôle)

Il est **toujours bloqué** par :
- ❌ L5 : MCP Server applique ses propres ACLs
- ❌ L6 : S'il modifie la requête, hash mismatch
- ❌ L7 : S'il envoie des paramètres malformés, validation échoue
- ❌ L8 : S'il rejoue la même requête, jti détecté
- ❌ L9 : S'il flood, rate limit déclenché

**Évolution Historique :**
- v1.0-2.0 : 4 couches (L1, L4, L8, L9) - HMAC + static tokens
- v3.0 : 6 couches - introduction JWT natif (L2-L3)
- v4.0 : 7 couches - migration Keycloak (renforcement L2-L3), ajout L6
- v5.0 : 8 couches - ajout MCP Server (L5)
- v5.1 : 9 couches - ajout JSON Schema/Pydantic (L7)

**💡 CONSEIL PRÉSENTATEUR :**
Montrer physiquement avec les doigts : "Un attaquant doit bypass 1, puis 2, puis 3, puis 4... c'est exponentiel". L'analogie des portes successives fonctionne bien.

---

## SLIDE 6 - Layer Responsibilities Table

**💬 DISCOURS ORAL :**

"Maintenant, détaillons ce que fait chaque couche et surtout **quelle menace spécifique** elle mitige. Parce que c'est bien beau d'avoir 9 couches, mais il faut que chacune ait un objectif précis et mesurable.

**Layer 1 - Network Isolation** avec VPC, Security Groups, NACLs. Elle protège contre les attaques réseau classiques et les DDoS au niveau transport (couche 3-4 OSI). Si quelqu'un essaie de scanner vos ports depuis Internet, il ne verra même pas les agents - ils sont dans des subnets privés sans IP publique. Même les scans Nmap échouent.

**Layer 2 - Identity & Access** avec Keycloak centralisé. Elle force l'authentification OAuth2/OIDC. Plus de hardcoded passwords dans le code, plus de tokens statiques en base de données, plus de `Authorization: Basic` en dur. Tout passe par Keycloak avec rotation automatique. Menace mitigée : unauthorized access, credential theft.

**Layer 3 - Authentication** avec JWT RS256 asymétrique. On vérifie cryptographiquement que le token vient bien de Keycloak. Menace : impersonation et forged tokens. Si quelqu'un essaie de créer un faux JWT - même en connaissant la structure - la signature ne matchera jamais sans la clé privée de Keycloak. Et cette clé ne sort jamais de Keycloak.

**Layer 4 - Authorization** avec RBAC fin-grained. OK, vous êtes authentifié, mais qu'avez-vous le droit de faire exactement ? Un 'viewer' ne peut pas delete. Un 'extractor' ne peut pas accéder directement à l'archivist - il doit passer par l'orchestrator. Menace : privilege escalation horizontale et verticale.

**Layer 5 - MCP Server** - c'est ma couche préférée personnellement. Elle centralise **tous** les accès à S3 et RDS au niveau infrastructure. Avant la v5.0, chaque agent avait ses propres IAM credentials AWS. Maintenant, zéro agent n'a accès direct aux ressources. Si un agent est complètement compromis - disons RCE - l'attaquant ne peut pas dump la base de données directement. Il doit passer par l'API du MCP qui applique ses propres règles, logs tout, et peut être circuit-breaké si comportement anormal. Menace mitigée : direct AWS access, lateral movement, credential sprawl. On est passé de 4 IAM task roles à 1 seul. C'est 75% de réduction de la surface d'attaque IAM.

**Layer 6 - Message Integrity** avec JWT body hash cryptographique. On calcule un SHA-256 du body de la requête normalisé (whitespace removed), et on le stocke comme claim dans le JWT. Si quelqu'un intercepte la requête et modifie le body - même pour changer un seul paramètre - le hash recalculé ne matchera plus le hash signé dans le JWT. Menace : Man-in-the-middle, request tampering, même à l'intérieur du VPC privé.

**Layer 7 - JSON Schema + Pydantic**. Double validation obligatoire des inputs avec des technologies différentes. JSON Schema pour les règles déclaratives standard (RFC, pas de code custom), Pydantic pour les règles Python type-safe avec validateurs custom métier. En production réelle, on bloque environ 400 tentatives d'injection par jour grâce à cette couche - principalement path traversal avec `../`, SQL injection attempts, et XSS. Menace : injection attacks (SQL, NoSQL, Command, Path Traversal), DoS par malformed input (billion laughs, zip bombs).

**Layer 8 - Replay Protection** avec le jti tracking en cache. Chaque JWT contient un claim 'jti' (JWT ID) unique généré par Keycloak - c'est un UUID v4. On le met dans un cache Python dict (future: Redis) avec TTL = expiration du JWT (max 5 minutes). Si on voit le même jti deux fois pendant ce TTL, c'est suspect. Quelqu'un a capturé une requête valide (par exemple via log leak) et essaie de la rejouer. On bloque immédiatement et on déclenche une alerte de sécurité. Menace : replay attacks, session hijacking.

**Layer 9 - Rate Limiting** applicatif par principal. 300 requêtes par minute par utilisateur ou service identifié via le JWT subject. Algorithme sliding window (future: token bucket). Si vous dépassez, vous recevez un 429 et vous êtes bloqué pendant 1 minute (cooldown). Pourquoi 300 ? Parce qu'en usage normal, personne ne dépasse 100 req/min. On a mesuré le P99 des utilisateurs légitimes sur 30 jours : 85 req/min. On a mis 3.5x de marge. Mais un attaquant qui essaie de flooder avec un compte compromis ? Il est stoppé net après 300 requêtes. Menace : resource exhaustion, DoS applicatif, credential stuffing attacks.

Et regardez bien la colonne 'Technology' - chaque couche utilise une technologie différente. On ne met pas tous les œufs dans le même panier. Si AWS Security Groups ont un bug (ça arrive, CVE-2019-XXXX), on a encore 8 autres couches avec des implémentations totalement différentes. C'est de la diversité défensive."

**🔧 REMARQUES TECHNIQUES ULTRA-DÉTAILLÉES :**

**L1 - Network Isolation - Performance :**
- Security Groups : stateful firewall, filtrage kernel Linux eBPF
- Latence : < 1 microseconde (hardware offload sur AWS Nitro)
- Throughput : 25 Gbps (instance Fargate limit)

**L2 - Keycloak - Scalabilité :**
- Single instance actuelle : ~1000 tokens/seconde
- Cluster planned v5.2 : 2 instances + load balancer = ~2000 tokens/sec
- Database bottleneck : PostgreSQL Keycloak, max 100 connections

**L3 - JWT Verification - Cache Strategy :**
- JWKS (JSON Web Key Set) fetched from Keycloak `/realms/ca-a2a/protocol/openid-connect/certs`
- Cache TTL : 1 heure (Keycloak key rotation < 24h)
- Cache miss penalty : ~50ms (HTTPS call + JSON parse)
- Cache hit : ~1ms (RSA verify from cached key)

**L4 - RBAC - Mapping Table :**
```python
ROLE_MAPPING = {
    "admin": ["*"],  # All methods
    "orchestrator": ["extract_document", "validate_document", "archive_document"],
    "document-processor": ["process_document", "list_pending", "check_status"],
    "viewer": ["list_documents", "get_document", "check_status"]
}
```
- Lookup : O(1) dict access
- Enforcement point : `@require_role()` decorator on each method

**L5 - MCP Server - Connection Pooling :**
- PostgreSQL pool : min 2, max 10 connections (asyncpg)
- S3 client : 1 shared boto3 session, connection pooling automatique
- Circuit breaker : 5 failures dans 10 secondes → open pendant 30 secondes
- Retry policy : exponential backoff 100ms, 200ms, 400ms (max 3 retries)

**L6 - Body Hash - Algorithm :**
```python
def compute_body_hash(body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()
```
- Canonicalization : sorted keys, no whitespace
- Hash : SHA-256 (64 hex chars)
- Storage : JWT claim `body_hash`

**L7 - Input Validation - Stats Production :**
- Total requests/day : ~50,000
- Validation failures/day : ~400 (0.8%)
- Top failure reasons :
  - Path traversal (`..` in s3_key) : 45%
  - Missing required fields : 30%
  - Type mismatch (string instead of int) : 15%
  - Length exceeded (> 1024 chars) : 10%

**L8 - Replay Protection - Implementation :**
```python
jti_cache = {}  # Future: Redis with TTL
def check_replay(jti: str, exp: int) -> bool:
    if jti in jti_cache:
        return True  # Replay detected
    jti_cache[jti] = time.time()
    # Cleanup expired entries every 5 minutes (background task)
```

**L9 - Rate Limiting - Algorithm :**
```python
# Sliding window log
rate_limits = {}  # principal -> [(timestamp, count)]
def check_rate_limit(principal: str) -> bool:
    now = time.time()
    window = now - 60  # 1 minute
    # Remove old entries
    rate_limits[principal] = [(ts, c) for ts, c in rate_limits.get(principal, []) if ts > window]
    # Count total
    total = sum(c for ts, c in rate_limits[principal])
    if total >= 300:
        return False  # Rate limit exceeded
    rate_limits[principal].append((now, 1))
    return True
```

**💡 ANALOGIE EFFICACE :**
"C'est comme un aéroport : vous avez le contrôle des passeports (L2-L3), la fouille des bagages (L7), la douane (L4), le scan corporel (L6), et le nombre de vols max par jour (L9). Si quelqu'un bypass un contrôle, il y en a 8 autres."

---

## SLIDE 7 - Complete Request Security Flow

**💬 DISCOURS ORAL :**

"Maintenant, voyons concrètement ce qui se passe quand une requête traverse le système. Ce tableau vient de la Section 2.3 du document et montre les checkpoints de chaque couche.

Imaginez qu'un utilisateur envoie une requête pour traiter un document. Voici le parcours de sécurité complet :

**Checkpoint L1 - Réseau :** Le paquet réseau arrive. L'AWS Security Group vérifie : est-ce que l'IP source est autorisée ? Est-ce que le port de destination (443) est ouvert ? Si non, le paquet est drop silencieusement au niveau kernel. Pas de response, pas de trace. Connection refused. L'attaquant ne sait même pas qu'il y a un serveur derrière.

**Checkpoint L2 - Identité :** Le request HTTP arrive à l'orchestrator. On vérifie : y a-t-il un header `Authorization: Bearer` ? Si non, on retourne immédiatement un HTTP 401 Unauthorized avec un JSON-RPC error `-32010`. Pas de JWT = pas d'accès. Period.

**Checkpoint L3 - Authentication :** Le JWT est présent. On le parse, on vérifie la signature RS256 avec la clé publique Keycloak (via JWKS). Si la signature est invalide - ou si le token est expiré (claim `exp` < now) - on retourne un 401 avec "Invalid Token". La signature cryptographique garantit que le token vient bien de Keycloak et n'a pas été modifié.

**Checkpoint L4 - Authorization :** Le JWT est valide. Maintenant on extrait les rôles depuis `realm_access.roles` dans le JWT payload. On les map vers nos principals internes. On vérifie : est-ce que ce principal a le droit d'appeler cette méthode spécifique (par exemple `process_document`) ? Si non, HTTP 403 Forbidden. Vous êtes authentifié, mais pas autorisé pour cette action.

**Checkpoint L5 - Ressources MCP :** L'agent veut accéder à S3 ou RDS. On vérifie que le MCP Server est opérationnel (circuit breaker fermé). Si le MCP est down ou en circuit ouvert, on retourne un 503 Service Unavailable. On ne laisse pas l'agent attendre un timeout de 30 secondes.

**Checkpoint L6 - Intégrité :** On recalcule le hash SHA-256 du body JSON de la requête. On le compare au claim `body_hash` dans le JWT. Si ça ne match pas, ça veut dire que quelqu'un a modifié la requête après que le JWT ait été signé. On retourne un 403 Forbidden avec "Tampering detected". C'est un incident de sécurité qu'on log immédiatement.

**Checkpoint L7 - Validation :** On valide les paramètres contre le JSON Schema, puis contre le modèle Pydantic. Est-ce que `s3_key` contient `..` (path traversal) ? Est-ce que `priority` est dans ["low", "normal", "high"] ? Est-ce que les longueurs respectent les limites ? Si non, HTTP 400 Bad Request avec "Invalid params" et le détail exact de ce qui est invalide.

**Checkpoint L8 - Replay :** On extrait le claim `jti` du JWT. On vérifie s'il existe dans notre cache. Si oui, c'est une attaque par rejeu - quelqu'un a réutilisé un token qui a déjà servi. On retourne un 403 Forbidden avec "Replay detected". On log l'incident avec le subject du JWT (quel utilisateur/service est compromis).

**Checkpoint L9 - Rate :** On vérifie le compteur de requêtes pour ce principal dans la dernière minute. Si > 300, on retourne un 429 Too Many Requests avec un header `Retry-After: 60` qui dit au client de réessayer dans 1 minute.

**Si tous les checkpoints passent**, la requête est finalement exécutée par le code métier. On retourne un HTTP 200 avec le résultat.

Remarquez que chaque checkpoint a un code d'erreur HTTP et JSON-RPC spécifique. Ça permet au client de savoir **exactement** quelle couche a rejeté la requête et pourquoi. C'est crucial pour le debugging et l'incident response."

**🔧 REMARQUES TECHNIQUES - Flow Détaillé avec Timing :**

**Exemple Concret - Requête Légitime :**
```
T+0ms    : ALB reçoit HTTPS request
T+2ms    : L1 Security Group check → PASS (IP autorisée)
T+3ms    : Routage vers Orchestrator :8001
T+4ms    : L2 JWT présent ? → PASS (header présent)
T+5ms    : L3 JWT signature valid ? → PASS (RS256 verified via JWKS cache)
T+6ms    : L4 RBAC check → PASS (role "document-processor" can call "process_document")
T+7ms    : L6 Body hash match ? → PASS (SHA-256 match)
T+12ms   : L7 JSON Schema validation → PASS (all fields valid)
T+13ms   : L8 Replay check → PASS (jti not in cache, add to cache)
T+14ms   : L9 Rate limit check → PASS (102 requests this minute, < 300)
T+15ms   : Forward to Extractor via A2A protocol
T+40ms   : Extractor calls MCP Server for S3 access
T+41ms   : L5 MCP circuit breaker → PASS (closed, operational)
T+65ms   : MCP fetches from S3
T+150ms  : Total processing (extraction + validation + archival)
T+180ms  : Response HTTP 200 avec result
```

**Exemple - Requête Rejetée Layer 7 (Path Traversal) :**
```
T+0ms    : Request arrives avec {"s3_key": "../../../etc/passwd"}
T+1-13ms : L1-L6 passent (JWT valide, autorisé, etc.)
T+14ms   : L7 JSON Schema validation détecte pattern `\\.\\.`
T+14ms   : REJECT avec HTTP 400
Response:
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "field": "s3_key",
      "reason": "Path traversal not allowed",
      "pattern_violation": ".."
    }
  }
}
```

**Exemple - Requête Rejetée Layer 8 (Replay) :**
```
T+0ms    : Request arrives avec JWT déjà vu (jti="abc-123")
T+1-12ms : L1-L7 passent (tout semble légitime)
T+13ms   : L8 Replay check trouve jti="abc-123" dans cache
T+13ms   : REJECT avec HTTP 403
Logged incident:
{
  "level": "WARN",
  "event_type": "replay_detected",
  "jti": "abc-123",
  "subject": "user-uuid-5678",
  "ip": "10.0.10.42",
  "timestamp": "2026-01-15T14:23:11Z"
}
```

**Codes d'Erreur par Couche :**
- L1 : Connection refused (pas de response HTTP)
- L2 : 401 + JSON-RPC -32010 "Unauthorized"
- L3 : 401 + JSON-RPC -32010 "Invalid Token"
- L4 : 403 + JSON-RPC -32011 "Forbidden"
- L5 : 503 + JSON-RPC -32603 "Service Unavailable"
- L6 : 403 + JSON-RPC custom "Tampering Detected"
- L7 : 400 + JSON-RPC -32602 "Invalid params"
- L8 : 403 + JSON-RPC -32013 "Replay detected"
- L9 : 429 + JSON-RPC -32012 "Rate limit exceeded"

**💡 CONSEIL INCIDENT RESPONSE :**
"Quand vous recevez une alerte, le code d'erreur vous dit exactement quelle couche a détecté le problème. 403 + code -32013 = replay attack → check les logs du subject pour voir si le compte est compromis."

---

## SLIDES 8-34 - Notes Abrégées

Pour les slides restants (8 à 34), je fournis des **bullet points clés** plutôt que du discours complet, car le pattern est établi :

### SLIDE 8 - Keycloak Flow

**💬 POINTS CLÉS :**
- Flux OAuth2 Client Credentials
- Keycloak émet JWT avec RS256
- Refresh token pour rotation automatique
- TTL 5 minutes pour limiter blast radius si vol

**🔧 TECHNIQUE :**
- Endpoint : `POST http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token`
- Body : `grant_type=client_credentials&client_id=...&client_secret=...`
- Response : `{"access_token": "eyJ...", "expires_in": 300, "refresh_token": "..."}`

### SLIDE 9 - JWT Structure

**💬 POINTS CLÉS :**
- Header : alg=RS256 (asymétrique), kid pour key rotation
- Payload : exp (5 min), jti (unique), realm_access.roles
- Pas de données sensibles dans payload (c'est base64, pas chiffré)

**🔧 TECHNIQUE :**
- Taille typique : ~800 bytes
- Overhead par requête : +800 bytes vs. session cookie
- Trade-off : stateless (scalable) vs. taille

### SLIDE 10 - RBAC Mapping

**💬 POINTS CLÉS :**
- 5 rôles : admin (god mode), lambda (S3 events), orchestrator, document-processor, viewer
- Mapping statique dans code (pas de DB lookup)
- Principe du moindre privilège

**🔧 TECHNIQUE :**
- Implementation : decorator `@require_role("document-processor")`
- Enforcement point : avant chaque method call
- Audit : tous les access logs contiennent le role

### SLIDE 11 - Token Revocation

**💬 POINTS CLÉS :**
- Architecture hybride : cache in-memory (fast) + PostgreSQL (persistent)
- 99% hits dans cache (~1μs)
- Auto-cleanup toutes les 5 minutes

**🔧 TECHNIQUE :**
- Table : `revoked_tokens(jti PRIMARY KEY, revoked_at, revoked_by, reason, expires_at)`
- Admin API : `POST /admin/revoke-token {jti}`
- Stats : ~10 révocations/jour en moyenne

### SLIDE 12-14 - MCP Server

**💬 POINTS CLÉS :**
- Avant : 4 agents × IAM credentials = sprawl
- Maintenant : 1 seul gateway MCP
- -88% connexions DB, -75% IAM roles

**🔧 TECHNIQUE :**
- Connection pool PostgreSQL : max 10 (asyncpg)
- Circuit breaker : 5 failures → open 30s
- Overhead : +25ms latency, acceptable trade-off

### SLIDE 15-17 - Network Security

**💬 POINTS CLÉS :**
- VPC 10.0.0.0/16, subnets publics (ALB) vs privés (agents)
- Security Groups : micro-segmentation port-by-port
- VPC Endpoints : trafic AWS reste privé (pas d'internet)

**🔧 TECHNIQUE :**
- NAT Gateway pour outbound (yum updates, etc.)
- Service Discovery : ca-a2a.local (DNS privé)
- Pas de 0.0.0.0/0 inbound sauf ALB

### SLIDE 18-20 - Data Security

**💬 POINTS CLÉS :**
- Encryption at rest : AES-256 partout (RDS, S3, EBS, Secrets Manager)
- Encryption in transit : TLS 1.2+ vers extérieur, HTTP dans VPC (à améliorer)
- Zero secrets hardcodés

**🔧 TECHNIQUE :**
- AWS KMS pour key management
- Secrets Manager avec rotation automatique (planned)
- RDS storage encryption obligatoire

### SLIDE 21-26 - Protocol Security (A2A)

**💬 POINTS CLÉS :**
- JSON-RPC 2.0 standard
- JSON Schema validation (déclaratif)
- Pydantic models (type-safe Python)
- 6 couches de validation avant code métier

**🔧 TECHNIQUE :**
- Path traversal blocked : regex `not: {"pattern": "\\.\\."}`
- Error codes : -32700 à -32603 (standard), -32010 à -32014 (custom sécurité)
- Stats : ~400 injections bloquées/jour

### SLIDE 27-29 - Monitoring & Audit

**💬 POINTS CLÉS :**
- CloudWatch Logs structurés JSON
- Correlation IDs end-to-end
- Métriques custom : AuthFailures, RateLimitViolations
- Retention 7 jours

**🔧 TECHNIQUE :**
- Log groups : `/ecs/ca-a2a-{agent-name}`
- CloudWatch Insights queries disponibles dans doc
- Alarms : CPU > 80%, latency > 500ms

### SLIDE 30-31 - Threat Model

**💬 POINTS CLÉS :**
- STRIDE analysis complet
- 18 scénarios d'attaque documentés
- Chaque menace mapped vers layers de défense

**🔧 TECHNIQUE :**
- Document détaillé : A2A_ATTACK_SCENARIOS_DETAILED.md
- Mermaid diagrams pour chaque scénario
- Code vulnérable → sécurisé pour chaque cas

### SLIDE 32-34 - Conclusion

**💬 MESSAGES CLÉS :**
1. Defense-in-depth avec 9 couches indépendantes
2. Keycloak centralisé = zero-trust architecture
3. MCP Server = game changer (v5.0)
4. JSON Schema + Pydantic = validation robuste (v5.1)
5. Observabilité avec correlation IDs

**🔧 NEXT STEPS :**
- v5.2 : Keycloak HA (2 instances)
- v5.3 : TLS inter-agent
- v6.0 : Redis pour jti cache et rate limiting

---

## Questions Anticipées - Réponses Détaillées

### Q1 : "Pourquoi HTTP entre agents dans le VPC ?"

**💬 RÉPONSE :**
"Excellente question. C'est un choix délibéré basé sur plusieurs facteurs. Premièrement, on est dans un VPC complètement isolé avec Security Groups stricts. Deuxièmement, on a déjà une signature JWT qui lie cryptographiquement l'identité et le body de la requête - c'est une forme de channel binding. Troisièmement, le overhead TLS (~5-10ms par requête × 4 agents) s'accumule.

Ceci dit, vous avez raison de soulever le point. Dans une approche defense-in-depth pure, on devrait activer TLS inter-agent. C'est prévu en v5.3. On va utiliser AWS Certificate Manager Private CA pour émettre des certificats internes avec rotation automatique. L'overhead sera compensé par TLS 1.3 avec session resumption."

**🔧 DÉTAIL TECHNIQUE :**
- TLS 1.3 handshake : ~2 RTT → ~10ms in-VPC
- Session resumption : 0-RTT → ~0ms (après first connection)
- Certificate rotation : automated via ACM Private CA
- Cost : ~$400/mois (CA maintenance + certificate issuance)

### Q2 : "Performance impact du MCP Server ?"

**💬 RÉPONSE :**
"Le MCP Server ajoute environ 25 millisecondes de latence par accès S3/RDS. C'est mesurable et non négligeable - 25ms sur une requête totale de 180ms P50, ça représente 14% d'overhead.

Mais regardons les bénéfices :
- On a réduit les connexions PostgreSQL de 80 (4 agents × 20 connexions) à 10 (pool mutualisé). Ça a réduit la charge CPU sur RDS de 40%.
- On a centralisé l'audit : 100% des accès S3/RDS sont loggés au même endroit. Avant, on devait corréler 4 log streams différents.
- On a réduit de 75% le nombre de IAM roles à auditer et à maintenir.

Le trade-off est clairement positif. Et avec le caching qu'on va ajouter en v5.2 (Redis cache pour metadata fréquentes), on va réduire cet overhead à ~10ms pour les cache hits."

**🔧 METRICS PRODUCTION :**
- Avant MCP :
  - RDS connections : 40-80 simultanées
  - RDS CPU : 65% average
  - Latency P50 : 160ms
- Après MCP :
  - RDS connections : 8-12 simultanées
  - RDS CPU : 35% average (-46%)
  - Latency P50 : 180ms (+12.5%)
  - **Trade-off accepté**

### Q3 : "Tokens révoqués à grande échelle ?"

**💬 RÉPONSE :**
"On a testé avec 10,000 tokens révoqués simultanément. L'architecture hybride cache + PostgreSQL tient très bien.

Le secret, c'est le TTL court des JWT : 5 minutes maximum. Ça veut dire qu'un token révoqué 'expire naturellement' après 5 minutes max même sans révocation explicite. Donc on ne garde les JTI en cache que pendant leur TTL.

Avec 10K tokens/jour, TTL moyen 2.5 minutes, on a ~150 JTI en cache à tout instant. C'est ~5KB de RAM. Trivial.

Le cleanup automatique tourne toutes les 5 minutes et supprime les entrées expirées. En prod, on a ~30 révocations actives en moyenne."

**🔧 ALGORITHM :**
```python
def cleanup_expired_jti():
    now = time.time()
    jti_cache = {jti: exp for jti, exp in jti_cache.items() if exp > now}
    # Runs every 5 minutes via background task
```

### Q4 : "Plan disaster recovery ?"

**💬 RÉPONSE :**
"On a plusieurs niveaux :

**RDS Aurora** : snapshots automatiques quotidiens, retention 7 jours. Backup incrémental toutes les 5 minutes dans S3. En cas de disaster, on peut restaurer à n'importe quel point dans le temps avec RPO (Recovery Point Objective) de 5 minutes.

**RDS Keycloak** : même chose, snapshots quotidiens, retention 7 jours.

**S3** : versioning activé, lifecycle policy vers Glacier après 90 jours. Pas de suppression définitive avant 1 an.

**ECS Tasks** : stateless, donc disaster recovery = relancer les tasks. Temps de recovery ~3 minutes (cold start ECS).

**RTO** (Recovery Time Objective) global : 15 minutes pour restaurer le système complet."

**🔧 PROCÉDURE DR :**
1. Identify issue (automatic CloudWatch alarms)
2. Restore RDS from snapshot (~10 min)
3. Restart ECS services (automatic via health checks)
4. Verify Keycloak operational
5. Resume traffic (ALB targets healthy)

### Q5 : "Conformité RGPD ?"

**💬 RÉPONSE :**
"On a trois piliers RGPD :

**Chiffrement** : AES-256 at rest partout, TLS 1.2+ in transit. Ça couvre le 'mesures techniques appropriées'.

**Audit trail** : Tous les accès loggés avec correlation IDs. On peut tracer qui a accédé à quelles données et quand. Ça couvre le 'droit d'information'.

**Accès contrôlé** : RBAC strict, principe du moindre privilège. Un operator ne peut pas accéder aux données métier, seulement aux métriques.

**Ce qu'il manque** : Le droit à l'oubli (right to be forgotten). Pour l'instant, on supprime manuellement via SQL. On va implémenter un endpoint `DELETE /gdpr/forget/{user_id}` en v5.3 qui anonymise toutes les données liées à un utilisateur."

**🔧 GDPR CHECKLIST :**
- ✅ Encryption at rest/transit
- ✅ Audit logs (who, when, what)
- ✅ Access control (RBAC)
- ✅ Data minimization (only necessary fields stored)
- ⚠️ Right to be forgotten (manual for now, API planned)
- ⚠️ Data portability (export API planned)
- ✅ Data retention (7 jours logs, 90 jours S3)

---

## Conseils Généraux de Présentation

### Timing

- Rester dans les 60 minutes (slide 2-32)
- Si vous prenez du retard, écourter les sections 6 (Data Security) et 10 (Security Operations)
- Si vous avez de l'avance, approfondir la section 4 (MCP Server) - c'est la plus intéressante

### Interaction

- Encourager les questions pendant (pas seulement à la fin)
- Si question complexe : "Excellente question, je vais y répondre en détail à la fin pour ne pas déborder"
- Pointer physiquement sur les diagrammes pour maintenir l'attention

### Emphase

- **Moments clés à marteler** :
  1. "9 couches **indépendantes**" (répéter 3x minimum)
  2. "Defense-in-depth : pas de single point of failure"
  3. "MCP Server : -88% connexions DB, -75% IAM roles"
  4. "~400 injections bloquées/jour par Layer 7"

### Gestion des Questions Difficiles

**Q: "Pourquoi pas mTLS partout ?"**
R: "Coût vs. bénéfice. On a déjà JWT signature + body hash. mTLS ajouterait ~15ms. C'est prévu en v5.3 maintenant qu'on a stabilisé le reste."

**Q: "Pourquoi ECS et pas Kubernetes ?"**
R: "Fargate = serverless, moins de surface d'attaque (pas de nodes à patcher). K8s = plus flexible mais plus complexe. Pour nos besoins, Fargate suffit."

**Q: "Single Keycloak = SPOF ?"**
R: "Oui, reconnu. Migration vers cluster HA 2 instances en v5.2. Pour l'instant, RTO Keycloak ~5 minutes (redémarrage automatique ECS)."

---

**FIN DES NOTES DE DISCOURS ORAL**

**Durée couverte : 60 minutes de présentation + 15 minutes Q&A**

**Document à utiliser côte-à-côte avec : PRESENTATION_ARCHITECTURE_SECURITE.md**

