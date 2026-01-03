# Migration vers le Serveur MCP - Guide Complet

## Vue d'Ensemble

Ce guide documente la migration des agents CA A2A vers une architecture utilisant un serveur MCP (Model Context Protocol) centralisé pour l'accès aux ressources AWS (S3 et PostgreSQL).

## 🎯 Objectifs de la Migration

### Avant (Library-Based)
- Chaque agent accédait directement à S3 et PostgreSQL via `mcp_protocol.py`
- Bibliothèques S3/PostgreSQL embarquées dans chaque conteneur
- Credentials dupliqués dans chaque agent
- Pas de centralisation des accès

### Après (MCP Server)
- ✅ Serveur MCP centralisé pour tous les accès aux ressources
- ✅ Un seul point de configuration pour S3 et PostgreSQL
- ✅ Conformité au protocole MCP standard
- ✅ Meilleure observabilité et monitoring
- ✅ Isolation des credentials

## 📁 Fichiers Créés/Modifiés

### Nouveaux Fichiers

| Fichier | Description |
|---------|-------------|
| `mcp_server_http.py` | Serveur MCP avec API HTTP pour ECS |
| `mcp_client_http.py` | Client MCP HTTP pour agents distribués |
| `mcp_context_auto.py` | Sélection automatique stdio/HTTP selon l'environnement |
| `Dockerfile.mcp` | Dockerfile spécifique pour le serveur MCP |
| `Deploy-MCPServer.ps1` | Script de déploiement du serveur MCP sur AWS ECS |
| `Update-AgentsWithMCP.ps1` | Script de mise à jour des agents pour utiliser MCP |

### Fichiers Modifiés

| Fichier | Changement |
|---------|------------|
| `orchestrator_agent.py` | Import: `mcp_context_auto.get_mcp_context()` |
| `extractor_agent.py` | Import: `mcp_context_auto.get_mcp_context()` |
| `archivist_agent.py` | Import: `mcp_context_auto.get_mcp_context()` |
| `mcp_client.py` | Ajout de `initialize_schema()` pour PostgreSQL |
| `mcp_server.py` | Ajout de l'outil `postgres_init_schema` |
| `docker-compose.yml` | Ajout du service `mcp-server` avec port 8000 |

## 🏗️ Architecture

### Ancienne Architecture
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Orchestrator│     │  Extractor  │     │  Archivist  │
│             │     │             │     │             │
│  S3 Client  │     │  S3 Client  │     │  S3 Client  │
│  PG Client  │     │  PG Client  │     │  PG Client  │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       ├───────────────────┼───────────────────┤
       │                   │                   │
       ▼                   ▼                   ▼
   ┌─────┐             ┌─────┐           ┌──────────┐
   │ S3  │             │ RDS │           │ Secrets  │
   └─────┘             └─────┘           │ Manager  │
                                         └──────────┘
```

### Nouvelle Architecture
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Orchestrator│     │  Extractor  │     │  Archivist  │
│             │     │             │     │             │
│ MCP Client  │     │ MCP Client  │     │ MCP Client  │
│    HTTP     │     │    HTTP     │     │    HTTP     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                           ▼
                   ┌───────────────┐
                   │  MCP Server   │
                   │   (HTTP API)  │
                   │               │
                   │  Port: 8000   │
                   └───────┬───────┘
                           │
                ┌──────────┼──────────┐
                │          │          │
                ▼          ▼          ▼
            ┌─────┐    ┌─────┐  ┌──────────┐
            │ S3  │    │ RDS │  │ Secrets  │
            └─────┘    └─────┘  │ Manager  │
                                └──────────┘
```

## 🚀 Déploiement

### 1. Déployer le Serveur MCP sur ECS

```powershell
# Construire, pousser et déployer le serveur MCP
.\Deploy-MCPServer.ps1 -Profile AWSAdministratorAccess-555043101106

# Options disponibles:
# -SkipBuild   : Sauter la construction Docker
# -SkipPush    : Sauter le push vers ECR
# -Region      : Région AWS (défaut: eu-west-3)
```

**Ce que fait le script:**
1. Crée un dépôt ECR `ca-a2a-mcp-server`
2. Construit l'image Docker avec `Dockerfile.mcp`
3. Pousse l'image vers ECR
4. Enregistre une task definition ECS
5. Crée/met à jour le service ECS `mcp-server`

**Ressources créées:**
- **Service ECS**: `mcp-server` (1 tâche Fargate)
- **Port**: 8000 (HTTP API)
- **CPU**: 256 unités (0.25 vCPU)
- **Memory**: 512 MB
- **Health Check**: `GET /health`
- **Logs**: `/ecs/ca-a2a-mcp-server`

### 2. Mettre à Jour les Agents

```powershell
# Mettre à jour les services agents avec MCP_SERVER_URL
.\Update-AgentsWithMCP.ps1 -Profile AWSAdministratorAccess-555043101106

# Vérifie et met à jour:
# - orchestrator
# - extractor
# - archivist
```

**Variables d'environnement ajoutées:**
```bash
MCP_SERVER_URL=http://mcp-server.ca-a2a.local:8000
```

### 3. Service Discovery (Optionnel mais Recommandé)

Pour que les agents puissent découvrir le serveur MCP par nom DNS, créer un Cloud Map service:

```powershell
# Créer un namespace privé (si pas déjà fait)
aws servicediscovery create-private-dns-namespace `
    --name ca-a2a.local `
    --vpc <VPC_ID>

# Créer un service pour MCP
aws servicediscovery create-service `
    --name mcp-server `
    --dns-config "NamespaceId=<NAMESPACE_ID>,DnsRecords=[{Type=A,TTL=60}]" `
    --health-check-custom-config FailureThreshold=1

# Mettre à jour le service ECS MCP avec Service Discovery
aws ecs update-service `
    --cluster ca-a2a-cluster `
    --service mcp-server `
    --service-registries "registryArn=<SERVICE_ARN>"
```

## 🔧 Configuration

### Variables d'Environnement

#### Serveur MCP (`mcp-server`)
```bash
POSTGRES_HOST=ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com
POSTGRES_PORT=5432
POSTGRES_DB=documents_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=<from-secrets-manager>
AWS_REGION=eu-west-3
S3_BUCKET=ca-a2a-documents
```

#### Agents (orchestrator, extractor, archivist)
```bash
# Existantes + Nouvelle:
MCP_SERVER_URL=http://mcp-server.ca-a2a.local:8000
```

### Sélection Automatique du Mode MCP

Le fichier `mcp_context_auto.py` gère automatiquement le mode:

- **Si `MCP_SERVER_URL` est défini** → Mode HTTP (AWS ECS)
- **Sinon** → Mode stdio (local/docker-compose)

```python
# Dans les agents:
from mcp_context_auto import get_mcp_context

# Utilisation identique:
self.mcp = get_mcp_context()
await self.mcp.__aenter__()
```

## 📊 Monitoring

### Health Checks

```bash
# Vérifier la santé du serveur MCP
curl http://mcp-server.ca-a2a.local:8000/health

# Réponse attendue:
{
  "status": "healthy",
  "timestamp": "2026-01-02T12:00:00",
  "services": {
    "postgresql": "ok",
    "s3": "ok"
  }
}
```

### Logs CloudWatch

```bash
# Logs du serveur MCP
aws logs tail /ecs/ca-a2a-mcp-server --follow

# Logs des agents
aws logs tail /ecs/ca-a2a-orchestrator --follow
aws logs tail /ecs/ca-a2a-extractor --follow
aws logs tail /ecs/ca-a2a-archivist --follow
```

### Métriques ECS

```bash
# Status des services
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services mcp-server orchestrator extractor archivist \
    --query 'services[*].[serviceName,status,runningCount,desiredCount]' \
    --output table
```

## 🧪 Tests

### Test Local (Docker Compose)

```bash
# Démarrer tous les services incluant MCP
docker-compose up -d

# Vérifier que le serveur MCP est actif
curl http://localhost:8000/health

# Tester un appel d'outil
curl -X POST http://localhost:8000/call_tool \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "postgres_query",
    "arguments": {
      "query": "SELECT COUNT(*) FROM documents"
    }
  }'
```

### Test AWS (ECS)

```bash
# Trouver le task ID du serveur MCP
aws ecs list-tasks --cluster ca-a2a-cluster --service-name mcp-server

# Exécuter un health check dans le conteneur
aws ecs execute-command \
    --cluster ca-a2a-cluster \
    --task <TASK_ID> \
    --container mcp-server \
    --interactive \
    --command "python -c \"import urllib.request; print(urllib.request.urlopen('http://localhost:8000/health').read())\""
```

## 🔒 Sécurité

### Avantages de Sécurité

1. **Centralisation des Credentials**
   - Un seul point d'accès à Secrets Manager
   - Pas de duplication des secrets dans chaque agent

2. **Isolation Réseau**
   - Serveur MCP dans un subnet privé
   - Agents communiquent via réseau VPC interne
   - Pas d'exposition externe du port 8000

3. **Audit Centralisé**
   - Tous les accès S3/PostgreSQL passent par MCP
   - Logs centralisés des opérations
   - Facilite le monitoring des accès aux données

### Recommandations

- [ ] Activer VPC Flow Logs pour le traffic MCP
- [ ] Configurer CloudWatch Alarms sur les métriques MCP
- [ ] Restreindre les Security Groups pour limiter l'accès au port 8000
- [ ] Implémenter une authentification token entre agents et MCP
- [ ] Chiffrer les communications avec TLS (futur)

## 📈 Performance

### Optimisations Implémentées

1. **Connection Pooling PostgreSQL**
   - Pool de 2-10 connexions
   - Timeout de 60 secondes
   - Réutilisation des connexions

2. **Circuit Breakers**
   - Seuil d'erreur: 5 échecs
   - Timeout de récupération: 60 secondes
   - Protège contre les cascades d'erreurs

3. **Retry Logic**
   - 3 tentatives maximum par opération
   - Backoff exponentiel
   - Gestion des erreurs transitoires

### Métriques Attendues

| Métrique | Valeur Cible |
|----------|--------------|
| Latence moyenne (P50) | < 50ms |
| Latence P99 | < 200ms |
| Disponibilité | > 99.9% |
| Taux d'erreur | < 0.1% |

## 🔄 Rollback

En cas de problème, rollback possible:

### Option 1: Désactiver MCP (Rollback Rapide)

```bash
# Supprimer MCP_SERVER_URL des agents
# Les agents reviendront automatiquement au mode direct

aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service orchestrator \
    --task-definition <OLD_TASK_DEF_ARN> \
    --force-new-deployment
```

### Option 2: Arrêter le Serveur MCP

```bash
# Mettre le service MCP à 0 tâches
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service mcp-server \
    --desired-count 0
```

### Option 3: Rollback Complet

```bash
# Supprimer le service MCP
aws ecs delete-service --cluster ca-a2a-cluster --service mcp-server --force

# Supprimer la task definition (optionnel)
aws ecs deregister-task-definition --task-definition ca-a2a-mcp-server:1
```

## 📝 Checklist de Migration

- [x] Créer `mcp_server_http.py` et `mcp_client_http.py`
- [x] Créer `mcp_context_auto.py` pour sélection automatique
- [x] Mettre à jour imports dans orchestrator, extractor, archivist
- [x] Créer `Dockerfile.mcp`
- [x] Mettre à jour `docker-compose.yml`
- [x] Créer scripts de déploiement AWS
- [ ] Tester localement avec Docker Compose
- [ ] Déployer serveur MCP sur AWS ECS
- [ ] Mettre à jour agents avec MCP_SERVER_URL
- [ ] Vérifier health checks et logs
- [ ] Tester pipeline end-to-end
- [ ] Valider métriques de performance
- [ ] Documenter la migration (ce fichier)

## 🎓 Références

- **MCP Specification**: https://spec.modelcontextprotocol.io/
- **Guide Original MCP**: [MCP_SERVER_GUIDE.md](./MCP_SERVER_GUIDE.md)
- **Documentation AWS ECS**: [AWS_COMPREHENSIVE_TESTS.md](./AWS_COMPREHENSIVE_TESTS.md)
- **Architecture Sécurité**: [EXHAUSTIVE_SECURITY_DEMO.md](./EXHAUSTIVE_SECURITY_DEMO.md)

## 🤝 Support

Pour toute question ou problème:
1. Consulter les logs CloudWatch
2. Vérifier le health check du serveur MCP
3. Consulter ce guide de migration
4. Contacter l'équipe DevOps

---

**Date de Migration**: 2026-01-02  
**Version**: 1.0  
**Statut**: ✅ Prêt pour Déploiement

