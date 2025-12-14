# Pipeline Documentaire Intelligent Multi-Agents

Un système de traitement documentaire distribué basé sur une architecture multi-agents autonomes, utilisant les protocoles A2A (Agent-to-Agent) et MCP (Model Context Protocol).

## 🚀 Démarrage Rapide

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Configurer
cp .env.example .env
# Éditer .env avec vos credentials AWS et PostgreSQL

# 3. Initialiser la base
createdb documents_db
python init_db.py init

# 4. Démarrer tous les agents
python run_agents.py

# 5. Tester
python client.py health
python client.py process "documents/test.pdf"
```

## 🏗️ Architecture

**4 Agents Spécialisés** qui collaborent de manière autonome :

| Agent | Port | Rôle |
|-------|------|------|
| **Orchestrateur** | 8001 | Coordonne le pipeline complet |
| **Extracteur** | 8002 | Extrait données depuis S3 (PDF/CSV) |
| **Validateur** | 8003 | Valide et calcule le score (0-100) |
| **Archiviste** | 8004 | Persiste dans PostgreSQL |

**Protocoles** :
- **A2A** (JSON-RPC 2.0) : Communication inter-agents
- **MCP** : Accès unifié à S3 et PostgreSQL
- **Agent Cards** : Auto-description et découverte des capacités

## 📚 Documentation

**Toute la documentation est maintenant centralisée dans un seul fichier :**

➡️ **[DOCUMENTATION.md](DOCUMENTATION.md)** - Guide complet incluant :
- Vue d'ensemble et architecture
- Installation et configuration
- API Reference complète
- Agent Cards & Skills
- Best Practices A2A
- Déploiement AWS

**Autres documents utiles :**
- [A2A_BEST_PRACTICES.md](A2A_BEST_PRACTICES.md) - Guide technique des best practices
- [AWS_DEPLOYMENT.md](AWS_DEPLOYMENT.md) - Guide de déploiement AWS détaillé
- [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md) - Checklist de production

## ✨ Fonctionnalités Principales

- 🤖 **4 Agents Autonomes** communicant via A2A (JSON-RPC 2.0)
- 📄 **Support Multi-Format** : PDF (texte + tableaux) et CSV
- ✅ **Validation Intelligente** avec scoring 0-100
- 💾 **Persistence Fiable** : PostgreSQL avec audit trail
- 🔍 **Agent Cards** : Auto-description et découverte dynamique
- 🛡️ **Production-Ready** : Retry, circuit breakers, idempotency, structured logging
- 🐳 **Docker Ready** : Déploiement containerisé
- ☁️ **AWS Ready** : Guide complet ECS Fargate + Cloud Map

## 🎯 Utilisation

### Client CLI

```bash
# Traiter un document
python client.py process "documents/rapport.pdf"

# Traiter un lot
python client.py batch --prefix "documents/2024/" --extension ".pdf"

# Vérifier le statut
python client.py status <task_id>

# Découvrir les agents
python discover_agents.py
```

### API Python

```python
import asyncio
from client import PipelineClient

async def main():
    client = PipelineClient()
    result = await client.process_document("documents/rapport.pdf")
    print(f"Task ID: {result['task_id']}")

asyncio.run(main())
```

## 🛠️ Structure du Projet

```
ca_a2a/
├── a2a_protocol.py          # Protocole A2A JSON-RPC 2.0
├── mcp_protocol.py          # Protocole MCP (S3 + PostgreSQL)
├── agent_card.py            # Système de cartes d'agents
├── utils.py                 # Utilitaires best practices
├── base_agent.py            # Classe de base pour agents
├── *_agent.py               # Les 4 agents spécialisés
├── config.py                # Configuration
├── client.py                # Client CLI
├── run_agents.py            # Démarrage de tous les agents
├── discover_agents.py       # Découverte des agents
├── DOCUMENTATION.md         # 📚 Documentation complète
├── requirements.txt         # Dépendances
└── Dockerfile              # Image Docker
```

## 📝 Licence

MIT License

## 📞 Support

- 📖 Documentation complète : [DOCUMENTATION.md](DOCUMENTATION.md)
- 🐛 Issues : Consulter les logs dans `agents.log`
- 🧪 Tests : `pytest test_pipeline.py -v`
