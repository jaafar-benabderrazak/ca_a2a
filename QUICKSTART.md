# Guide de Démarrage Rapide

## Installation Rapide

### 1. Prérequis

- Python 3.9+
- PostgreSQL 12+
- Compte AWS avec accès S3

### 2. Configuration Initiale

```bash
# Cloner le projet
cd ca_a2a

# Créer un environnement virtuel
python -m venv venv

# Activer l'environnement (Windows)
venv\Scripts\activate
# Ou sur Linux/Mac:
# source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Copier le fichier de configuration exemple
cp .env.example .env
```

### 3. Configurer les Variables d'Environnement

Éditez le fichier `.env` :

```env
# AWS S3
AWS_ACCESS_KEY_ID=VOTRE_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=VOTRE_SECRET_KEY
AWS_REGION=us-east-1
S3_BUCKET_NAME=votre-bucket

# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=documents_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=votre_password
```

### 4. Initialiser la Base de Données

```bash
# Créer la base de données PostgreSQL
createdb documents_db

# Initialiser le schéma
python init_db.py init

# Vérifier la connexion
python init_db.py check
```

### 5. Démarrer les Agents

```bash
# Option 1: Tous les agents ensemble
python run_agents.py

# Option 2: Agents individuels (dans des terminaux séparés)
python orchestrator_agent.py
python extractor_agent.py
python validator_agent.py
python archivist_agent.py
```

### 6. Tester le Système

```bash
# Vérifier la santé du système
python client.py health

# Voir le statut
python client.py info

# Traiter un document de test
python client.py process "documents/test.pdf"
```

## Premiers Pas

### Traiter Votre Premier Document

1. **Uploader un document sur S3**

```bash
aws s3 cp mon_document.pdf s3://votre-bucket/documents/
```

2. **Lancer le traitement**

```bash
python client.py process "documents/mon_document.pdf"
```

3. **Suivre la progression**

```bash
# Utiliser le task_id retourné
python client.py status <task_id>
```

### Traiter un Lot de Documents

```bash
# Traiter tous les PDFs dans un dossier
python client.py batch --prefix "documents/2024/" --extension ".pdf"
```

### Utiliser l'API Directement

```python
import asyncio
from client import PipelineClient

async def main():
    client = PipelineClient()
    
    # Traiter un document
    result = await client.process_document("documents/rapport.pdf")
    print(f"Task ID: {result['task_id']}")
    
    # Attendre quelques secondes
    await asyncio.sleep(5)
    
    # Vérifier le statut
    status = await client.get_task_status(result['task_id'])
    print(f"Status: {status['status']}")
    print(f"Stage: {status['current_stage']}")

asyncio.run(main())
```

## Structure des Documents

### PDF

Le système extrait :
- Texte de chaque page
- Tableaux structurés
- Métadonnées (auteur, titre, date, etc.)

### CSV

Le système extrait :
- Colonnes et types
- Données avec conversion de types automatique
- Statistiques descriptives
- Détection des valeurs manquantes

## Validation

Les documents sont validés selon :

### Pour PDF
- **Complétude** : Texte présent, nombre de pages
- **Qualité** : Longueur du texte suffisante
- **Cohérence** : Tableaux bien formés

### Pour CSV
- **Complétude** : Colonnes et données présentes
- **Qualité** : Taux de valeurs manquantes acceptable
- **Cohérence** : Types de données cohérents

### Scores de Validation

- **90-100** : Excellent ✅
- **75-89** : Bon ✓
- **60-74** : Acceptable ⚠️
- **40-59** : Faible ⚠️
- **0-39** : Échec ❌

## Consultation des Résultats

### Via l'API

```bash
# Rechercher des documents validés
python -c "
import asyncio
import aiohttp
import json

async def search():
    message = {
        'jsonrpc': '2.0',
        'id': '1',
        'method': 'search_documents',
        'params': {
            'status': 'validated',
            'min_score': 80.0,
            'limit': 10
        }
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post('http://localhost:8004/message', json=message) as resp:
            result = await resp.json()
            print(json.dumps(result['result'], indent=2))

asyncio.run(search())
"
```

### Via PostgreSQL

```sql
-- Voir les documents récents
SELECT id, file_name, document_type, validation_score, status
FROM documents
ORDER BY processing_date DESC
LIMIT 10;

-- Statistiques par type
SELECT document_type, COUNT(*), AVG(validation_score)
FROM documents
GROUP BY document_type;

-- Documents avec score faible
SELECT id, file_name, validation_score, validation_details
FROM documents
WHERE validation_score < 60
ORDER BY validation_score ASC;
```

## Dépannage Rapide

### Les agents ne démarrent pas

**Problème** : Port déjà utilisé

```bash
# Vérifier les ports
netstat -ano | findstr "8001 8002 8003 8004"

# Changer les ports dans .env si nécessaire
```

### Erreur de connexion S3

```bash
# Vérifier les credentials
aws s3 ls s3://votre-bucket/

# Vérifier les permissions IAM
aws iam get-user
```

### Erreur de connexion PostgreSQL

```bash
# Vérifier que PostgreSQL est démarré
pg_isready

# Tester la connexion
psql -h localhost -U postgres -d documents_db
```

### Erreur d'extraction PDF

- Vérifier que le PDF n'est pas corrompu
- Vérifier que le PDF n'est pas protégé par mot de passe
- Essayer avec un autre PDF

## Logs

Les logs sont écrits dans :
- Console (stdout)
- Fichier `agents.log`

```bash
# Suivre les logs en temps réel
tail -f agents.log

# Filtrer par agent
grep "Orchestrator" agents.log

# Voir les erreurs
grep "ERROR" agents.log
```

## Exemples Complets

```bash
# Lancer les exemples fournis
python examples.py
```

## Prochaines Étapes

1. **Personnaliser les règles de validation** (`validator_agent.py`)
2. **Ajouter des formats de documents** (`extractor_agent.py`)
3. **Créer des dashboards** (Grafana + PostgreSQL)
4. **Déployer en production** (Docker, Kubernetes)

## Support

- Documentation complète : `README.md`
- Architecture : `ARCHITECTURE.md`
- API Reference : `API.md`
- Tests : `pytest test_pipeline.py`

## Liens Utiles

- [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [AWS S3 Documentation](https://docs.aws.amazon.com/s3/)
- [asyncio Documentation](https://docs.python.org/3/library/asyncio.html)

