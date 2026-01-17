# Accès aux Ressources - Serveur MCP CA-A2A

**Version :** 6.0  
**Dernière mise à jour :** 17 janvier 2026

---

## Vue d'ensemble

Le Serveur MCP (Model Context Protocol) agit comme une **passerelle centralisée** pour tous les accès aux ressources AWS (S3 et RDS PostgreSQL). Au lieu d'accéder directement aux services AWS avec leurs propres credentials, les agents communiquent avec le Serveur MCP via HTTP API.

**Avantages Clés :**
- ✅ Aucun credential AWS dans les conteneurs agents
- ✅ Pooling de connexions centralisé
- ✅ Pattern circuit breaker
- ✅ Réessais automatiques avec backoff
- ✅ Point d'audit unique pour l'accès aux ressources

---

## Outils Disponibles

### Opérations S3

| Nom de l'Outil | Description | Arguments |
|----------------|-------------|-----------|
| `s3_list_objects` | Lister les objets | `prefix` (optionnel) |
| `s3_get_object` | Télécharger un objet | `key` (requis) |
| `s3_put_object` | Uploader un objet | `key`, `body`, `content_type` |
| `s3_delete_object` | Supprimer un objet | `key` (requis) |

### Opérations PostgreSQL

| Nom de l'Outil | Description | Arguments |
|----------------|-------------|-----------|
| `postgres_query` | Exécuter requête SELECT | `query` (requis) |
| `postgres_execute` | Exécuter INSERT/UPDATE/DELETE | `query`, `params` |
| `postgres_transaction` | Exécuter plusieurs requêtes en transaction | `queries[]` |

---

## Avantages de Sécurité

| Avantage | Description | Impact |
|----------|-------------|--------|
| **Pas de Prolifération Credentials** | Seul le Serveur MCP a les credentials AWS | Surface d'attaque réduite |
| **Contrôle d'Accès Centralisé** | Point unique pour audit/surveillance | Conformité facilitée |
| **Circuit Breaker** | Empêche les défaillances en cascade | Stabilité système |
| **Pooling de Connexions** | Réutilisation connexions BD | Performance (10x plus rapide) |

---

## Détails d'Implémentation

### Pooling de Connexions (PostgreSQL)

```python
self.db_pool = await asyncpg.create_pool(
    host="documents-db.cluster-xxx.eu-west-3.rds.amazonaws.com",
    min_size=5,           # Connexions minimales
    max_size=20,          # Connexions maximales
    max_queries=50000,    # Recyclage après 50k requêtes
)
```

**Avantages :**
- Réutilisation de connexions (évite surcharge TCP handshake)
- 10x plus rapide que créer de nouvelles connexions
- Recyclage automatique des connexions

---

## Métriques de Performance

| Opération | Sans MCP | Avec MCP | Amélioration |
|-----------|----------|----------|--------------|
| **Requête PostgreSQL** | 50-100ms (nouvelle connexion) | 5-10ms (pool) | 10x plus rapide |
| **S3 Get Object** | 100-200ms | 100-200ms | Identique (limité réseau) |
| **Circuit Breaker** | Défaillances en cascade | Échec rapide | Stabilité système |

---

**Lié :** [Architecture Système](ARCHITECTURE_SYSTEME.md), [Sécurité Données](SECURITE_DONNEES.md)
