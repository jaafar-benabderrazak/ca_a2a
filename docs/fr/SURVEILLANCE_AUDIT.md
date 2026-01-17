# Surveillance & Audit CA-A2A

**Version :** 6.0  
**Dernière mise à jour :** 17 janvier 2026

---

## Journaux CloudWatch

### Groupes de Journaux

| Groupe de Journaux | Objectif | Rétention |
|--------------------|----------|-----------|
| `/ecs/ca-a2a-orchestrator` | Journaux Orchestrateur | 7 jours |
| `/ecs/ca-a2a-extractor` | Journaux Extracteur | 7 jours |
| `/ecs/ca-a2a-validator` | Journaux Validateur | 7 jours |
| `/ecs/ca-a2a-archivist` | Journaux Archiviste | 7 jours |
| `/ecs/ca-a2a-keycloak` | Journaux Keycloak | 7 jours |
| `/ecs/ca-a2a-mcp-server` | Journaux Serveur MCP | 7 jours |

---

## Événements de Sécurité Journalisés

| Type d'Événement | Déclencheur | Niveau Journal | Alerte ? |
|------------------|-------------|----------------|----------|
| `authentication_success` | JWT valide vérifié | INFO | Non |
| `authentication_failure` | JWT invalide | WARN | Oui (> 5/min) |
| `authorization_failure` | Permissions insuffisantes | WARN | Oui (> 3/min) |
| `rate_limit_exceeded` | Trop de requêtes | WARN | Oui |
| `replay_detected` | jti JWT dupliqué | WARN | Oui |
| `token_revoked` | Token révoqué utilisé | WARN | Oui |
| `invalid_input` | Validation schema échouée | WARN | Non |
| `method_executed` | Appel méthode réussi | INFO | Non |

---

## Format de Journalisation Structuré

```json
{
  "timestamp": "2026-01-17T10:30:00Z",
  "level": "INFO",
  "agent": "orchestrator",
  "event_type": "request",
  "correlation_id": "2026-01-17T10:30:00Z-a1b2c3d4",
  "method": "process_document",
  "principal": "document-processor",
  "duration_ms": 250,
  "success": true
}
```

---

## Exemples de Requêtes

### CloudWatch Insights

```sql
-- Échecs d'authentification dans la dernière heure
fields @timestamp, principal, error_message
| filter event_type = "authentication_failure"
| sort @timestamp desc
| limit 50

-- Requêtes lentes (> 1 seconde)
fields @timestamp, method, duration_ms, agent
| filter duration_ms > 1000
| sort duration_ms desc
| limit 20
```

---

## Métriques & Alarmes

### Métriques CloudWatch

| Métrique | Seuil | Action |
|----------|-------|--------|
| **Utilisation CPU** | > 70% pendant 3 min | Scale up tâches ECS |
| **Utilisation Mémoire** | > 80% pendant 3 min | Scale up tâches ECS |
| **Échecs Authentification** | > 10/min | Alerte SNS équipe sécurité |
| **Taux Erreur 5xx** | > 1% | Alerte SNS équipe ops |
| **Latence Requête** | p99 > 2s | Investiguer performance |

---

## Piste d'Audit

### Qu'est-ce qui est Journalisé ?

✅ Toutes les tentatives d'authentification (succès/échec)  
✅ Toutes les décisions d'autorisation  
✅ Tous les appels de méthode API avec paramètres  
✅ Toutes les révocations de token  
✅ Tous les changements de configuration (CloudTrail)  
✅ Tous les appels API AWS (CloudTrail)

### Stockage Journaux d'Audit

- **CloudWatch Logs :** 7 jours (stockage chaud)
- **Export S3 :** 90 jours (stockage froid)
- **CloudTrail :** 90 jours (appels API AWS)

---

**Lié :** [Opérations de Sécurité](OPERATIONS_SECURITE.md), [Modèle de Menaces](MODELE_MENACES_DEFENSES.md)
