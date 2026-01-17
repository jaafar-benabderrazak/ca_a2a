# Sécurité des Données CA-A2A

**Version :** 6.0  
**Dernière mise à jour :** 17 janvier 2026

---

## Chiffrement au Repos

| Ressource | Chiffrement | Gestion des Clés |
|-----------|-------------|------------------|
| **RDS Aurora PostgreSQL** | AES-256 | AWS KMS (clé par défaut) |
| **RDS PostgreSQL (Keycloak)** | AES-256 | AWS KMS (clé par défaut) |
| **Bucket S3** | SSE-S3 (AES-256) | Clés gérées par AWS |
| **Volumes EBS (ECS)** | AES-256 | AWS KMS (clé par défaut) |
| **Secrets Manager** | AES-256 | AWS KMS (clé dédiée) |
| **CloudWatch Logs** | AES-256 | Clés gérées par AWS |

---

## Chiffrement en Transit

| Connexion | Protocole | Chiffrement |
|-----------|-----------|-------------|
| **Utilisateur → ALB** | HTTPS | TLS 1.2+ |
| **ALB → Orchestrateur** | HTTP | Dans VPC (réseau privé) |
| **Agent → Agent** | HTTP | Dans VPC (réseau privé) |
| **Agent → Keycloak** | HTTP | Dans VPC |
| **Agent → RDS** | PostgreSQL | SSL/TLS (imposé) |
| **Agent → S3** | HTTPS | TLS 1.2+ |

**Note :** Le trafic interne utilise HTTP dans le VPC (réseau privé) pour des raisons de performance. TLS utilisé pour les connexions externes et services sensibles (RDS, S3).

---

## Gestion des Secrets

### AWS Secrets Manager

**Secrets Stockés :**
- Mots de passe base de données (RDS, Keycloak)
- Mot de passe admin Keycloak
- Secret client Keycloak
- Clés API (si utilisées)

**Sécurité :**
- ✅ Rotation automatique (tous les 90 jours)
- ✅ Contrôle d'accès basé sur IAM
- ✅ Journalisation audit CloudTrail
- ✅ Aucun secret en dur dans code ou config

---

## Rétention des Données

| Type de Données | Période de Rétention | Sauvegarde |
|-----------------|----------------------|------------|
| **Métadonnées Documents** | Indéfinie | Snapshots quotidiens (30 jours) |
| **Documents S3** | Configurable (politique lifecycle) | Versioning activé |
| **Journaux CloudWatch** | 7 jours | N/A |
| **Journaux d'Audit** | 90 jours | Exports quotidiens vers S3 |
| **Tokens Révoqués** | Jusqu'à expiration token | N/A (données transitoires) |

---

**Lié :** [Architecture Système](ARCHITECTURE_SYSTEME.md), [Couches de Sécurité](COUCHES_SECURITE_DEFENSE_EN_PROFONDEUR.md)
