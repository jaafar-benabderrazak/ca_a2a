# Opérations de Sécurité CA-A2A

**Version :** 6.0  
**Dernière mise à jour :** 17 janvier 2026

---

## Réponse aux Incidents

### Types d'Incidents de Sécurité

| Incident | Détection | Temps de Réponse | Action |
|----------|-----------|------------------|--------|
| **Vol de Token** | Emplacement/modèle inhabituel | < 15 min | Révoquer token via API Admin |
| **Pic d'Échecs Authentification** | > 10 échecs/min | < 5 min | Investiguer + bloquer IP si nécessaire |
| **Tentative Accès Non Autorisé** | Refus RBAC journalisé | < 30 min | Réviser permissions |
| **Suspicion Fuite Données** | Modèle d'accès données inhabituel | < 1 heure | Investiguer + rotation credentials |

### Playbooks de Réponse

**Révocation de Token :**
```bash
# 1. Identifier JTI token compromis
aws logs filter-pattern "jti=abc123" --log-group /ecs/ca-a2a-orchestrator

# 2. Révoquer token
curl -X POST https://orchestrator.ca-a2a.local:8001/admin/revoke-token \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"jti": "abc123", "reason": "Faille sécurité", "revoked_by": "admin@example.com"}'

# 3. Vérifier révocation
curl https://orchestrator.ca-a2a.local:8001/admin/revoked-tokens | jq '.[] | select(.jti=="abc123")'

# 4. Surveiller tentatives d'utilisation
aws logs filter-pattern "token_revoked jti=abc123" --log-group /ecs/ca-a2a-orchestrator --follow
```

---

## Maintenance de Sécurité

### Tâches Hebdomadaires
- ✅ Réviser journaux échecs authentification
- ✅ Vérifier violations limite débit
- ✅ Surveiller alarmes CloudWatch
- ✅ Réviser nouvelles CVE dans dépendances

### Tâches Mensuelles
- ✅ Rotation secrets Secrets Manager
- ✅ Réviser permissions IAM (moindre privilège)
- ✅ Mettre à jour documentation sécurité
- ✅ Lancer tests de pénétration (optionnel)

### Tâches Trimestrielles
- ✅ Audit sécurité (externe)
- ✅ Mises à jour dépendances (versions majeures)
- ✅ Réviser et mettre à jour modèle menaces
- ✅ Exercice de reprise après sinistre

---

## Contrôle d'Accès

### Accès Admin

**Rôles Admin :**
- **Admin Sécurité :** Révocation token, accès journaux audit
- **Admin Ops :** Déployer code, scale services
- **Admin Lecture Seule :** Voir journaux, métriques (pas de changements)

**Points de Terminaison API Admin :**
```bash
# Gestion tokens
POST /admin/revoke-token
GET /admin/revoked-tokens

# Statistiques sécurité
GET /admin/security-stats
GET /admin/authentication-failures

# Santé & métriques
GET /admin/health
GET /admin/metrics
```

---

## Rotation de Clés

### Clés de Signature Keycloak
- **Fréquence :** Tous les 90 jours
- **Processus :** Console admin Keycloak → Paramètres Realm → Clés → Rotation
- **Impact :** Les anciens tokens restent valides jusqu'à expiration (15 min)

### Secrets AWS
- **Fréquence :** Automatique (Secrets Manager)
- **Manuel :** Utiliser `aws secretsmanager rotate-secret`

### Certificats TLS
- **ALB :** AWS Certificate Manager (renouvellement automatique)
- **mTLS :** Génération manuelle (certificats clients expirent après 1 an)

---

## Sauvegarde & Récupération

### Sauvegardes Base de Données
- **Fréquence :** Snapshots quotidiens automatisés
- **Rétention :** 30 jours
- **RTO (Recovery Time Objective) :** < 1 heure
- **RPO (Recovery Point Objective) :** < 24 heures

### Sauvegarde Configuration
- **Définitions Tâches ECS :** Versionnées dans Git
- **Politiques IAM :** Versionnées dans Git
- **Configuration Keycloak :** Export manuel (trimestriel)

---

## Contacts Sécurité

| Rôle | Responsabilité | Astreinte |
|------|----------------|-----------|
| **Équipe Sécurité** | Réponse incidents, analyse menaces | 24/7 |
| **Équipe Ops** | Infrastructure, déploiements | Heures ouvrables |
| **Équipe Dév** | Corrections code, patchs sécurité | Heures ouvrables |

---

## Liste de Vérification Conformité

- ✅ Journalisation audit activée (CloudWatch + CloudTrail)
- ✅ Chiffrement au repos (AES-256)
- ✅ Chiffrement en transit (TLS 1.2+)
- ✅ Contrôle d'accès (IAM + RBAC)
- ✅ Rotation secrets (Secrets Manager)
- ✅ Scan vulnérabilités (automatisé)
- ✅ Tests de pénétration (annuel)
- ✅ Plan de réponse aux incidents (documenté)

---

**Lié :** [Surveillance & Audit](SURVEILLANCE_AUDIT.md), [Modèle de Menaces](MODELE_MENACES_DEFENSES.md)
