# Modèle de Menaces & Défenses CA-A2A

**Version :** 6.0  
**Dernière mise à jour :** 17 janvier 2026

---

## Catégories de Menaces & Défenses

### Menaces d'Authentification
- **Vol de Token** → Liaison de Token (RFC 8473)
- **Tokens Forgés** → Vérification signature RS256
- **Tokens Expirés** → Validation claim JWT `exp`
- **Force Brute** → Limitation de débit

### Menaces d'Autorisation
- **Élévation de Privilèges** → Application RBAC
- **Accès Horizontal** → Filtrage basé principal
- **Manipulation Rôle** → JWT signé (inviolable)

### Menaces Réseau
- **MITM** → Chiffrement TLS 1.2+
- **DDoS** → AWS Shield + Limitation débit
- **Scan de Ports** → Security Groups

### Menaces sur les Données
- **Données au Repos** → Chiffrement AES-256
- **Injection SQL** → Requêtes paramétrées
- **Traversée de Chemins** → Validation regex

### Menaces Application
- **Attaques par Rejeu** → Suivi JWT jti
- **Falsification Message** → Liaison hash du corps
- **DoS** | Limitation débit (300 req/min)
- **Attaques Timing** → Comparaison temps constant

---

## Analyse STRIDE

| Menace | Atténuation |
|--------|-------------|
| **Usurpation (Spoofing)** | Signature RS256 + Liaison Token |
| **Falsification (Tampering)** | Liaison hash du corps |
| **Répudiation (Repudiation)** | Journaux audit (CloudWatch) |
| **Divulgation d'Information** | TLS + AES-256 |
| **Déni de Service** | Limitation débit + Circuit breaker |
| **Élévation de Privilège** | Application RBAC |

---

## Scénarios d'Attaque

### Scénario 1 : Menace Interne
**Attaquant :** Employé mécontent avec rôle `viewer`  
**Objectif :** Supprimer documents production

| Étape | Attaque | Défense | Résultat |
|-------|---------|---------|----------|
| 1 | Obtenir JWT valide | ✅ Employé a accès valide | Token obtenu |
| 2 | Appeler `delete_document` | ❌ RBAC bloque `viewer` de delete | **Bloqué** |

**Résultat :** Attaque échouée à la Couche 4 (Autorisation)

### Scénario 2 : Attaquant Externe
**Attaquant :** Hacker avec JWT volé  
**Objectif :** Usurper utilisateur depuis emplacement différent

| Étape | Attaque | Défense | Résultat |
|-------|---------|---------|----------|
| 1 | Intercepter JWT via XSS | ✅ Token volé | Token obtenu |
| 2 | Utiliser token depuis machine attaquant | ❌ Liaison token (certificat incompatible) | **Bloqué** |

**Résultat :** Attaque échouée à la Couche 3 (Authentification)

---

## Risques Résiduels

| Risque | Probabilité | Impact | Atténuation | Statut |
|--------|-------------|--------|-------------|--------|
| **Compromission Keycloak** | Faible | Élevé | Rotation clés, surveillance | Accepté |
| **Zero-Day Dépendances** | Moyen | Moyen | Mises à jour automatisées | Accepté |
| **Initié avec Rôle Admin** | Faible | Élevé | Journaux audit, moindre privilège | Accepté |
| **Défaillance Région AWS** | Très Faible | Élevé | Multi-région (futur) | Accepté |

---

**Lié :** [Couches de Sécurité](COUCHES_SECURITE_DEFENSE_EN_PROFONDEUR.md), [Opérations Sécurité](OPERATIONS_SECURITE.md)
