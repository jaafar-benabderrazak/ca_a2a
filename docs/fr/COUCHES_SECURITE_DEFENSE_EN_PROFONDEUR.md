# Couches de Sécurité CA-A2A (Défense en Profondeur)

**Version :** 6.0  
**Dernière mise à jour :** 17 janvier 2026

---

## Vue d'ensemble

Le système CA-A2A implémente une **architecture de sécurité en 10 couches**. Chaque couche fournit une protection indépendante, garantissant que la compromission d'une couche ne compromet pas l'ensemble du système.

**Principe de Sécurité :** Contrôles de sécurité multiples et indépendants → Aucun point unique de défaillance

---

## Les 10 Couches de Sécurité

### Couche 1 : Isolation Réseau
**Technologie :** VPC AWS, Security Groups, NACLs  
**Objectif :** Empêcher l'accès réseau non autorisé

**Contrôles :**
- Sous-réseaux privés (pas d'IP publiques)
- Security Groups (filtrage au niveau des ports)
- NAT Gateway (internet sortant uniquement)

**Menaces Atténuées :** Attaques réseau, scan de ports, accès direct, DDoS

---

### Couche 2 : Identité & Accès
**Technologie :** Keycloak OAuth2/OIDC  
**Objectif :** Authentification centralisée

**Contrôles :**
- Keycloak comme fournisseur d'identité
- Flux client credentials (client_id + client_secret)
- Émission de tokens avec rôles utilisateur

**Menaces Atténuées :** Tentatives d'authentification non autorisées, usurpation d'identité

---

### Couche 3 : Authentification
**Technologie :** JWT RS256 + Token Binding (RFC 8473)  
**Objectif :** Vérifier l'authenticité du token

**Contrôles :**
- Vérification signature asymétrique RS256
- Validation expiration (claim exp)
- Validation émetteur (claim iss) et audience (claim aud)
- Liaison token au certificat TLS

**Menaces Atténuées :** Tokens forgés, tokens expirés, vol de token

---

### Couche 4 : Autorisation
**Technologie :** RBAC avec Rôles Keycloak  
**Objectif :** Appliquer les permissions

**Hiérarchie des Rôles :**
```
admin → * (toutes les méthodes)
orchestrator → extract_document, validate_document, archive_document
lambda → upload_document, process_document
document-processor → process_document, list_pending_documents
viewer → list_documents, get_document (lecture seule)
```

**Menaces Atténuées :** Élévation de privilèges, invocation de méthodes non autorisées

---

### Couche 5 : Contrôle d'Accès aux Ressources
**Technologie :** Serveur MCP (Passerelle Ressources)  
**Objectif :** Accès S3/RDS centralisé

**Contrôles :**
- Tous les accès AWS passent par le Serveur MCP
- Pattern circuit breaker
- Pooling de connexions
- Aucun credential AWS direct dans les agents

**Menaces Atténuées :** Prolifération credentials, accès AWS direct, abus API AWS

---

### Couche 6 : Intégrité des Messages
**Technologie :** Liaison JWT Body Hash  
**Objectif :** Détecter la falsification de messages

**Contrôles :**
- Hash SHA-256 du corps de requête
- Hash stocké dans le claim JWT `body_hash`
- Vérification côté agent

**Menaces Atténuées :** Falsification MITM, modification corps requête

---

### Couche 7 : Validation des Entrées
**Technologie :** JSON Schema + Modèles Pydantic  
**Objectif :** Rejeter les entrées malformées

**Contrôles :**
- Validation JSON Schema pour toutes les méthodes
- Vérification de type Pydantic
- Protection traversée de chemins (`../` détecté)
- Limites de longueur (max 1024 caractères)

**Menaces Atténuées :** Injection SQL, traversée de chemins, XSS, débordement buffer

---

### Couche 8 : Protection contre le Rejeu
**Technologie :** Suivi JWT jti Nonce  
**Objectif :** Empêcher le rejeu de requêtes

**Contrôles :**
- Suivi JWT `jti` (ID unique token) dans le cache
- Expiration basée sur TTL (120 secondes)
- Rejet `jti` dupliqués

**Menaces Atténuées :** Attaques par rejeu, duplication requêtes

---

### Couche 9 : Limitation de Débit
**Technologie :** Algorithme Fenêtre Glissante  
**Objectif :** Empêcher les abus

**Contrôles :**
- 300 requêtes par minute par principal
- Fenêtre glissante (pas fixe)
- Suivi par instance d'agent

**Menaces Atténuées :** Déni de service (DoS), force brute, abus API

---

### Couche 10 : Logique Métier
**Technologie :** Validations Spécifiques à l'Application  
**Objectif :** Appliquer les règles métier

**Contrôles :**
- Validations personnalisées (ex : document existe dans S3)
- Vérifications d'état du workflow
- Application des règles métier

**Menaces Atténuées :** Attaques spécifiques à l'application

---

## Analyse de Scénarios d'Attaque

### Scénario 1 : Token JWT Volé
| Couche | Résultat | Issue |
|--------|----------|-------|
| C1-C3 | ✅ Passe | L'attaquant a un réseau + auth valide |
| C4 | ❌ **ÉCHEC** | Token binding : Incompatibilité certificat |
| **Résultat** | **Bloqué à la Couche 4** | Token inutilisable depuis un autre client |

### Scénario 2 : Initié avec Rôle Viewer Tente de Supprimer
| Couche | Résultat | Issue |
|--------|----------|-------|
| C1-C4 | ✅ Passe | L'initié a un JWT valide |
| C5 | ❌ **ÉCHEC** | RBAC : `viewer` ne peut pas appeler `delete_document` |
| **Résultat** | **Bloqué à la Couche 5** | `403 Forbidden` |

---

## Garanties de Sécurité

✅ **Échec Sécurisé :** Tout échec de couche rejette la requête  
✅ **Indépendant :** Chaque couche fonctionne même si d'autres sont contournées  
✅ **Observable :** Toutes les couches enregistrent les décisions dans CloudWatch  
✅ **Performance :** Surcharge totale < 50ms (< 20% du temps de requête total)

---

## Documentation Liée

- [Architecture Système](ARCHITECTURE_SYSTEME.md)
- [Authentification & Autorisation](AUTHENTIFICATION_AUTORISATION.md)
- [Sécurité Protocole](SECURITE_PROTOCOLE.md)

---

**Fin du Document**
