# Sécurité du Protocole CA-A2A

**Version :** 6.0  
**Dernière mise à jour :** 17 janvier 2026

---

## Protocole JSON-RPC 2.0

### Pourquoi JSON-RPC 2.0 ?

✅ **Standardisé :** Spécification bien définie, comportement prévisible  
✅ **Simple :** Surcharge minimale (~100-200 octets)  
✅ **Sécurisé :** Validation déterministe, pas d'ambiguïté  
✅ **Agnostique Langage :** JSON est universel  
✅ **Gestion d'Erreurs :** Codes d'erreur standardisés

---

## Structure des Messages

### Format Requête

```json
{
  "jsonrpc": "2.0",
  "id": "req-abc123",
  "method": "process_document",
  "params": {
    "s3_key": "uploads/facture.pdf",
    "priority": "high"
  }
}
```

### Format Réponse

```json
{
  "jsonrpc": "2.0",
  "id": "req-abc123",
  "result": {
    "status": "success",
    "document_id": "doc-789"
  }
}
```

### Format Erreur

```json
{
  "jsonrpc": "2.0",
  "id": "req-abc123",
  "error": {
    "code": -32602,
    "message": "Paramètres invalides",
    "data": {"detail": "Champ 's3_key' requis"}
  }
}
```

---

## Contrôles de Sécurité

### 1. Validation JSON Schema

**Objectif :** Rejeter les entrées malformées

**Fonctionnalités de Sécurité :**
- Protection traversée de chemins (`../` bloqué)
- Limites de longueur (empêche DoS)
- Sécurité des types (string vs number)
- Aucune propriété supplémentaire (empêche affectation de masse)

### 2. Intégrité des Messages (Liaison Hash du Corps)

**Implémentation :**
```python
# Calculer hash SHA-256 du corps de requête
body_hash = hashlib.sha256(json.dumps(params).encode()).hexdigest()

# Ajouter aux claims JWT
jwt_claims = {"body_hash": body_hash, ...}

# Vérifier côté agent
if not secrets.compare_digest(expected_hash, actual_hash):
    raise ValueError("Falsification du corps détectée")
```

### 3. Protection contre le Rejeu

**Implémentation :**
```python
# Vérifier JWT jti (ID unique token)
jti = jwt_claims["jti"]
if await replay_protector.is_seen(jti):
    raise ValueError("Attaque par rejeu détectée")

# Marquer comme vu (TTL : 120 secondes)
await replay_protector.mark_seen(jti, ttl=120)
```

### 4. Limitation de Débit

**Configuration :**
- **Limite :** 300 requêtes par minute par principal
- **Algorithme :** Fenêtre glissante
- **Réponse :** `429 Too Many Requests`

---

## Comparaison Temps Constant

**Objectif :** Empêcher les attaques par timing

**Implémentation :**
```python
import hmac
import secrets

# Vérification clé API
if hmac.compare_digest(provided_digest, expected_digest):
    return True

# Vérification liaison token
if secrets.compare_digest(token_thumbprint, cert_thumbprint):
    return True
```

**Pourquoi ?** La comparaison standard `==` échoue rapidement à la première différence, divulguant de l'information via le timing.

---

## Codes d'Erreur

| Code | Signification | Cas d'Usage |
|------|---------------|-------------|
| `-32700` | Erreur d'analyse | JSON invalide |
| `-32600` | Requête invalide | Champs requis manquants |
| `-32601` | Méthode introuvable | Méthode inconnue |
| `-32602` | Paramètres invalides | Validation schema échouée |
| `-32603` | Erreur interne | Erreur serveur |
| `-32001` | Non autorisé | JWT invalide |
| `-32002` | Interdit | Permissions insuffisantes |
| `-32003` | Limite débit dépassée | Trop de requêtes |
| `-32004` | Rejeu détecté | jti dupliqué |
| `-32005` | Token révoqué | Token révoqué utilisé |

---

**Lié :** [Couches de Sécurité](COUCHES_SECURITE_DEFENSE_EN_PROFONDEUR.md), [Authentification](AUTHENTIFICATION_AUTORISATION.md)
