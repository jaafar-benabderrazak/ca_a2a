# 🎬 Guide de Démonstration Rapide - CA-A2A

**Durée:** 10 minutes  
**Prérequis:** Accès à AWS CloudShell

---

## 🎯 Objectif de la Démo

Montrer le pipeline complet de traitement automatisé d'un document :
1. Upload d'un document sur S3
2. Traitement automatique par les agents
3. Validation des données extraites
4. Archivage du document traité
5. Consultation des résultats

---

## ⚙️ Préparation (1 minute)

### Dans AWS CloudShell

```bash
# Définir l'URL de l'ALB
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
export AWS_REGION="eu-west-3"

# (Si l'auth A2A est activée) charger la clé API pour /message
# La Phase 1 écrit normalement: /tmp/ca-a2a-config.env
if [ -f "/tmp/ca-a2a-config.env" ]; then
  source /tmp/ca-a2a-config.env
  export A2A_API_KEY="$A2A_CLIENT_API_KEY"
fi

# Vérifier que tout fonctionne
curl -s "$ALB_URL/health" | jq -r '.status'
# Doit afficher: healthy
```

---

## 🚀 Démonstration

### **Étape 1: Santé du Système** (30 secondes)

```bash
echo "=== 1. Vérification de la Santé du Système ==="
curl -s "$ALB_URL/health" | jq '{
  status,
  agent_name,
  uptime: .uptime_seconds
}'
```

**Résultat attendu:**
```json
{
  "status": "healthy",
  "agent_name": "orchestrator",
  "uptime": 3600
}
```

---

### **Étape 2: Capacités du Système** (30 secondes)

```bash
echo -e "\n=== 2. Capacités Disponibles ==="
curl -s "$ALB_URL/card" | jq '.skills[] | {
  name,
  method,
  description
}' | head -20
```

**Résultat attendu:**
```json
{
  "name": "Process Document",
  "method": "process_document",
  "description": "Orchestrate complete document processing pipeline"
}
{
  "name": "Check Task Status",
  "method": "check_status",
  "description": "Check processing status of a task"
}
...
```

---

### **Étape 3: État Initial** (30 secondes)

```bash
echo -e "\n=== 3. Documents en Attente (Avant Traitement) ==="
curl -s -X POST "$ALB_URL/message" \
  ${A2A_API_KEY:+-H "X-API-Key: $A2A_API_KEY"} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 5},
    "id": 1
  }' | jq '.result'
```

**Résultat attendu:**
```json
{
  "count": 0,
  "documents": []
}
```

---

### **Étape 4: Upload d'un Document** (1 minute)

```bash
echo -e "\n=== 4. Création et Upload d'une Facture Test ==="

# Créer une facture réaliste
cat > facture_demo.txt << 'EOF'
=====================================
      FACTURE COMMERCIALE
=====================================

N° Facture: FAC-2025-12345
Date: 18/12/2025
Date d'échéance: 17/01/2026

FOURNISSEUR:
  Reply S.p.A.
  Corso Francia 110
  10143 Turin, Italie
  TVA: IT12345678901

CLIENT:
  ACME Corporation
  123 Avenue des Champs
  75008 Paris, France
  TVA: FR98765432109

DESCRIPTION:
┌─────────────────────────────────────┬──────┬─────────┬───────────┐
│ Description                         │ Qté  │ Prix U. │ Total     │
├─────────────────────────────────────┼──────┼─────────┼───────────┤
│ Consulting AWS Architecture         │  5 j │ 800 EUR │ 4,000 EUR │
│ Développement Multi-Agents          │ 10 j │ 900 EUR │ 9,000 EUR │
│ Formation DevOps                    │  2 j │ 700 EUR │ 1,400 EUR │
└─────────────────────────────────────┴──────┴─────────┴───────────┘

Sous-total HT:                              14,400.00 EUR
TVA (20%):                                   2,880.00 EUR
                                           ─────────────
TOTAL TTC:                                  17,280.00 EUR

Conditions de paiement: Net 30 jours
Mode de paiement: Virement bancaire
IBAN: FR76 1234 5678 9012 3456 7890 123
BIC: BNPAFRPPXXX

Merci pour votre confiance !
EOF

# Afficher le contenu
echo "Contenu de la facture:"
cat facture_demo.txt | head -15
echo "..."

# Upload vers S3
aws s3 cp facture_demo.txt s3://ca-a2a-documents/uploads/facture_demo.txt --region $AWS_REGION

echo "✅ Document uploadé: uploads/facture_demo.txt"
```

---

### **Étape 5: Lancement du Traitement** (30 secondes)

```bash
echo -e "\n=== 5. Lancement du Traitement Automatique ==="

RESPONSE=$(curl -s -X POST "$ALB_URL/message" \
  ${A2A_API_KEY:+-H "X-API-Key: $A2A_API_KEY"} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {
      "s3_key": "uploads/facture_demo.txt",
      "document_type": "invoice"
    },
    "id": 2
  }')

echo "$RESPONSE" | jq '.'

# Extraire le task_id
TASK_ID=$(echo "$RESPONSE" | jq -r '.result.task_id // empty')

if [ -z "$TASK_ID" ]; then
  echo "⚠️  Pas de task_id reçu - Vérifier la réponse ci-dessus"
else
  echo "✅ Traitement lancé - Task ID: $TASK_ID"
fi
```

---

### **Étape 6: Suivi du Traitement** (2 minutes)

```bash
echo -e "\n=== 6. Suivi du Traitement (polling toutes les 5s) ==="

if [ ! -z "$TASK_ID" ]; then
  for i in {1..6}; do
    echo "Vérification #$i ($(date +%H:%M:%S))..."
    
    STATUS_RESPONSE=$(curl -s -X POST "$ALB_URL/message" \
      ${A2A_API_KEY:+-H "X-API-Key: $A2A_API_KEY"} \
      -H "Content-Type: application/json" \
      -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"check_status\",
        \"params\": {\"task_id\": \"$TASK_ID\"},
        \"id\": $((i+2))
      }")
    
    echo "$STATUS_RESPONSE" | jq '.result // .error'
    
    STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.result.status // empty')
    
    if [ "$STATUS" = "completed" ]; then
      echo "✅ Traitement terminé !"
      break
    elif [ "$STATUS" = "failed" ]; then
      echo "❌ Traitement échoué"
      break
    fi
    
    if [ $i -lt 6 ]; then
      echo "Attente 5 secondes..."
      sleep 5
    fi
  done
else
  echo "⚠️  Impossible de suivre le traitement (pas de task_id)"
fi
```

---

### **Étape 7: Vérification des Résultats** (1 minute)

```bash
echo -e "\n=== 7. Documents Traités ==="
curl -s -X POST "$ALB_URL/message" \
  ${A2A_API_KEY:+-H "X-API-Key: $A2A_API_KEY"} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 10},
    "id": 99
  }' | jq '.result.documents[] | {
    id,
    file_name,
    status,
    document_type,
    created_at
  }'

echo -e "\n=== 8. Fichiers Archivés dans S3 ==="
aws s3 ls s3://ca-a2a-documents/archived/ --region $AWS_REGION --recursive --human-readable | tail -5
```

---

## 📊 Résumé de la Démo

### ✅ Ce Qui a Été Démontré

1. **Santé du Système** - Orchestrator accessible et fonctionnel
2. **Capacités** - 5+ compétences disponibles (extraction, validation, archivage)
3. **API JSON-RPC 2.0** - Communication standardisée
4. **Upload S3** - Intégration avec stockage cloud
5. **Traitement Asynchrone** - Task ID pour suivi
6. **Pipeline Multi-Agents:**
   - **Extractor** → Extraction des données (montant, date, TVA, etc.)
   - **Validator** → Validation de la structure et du contenu
   - **Archivist** → Archivage dans S3 avec métadonnées
7. **Persistence** - Données stockées dans PostgreSQL
8. **Traçabilité** - Logs CloudWatch pour chaque étape

---

## 🎯 Points Clés à Mentionner

### Architecture
- **Multi-Agents:** 4 agents spécialisés (Orchestrator, Extractor, Validator, Archivist)
- **Protocoles Standardisés:**
  - **A2A (Agent-to-Agent):** Communication JSON-RPC 2.0
  - **MCP (Model Context Protocol):** Accès unifié S3 + PostgreSQL
- **Déploiement AWS:** ECS Fargate + ALB + RDS + S3
- **Haute Disponibilité:** 2 AZ, 2 tasks par service

### Avantages Business
- ✅ **Automatisation Complète:** Pas d'intervention manuelle
- ✅ **Scalabilité:** ECS Fargate auto-scaling
- ✅ **Traçabilité:** Chaque action loggée dans CloudWatch
- ✅ **Sécurité:** VPC privé, VPC Endpoints, SSL/TLS
- ✅ **Extensible:** Facile d'ajouter de nouveaux agents

---

## 🔍 Commandes de Diagnostic (Si Problème)

```bash
# Vérifier les services ECS
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist \
  --region $AWS_REGION \
  --query 'services[*].[serviceName,status,runningCount,desiredCount]' \
  --output table

# Vérifier les logs récents
aws logs tail /ecs/ca-a2a-orchestrator --since 5m --region $AWS_REGION

# Vérifier la santé des targets ALB
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region $AWS_REGION \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State]' \
  --output table
```

---

## 📝 Notes pour le Présentateur

### Timing Recommandé
- **Introduction:** 1 min - Présenter l'objectif
- **Health Check:** 30s - Montrer que tout fonctionne
- **Capacités:** 30s - Montrer les compétences disponibles
- **Upload:** 1 min - Créer et uploader le document
- **Traitement:** 2-3 min - Lancer et suivre le traitement
- **Résultats:** 1 min - Montrer les résultats
- **Architecture:** 2 min - Expliquer le diagramme
- **Questions:** 2 min - Q&A

**Total:** ~10 minutes

### Points d'Attention
- ⚠️ Si le schéma DB n'est pas initialisé, l'étape 3 et 7 échoueront
- ⚠️ Le traitement peut prendre 10-30 secondes selon la charge
- ⚠️ Avoir un navigateur ouvert sur AWS Console (CloudWatch Logs) pour montrer les logs en temps réel

### Initialiser le schéma DB (obligatoire pour une démo fluide)

Le plus simple (et reproductible) est de lancer une **tâche ECS one-off** qui exécute `python init_db.py init` dans le conteneur *orchestrator* (même VPC/subnets/SG/secrets que le service).

#### PowerShell (Windows)

```powershell
$AWS_REGION = 'eu-west-3'
$CLUSTER = 'ca-a2a-cluster'

# Récupérer la config réseau (subnets + SG) du service orchestrator
$taskDef = aws ecs describe-services --profile reply-sso --cluster $CLUSTER --services orchestrator --region $AWS_REGION --query 'services[0].taskDefinition' --output text
$subnets = (aws ecs describe-services --profile reply-sso --cluster $CLUSTER --services orchestrator --region $AWS_REGION --query 'services[0].networkConfiguration.awsvpcConfiguration.subnets' --output text).Split()
$sg = aws ecs describe-services --profile reply-sso --cluster $CLUSTER --services orchestrator --region $AWS_REGION --query 'services[0].networkConfiguration.awsvpcConfiguration.securityGroups[0]' --output text

# Init schema
$ov = 'file://c:/Users/j.benabderrazak/OneDrive - Reply/Bureau/work/CA/A2A/ca_a2a/scripts/ecs_overrides_init_db.json'
$taskArn = aws ecs run-task --profile reply-sso --region $AWS_REGION --cluster $CLUSTER --launch-type FARGATE --task-definition $taskDef --count 1 `
  --network-configuration "awsvpcConfiguration={subnets=[$($subnets -join ',')],securityGroups=[$sg],assignPublicIp=DISABLED}" `
  --overrides $ov --query 'tasks[0].taskArn' --output text
aws ecs wait tasks-stopped --profile reply-sso --region $AWS_REGION --cluster $CLUSTER --tasks $taskArn
aws ecs describe-tasks --profile reply-sso --region $AWS_REGION --cluster $CLUSTER --tasks $taskArn --query 'tasks[0].containers[0].exitCode' --output text

# Check schema (optionnel)
$ovCheck = 'file://c:/Users/j.benabderrazak/OneDrive - Reply/Bureau/work/CA/A2A/ca_a2a/scripts/ecs_overrides_check_db.json'
$taskArn2 = aws ecs run-task --profile reply-sso --region $AWS_REGION --cluster $CLUSTER --launch-type FARGATE --task-definition $taskDef --count 1 `
  --network-configuration "awsvpcConfiguration={subnets=[$($subnets -join ',')],securityGroups=[$sg],assignPublicIp=DISABLED}" `
  --overrides $ovCheck --query 'tasks[0].taskArn' --output text
aws ecs wait tasks-stopped --profile reply-sso --region $AWS_REGION --cluster $CLUSTER --tasks $taskArn2
aws ecs describe-tasks --profile reply-sso --region $AWS_REGION --cluster $CLUSTER --tasks $taskArn2 --query 'tasks[0].containers[0].exitCode' --output text
```

#### Test rapide API (Étape 3)

Utilisez un fichier JSON (évite les soucis d’échappement sur Windows) :

```powershell
$ALB = 'ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com'
$A2A_API_KEY = (Get-Content .\\security-deploy-summary.json | ConvertFrom-Json).client_api_key

curl.exe -s -w "`nstatus=%{http_code}`n" `
  -H "Content-Type: application/json" `
  -H "X-API-Key: $A2A_API_KEY" `
  -X POST "http://$ALB/message" `
  --data-binary "@scripts/request_list_pending.json"
```

Troubleshooting réseau (si `CannotPullContainerError` vers ECR) :

- vérifier que l’agent peut sortir en `tcp/443` (NAT ou VPC endpoints) et que le SG des VPC endpoints autorise l’ingress depuis les SGs des agents.

---

## 🎬 Script de Présentation Suggéré

> "Bonjour, je vais vous montrer notre pipeline de traitement intelligent de documents déployé sur AWS.
>
> **[Étape 1-2]** Le système est composé d'un orchestrateur et de 3 agents spécialisés, tous accessibles via une API REST standardisée. Comme vous pouvez le voir, le système est en bonne santé et offre plusieurs capacités : extraction, validation, et archivage.
>
> **[Étape 3]** Actuellement, il n'y a aucun document en attente de traitement.
>
> **[Étape 4]** Je vais maintenant créer une facture commerciale fictive et l'uploader sur S3. Cette facture contient des informations structurées : montants, TVA, dates, etc.
>
> **[Étape 5]** Je lance maintenant le traitement via l'API. L'orchestrateur va coordonner les différents agents pour traiter ce document de manière automatique.
>
> **[Étape 6]** Pendant le traitement, je peux suivre l'état de la tâche. L'extracteur extrait les données, le validateur vérifie leur cohérence, et l'archiviste sauvegarde le tout.
>
> **[Étape 7]** Et voilà ! Le document a été traité et archivé. Nous pouvons voir qu'il apparaît maintenant dans notre base de données avec son statut et ses métadonnées.
>
> Ce système est déployé sur AWS avec haute disponibilité, traçabilité complète, et peut facilement évoluer en ajoutant de nouveaux types d'agents selon les besoins métier."

---

## Bonne démonstration
