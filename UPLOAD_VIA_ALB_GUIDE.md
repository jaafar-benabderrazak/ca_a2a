# Guide de Test - Upload via ALB

## 🎯 Architecture Implémentée

```
Client → ALB → Orchestrator → UploadHandler → MCP → S3
                    ↓
              ProcessDocument → Pipeline complet
```

## 📦 Fichiers Créés/Modifiés

### Nouveaux Fichiers
- ✅ `upload_handler.py` - Gestionnaire d'upload multipart
- ✅ `UPLOAD_VIA_ALB_GUIDE.md` - Ce guide

### Fichiers Modifiés
- ✅ `orchestrator_agent.py` - Ajout méthodes `handle_upload_document` et `handle_upload_endpoint`
- ✅ `mcp_client_http.py` - Support metadata et content dans `put_object`

## 🚀 Déploiement

### Étape 1 : Tester localement

```bash
# Rebuild orchestrator avec upload handler
docker-compose build orchestrator

# Redémarrer les services
docker-compose up -d orchestrator
```

### Étape 2 : Déployer sur AWS

```powershell
# 1. Build et push nouvelle image
cd c:\Users\Utilisateur\Desktop\projects\ca_a2a

# Login ECR
aws ecr get-login-password --region eu-west-3 | docker login --username AWS --password-stdin 555043101106.dkr.ecr.eu-west-3.amazonaws.com

# Build
docker build -t ca-a2a-orchestrator .

# Tag
docker tag ca-a2a-orchestrator:latest 555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a-orchestrator:latest

# Push
docker push 555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a-orchestrator:latest

# 2. Forcer redéploiement ECS
aws ecs update-service `
  --cluster ca-a2a-cluster `
  --service orchestrator `
  --force-new-deployment `
  --region eu-west-3 `
  --profile AWSAdministratorAccess-555043101106

# 3. Attendre le déploiement
aws ecs wait services-stable `
  --cluster ca-a2a-cluster `
  --services orchestrator `
  --region eu-west-3 `
  --profile AWSAdministratorAccess-555043101106
```

## 🧪 Tests

### Test 1 : Upload Simple (curl)

```bash
# Créer un PDF de test
cat > test_invoice.pdf << 'EOF'
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj
4 0 obj<</Length 55>>stream
BT /F1 12 Tf 100 700 Td (TEST INVOICE VIA ALB) Tj ET
endstream endobj
xref
0 5
trailer<</Size 5/Root 1 0 R>>
startxref
240
%%EOF
EOF

# Upload via ALB
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/upload \
  -F "file=@test_invoice.pdf" \
  -F "folder=invoices/via_alb/test" \
  -F 'metadata={"test":"true","source":"curl"}'

# Résultat attendu :
{
  "success": true,
  "s3_key": "invoices/via_alb/test/20260102_153045_abc123_test_invoice.pdf",
  "file_name": "test_invoice.pdf",
  "file_size": 240,
  "content_type": "application/pdf",
  "upload_id": "abc123",
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "processing_status": "processing",
  "message": "Document uploaded and processing started"
}
```

### Test 2 : Upload Avec Métadonnées

```bash
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/upload \
  -F "file=@facture_acme_dec2025.pdf" \
  -F "folder=invoices/2026/01" \
  -F 'metadata={"uploaded_by":"marie.dubois@reply.com","category":"invoice","vendor":"ACME"}'
```

### Test 3 : Upload via PowerShell

```powershell
# Créer un fichier de test
"Test content" | Out-File -FilePath test.txt -Encoding UTF8

# Upload
$uri = "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/upload"
$file = "test.txt"

$multipartContent = [System.Net.Http.MultipartFormDataContent]::new()
$fileStream = [System.IO.FileStream]::new($file, [System.IO.FileMode]::Open)
$fileContent = [System.Net.Http.StreamContent]::new($fileStream)
$multipartContent.Add($fileContent, "file", $file)

$response = Invoke-WebRequest -Uri $uri -Method Post -Body $multipartContent
$response.Content | ConvertFrom-Json
```

### Test 4 : Upload via Python

```python
import requests

url = "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/upload"

# Préparer le fichier
files = {
    'file': ('invoice.pdf', open('invoice.pdf', 'rb'), 'application/pdf')
}

# Métadonnées optionnelles
data = {
    'folder': 'invoices/python_test',
    'metadata': json.dumps({
        'source': 'python_script',
        'version': '1.0'
    })
}

# Envoyer
response = requests.post(url, files=files, data=data)
print(response.json())
```

### Test 5 : Upload via JavaScript (Frontend)

```html
<!DOCTYPE html>
<html>
<head>
    <title>Upload Document</title>
</head>
<body>
    <h1>CA A2A - Upload Document</h1>
    <input type="file" id="fileInput" />
    <button onclick="uploadFile()">Upload</button>
    <div id="result"></div>

    <script>
        async function uploadFile() {
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            
            if (!file) {
                alert('Please select a file');
                return;
            }
            
            const formData = new FormData();
            formData.append('file', file);
            formData.append('folder', 'invoices/web_upload');
            formData.append('metadata', JSON.stringify({
                uploaded_by: 'web_interface',
                timestamp: new Date().toISOString()
            }));
            
            try {
                const response = await fetch('http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/upload', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                document.getElementById('result').innerHTML = `
                    <h2>Upload Success!</h2>
                    <p>S3 Key: ${result.s3_key}</p>
                    <p>Task ID: ${result.task_id}</p>
                    <p>Status: ${result.processing_status}</p>
                `;
            } catch (error) {
                document.getElementById('result').innerHTML = `
                    <h2 style="color: red;">Upload Failed</h2>
                    <p>${error.message}</p>
                `;
            }
        }
    </script>
</body>
</html>
```

## 🔍 Vérification

### 1. Vérifier l'endpoint est actif

```bash
# Check orchestrator health
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health

# Check logs
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3
```

### 2. Vérifier le fichier dans S3

```bash
# Liste les fichiers uploadés
aws s3 ls s3://ca-a2a-documents/invoices/via_alb/ --recursive

# Voir métadonnées
aws s3api head-object \
  --bucket ca-a2a-documents \
  --key invoices/via_alb/test/20260102_153045_abc123_test_invoice.pdf
```

### 3. Vérifier le traitement

```bash
# Check task status via API
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "get_task_status",
    "params": {"task_id": "550e8400-e29b-41d4-a716-446655440000"},
    "id": 1
  }'
```

## 📊 Monitoring

### CloudWatch Logs

```bash
# Orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3 | grep -i "upload"

# MCP server logs
aws logs tail /ecs/ca-a2a-mcp-server --follow --region eu-west-3 | grep -i "s3_put"
```

### Métriques à Surveiller

- Nombre d'uploads réussis vs échoués
- Taille moyenne des fichiers
- Temps de traitement upload → S3
- Erreurs de validation

## ⚠️ Limites et Considérations

### Limites Techniques

| **Paramètre** | **Valeur** | **Raison** |
|---------------|------------|------------|
| Taille max fichier | 100 MB | Défini dans `UploadHandler` |
| Timeout ALB | 60 secondes | Configuration ALB |
| Connexions simultanées | ~200 | Limite ECS tasks |

### Sécurité

**⚠️ À AJOUTER (Recommandé) :**

1. **Authentification** : JWT ou API Key requis
2. **Rate Limiting** : Limite par IP/utilisateur
3. **Validation de type** : Whitelist extensions (pdf, csv uniquement)
4. **Scan antivirus** : Avant stockage S3
5. **CORS** : Configuration pour web apps

**Exemple avec authentification :**

```python
# Dans handle_upload_endpoint
async def handle_upload_endpoint(self, request):
    # Vérifier JWT
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return web.json_response({
            'error': 'Unauthorized',
            'code': 'MISSING_AUTH'
        }, status=401)
    
    # ... reste du code ...
```

## 🎉 Avantages de Cette Implémentation

1. ✅ **Upload via ALB** : Interface web native
2. ✅ **Intégration MCP** : Accès S3 unifié
3. ✅ **Traitement automatique** : Pipeline déclenché automatiquement
4. ✅ **Métadonnées riches** : Support de metadata custom
5. ✅ **Validation** : Taille, nom de fichier sanitized
6. ✅ **Sécurité** : Sanitization, size limits
7. ✅ **Observabilité** : Logs complets

## 🔄 Comparaison avec S3 Direct

| **Aspect** | **Upload ALB** | **S3 Direct** |
|------------|----------------|---------------|
| **Use case** | Interface web, validation pre-upload | Uploads automatisés, CLI |
| **Performance** | ~500ms | ~100ms |
| **Coût** | Plus cher (ALB + ECS) | Moins cher (S3 seul) |
| **Flexibilité** | Validation custom, transformation | Simple, rapide |
| **Recommandation** | UI/UX requirements | Batch processing |

## 📝 Prochaines Étapes

**Phase 1 : Fonctionnalité de base** ✅
- [x] Upload handler
- [x] Endpoint HTTP
- [x] Intégration MCP
- [x] Traitement automatique

**Phase 2 : Sécurité** 🔄
- [ ] Authentification JWT
- [ ] Rate limiting
- [ ] Validation type fichier
- [ ] CORS configuration

**Phase 3 : Features avancées** ⏳
- [ ] Scan antivirus
- [ ] Transformation (compression, thumbnails)
- [ ] Upload progress (WebSocket)
- [ ] Reprise d'upload (chunked)

---

**Document créé par** : Équipe CA-A2A  
**Date** : 2 janvier 2026  
**Version** : 1.0

