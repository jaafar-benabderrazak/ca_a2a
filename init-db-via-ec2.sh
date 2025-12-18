#!/bin/bash
# Script pour initialiser le schéma DB via EC2 temporaire
# À exécuter dans CloudShell

set -e

export AWS_REGION="eu-west-3"
export VPC_ID="vpc-086392a3eed899f72"
export SUBNET_ID="subnet-0aef6b4fcce7748a9"  # Private subnet
export SG_ID="sg-047a8f39f9cdcaf4c"  # ECS security group
export KEY_NAME="temp-db-init-key"

echo "=== Étape 1: Créer une paire de clés temporaire ==="
aws ec2 create-key-pair \
  --key-name $KEY_NAME \
  --region $AWS_REGION \
  --query 'KeyMaterial' \
  --output text > ${KEY_NAME}.pem

chmod 400 ${KEY_NAME}.pem
echo "✓ Clé créée: ${KEY_NAME}.pem"

echo ""
echo "=== Étape 2: Lancer instance EC2 temporaire ==="
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id ami-0302f42a44bf53a45 \
  --instance-type t2.micro \
  --key-name $KEY_NAME \
  --subnet-id $SUBNET_ID \
  --security-group-ids $SG_ID \
  --region $AWS_REGION \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=temp-db-init},{Key=Purpose,Value=database-initialization}]' \
  --query 'Instances[0].InstanceId' \
  --output text)

echo "✓ Instance lancée: $INSTANCE_ID"

echo ""
echo "=== Étape 3: Attente du démarrage (60 secondes) ==="
sleep 60

# Obtenir l'IP privée
PRIVATE_IP=$(aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --region $AWS_REGION \
  --query 'Reservations[0].Instances[0].PrivateIpAddress' \
  --output text)

echo "✓ IP privée: $PRIVATE_IP"

echo ""
echo "=== Étape 4: Créer le script d'initialisation SQL ==="
cat > init_schema.sql << 'EOF'
-- Create documents table
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    s3_key VARCHAR(500) UNIQUE NOT NULL,
    document_type VARCHAR(50) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_size INTEGER,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processing_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending',
    validation_score FLOAT,
    metadata JSONB,
    extracted_data JSONB,
    validation_details JSONB,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create processing_logs table
CREATE TABLE IF NOT EXISTS processing_logs (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id),
    agent_name VARCHAR(50) NOT NULL,
    action VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    details JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_documents_s3_key ON documents(s3_key);
CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);
CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type);
CREATE INDEX IF NOT EXISTS idx_documents_date ON documents(processing_date);
CREATE INDEX IF NOT EXISTS idx_logs_document_id ON processing_logs(document_id);
CREATE INDEX IF NOT EXISTS idx_logs_agent ON processing_logs(agent_name);

-- Verify
SELECT 'Tables created successfully!' as status;
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' 
ORDER BY table_name;
EOF

echo "✓ Script SQL créé: init_schema.sql"

echo ""
echo "=== Étape 5: Connexion via Session Manager et exécution ==="
echo ""
echo "ATTENTION: Cette étape nécessite une interaction manuelle"
echo ""
echo "Commandes à exécuter:"
echo ""
echo "1. Se connecter à l'instance:"
echo "   aws ssm start-session --target $INSTANCE_ID --region $AWS_REGION"
echo ""
echo "2. Sur l'instance, exécuter:"
echo "   sudo yum install -y postgresql15"
echo ""
echo "3. Obtenir le mot de passe DB:"
echo "   DB_PASSWORD=\$(aws secretsmanager get-secret-value \\"
echo "     --secret-id ca-a2a/db-password \\"
echo "     --region eu-west-3 \\"
echo "     --query 'SecretString' \\"
echo "     --output text)"
echo ""
echo "4. Se connecter et initialiser:"
echo "   psql \"postgresql://postgres:\${DB_PASSWORD}@ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com:5432/documents_db?sslmode=require\" < /tmp/init_schema.sql"
echo ""
echo "5. Taper 'exit' pour quitter la session"
echo ""

read -p "Appuyez sur ENTER une fois l'initialisation terminée..."

echo ""
echo "=== Étape 6: Nettoyage ==="
aws ec2 terminate-instances --instance-ids $INSTANCE_ID --region $AWS_REGION
aws ec2 delete-key-pair --key-name $KEY_NAME --region $AWS_REGION
rm -f ${KEY_NAME}.pem init_schema.sql

echo "✓ Instance terminée"
echo "✓ Clé supprimée"
echo ""
echo "=== TERMINÉ ==="
echo "Le schéma de base de données devrait maintenant être initialisé!"

