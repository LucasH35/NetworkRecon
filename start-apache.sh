#!/bin/bash
# Script de lancement Apache2 sur le port 44

set -e

echo "=== Configuration Apache2 - Port 44 ==="

# 1. Copier index.html
echo "[1/4] Copie de index.html vers /var/www/html/..."
sudo cp /home/lucash/Documents/Lab/index.html /var/www/html/index.html

# 2. Configurer le port 44 dans ports.conf
echo "[2/4] Configuration du port 44..."
sudo bash -c 'cat > /etc/apache2/ports.conf << EOF
Listen 44
EOF'

# 3. Configurer le VirtualHost sur le port 44
echo "[3/4] Configuration du VirtualHost..."
sudo bash -c 'cat > /etc/apache2/sites-available/000-default.conf << EOF
<VirtualHost *:44>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF'

# 4. Redémarrer Apache2
echo "[4/4] Redémarrage d'Apache2..."
sudo systemctl restart apache2

echo ""
echo "=== Apache2 lancé avec succès sur le port 44 ==="
echo "=> Accédez à : http://localhost:44"
echo ""
