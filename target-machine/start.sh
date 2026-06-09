#!/bin/bash
set -e

echo "=== Démarrage du serveur cible ==="

# ---- Démarrer MySQL ----
echo "[1/4] MySQL..."
service mysql start
sleep 3

# ---- Initialiser la base de données ----
echo "[2/4] Initialisation BDD..."
if [ -f /docker-entrypoint-initdb.d/init.sql ]; then
    mysql < /docker-entrypoint-initdb.d/init.sql 2>/dev/null || true
fi

# ---- Démarrer SSH ----
echo "[3/4] SSH..."
mkdir -p /var/run/sshd
/usr/sbin/sshd

# ---- Démarrer Nginx + Flask ----
echo "[4/4] Web server..."
nginx

# Lancer Flask en arrière-plan
cd /opt/app
python3 -m gunicorn -w 2 -b 127.0.0.1:5000 app:app &

echo ""
echo "=== Serveur cible démarré ==="
echo "  SSH:   0.0.0.0:22"
echo "  HTTP:  0.0.0.0:80"
echo "  MySQL: 0.0.0.0:3306"
echo ""

# Garder le container actif
exec tail -f /dev/null
