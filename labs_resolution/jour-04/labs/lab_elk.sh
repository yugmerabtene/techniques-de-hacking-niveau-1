#!/bin/bash
# Lab 4.2 — SOC : Centralisation des logs avec ELK Stack
# Mitigations : M1047 Log Collection + M1030 SIEM
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/env.sh"

echo "=== Lab 4.2 — ELK Stack SOC ==="
echo "Services : Elasticsearch:9200 | Kibana:$ELK_PORT"
echo ""

cd ~/cours-hacking/repo

# Démarrage ELK (profil soc)
docker compose --profile soc up -d elk

# Attente Elasticsearch
echo "Attente Elasticsearch..."
for i in $(seq 1 30); do
    if curl -s http://localhost:9200/_cluster/health > /dev/null 2>&1; then
        echo "Elasticsearch prêt"
        break
    fi
    sleep 2
done

# Vérification Kibana
curl -s -o /dev/null -w "%{http_code}" http://localhost:5601
echo " (Kibana)"

mkdir -p ~/cours-hacking/labs/jour-04
cd ~/cours-hacking/labs/jour-04

echo ""
echo "=== Étape 1 — Vérification des logs ==="
# Vérifier que les conteneurs envoient bien leurs logs
curl -s "http://localhost:9200/_cat/indices?v" | head -20

echo ""
echo "=== Étape 2 — Détection SQLi (T1190) ==="
curl -s "http://localhost:9200/_search?q=keyword:*OR*" | python3 -m json.tool 2>/dev/null || echo "Aucun résultat SQLi"

echo ""
echo "=== Étape 3 — Détection brute-force (T1110) ==="
curl -s "http://localhost:9200/_search?q=response.status_code:401" | python3 -m json.tool 2>/dev/null | head -30

echo ""
echo "=== Étape 4 — Dashboard SOC ==="
echo "Ouvrir http://localhost:5601 dans le navigateur"
echo "Créer un Data View sur 'logs-*'"
echo "Explorer 'Discover' pour visualiser les événements"
echo ""

echo "ELK prêt. Kibana: http://localhost:5601"
