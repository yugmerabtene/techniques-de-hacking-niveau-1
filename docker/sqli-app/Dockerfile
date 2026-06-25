# =====================================================================
# Dockerfile — Lab d'Injection SQL (SQLi Shop)
# =====================================================================
# Construit un conteneur PHP/Apache avec une base SQLite exposant
# volontairement 3 points d'injection SQL exploitables.
# Utilisé pour l'apprentissage des injections UNION, blind, booléennes.
# =====================================================================

# Image de base PHP 8.1 avec Apache intégré — pas besoin d'installer Apache séparément
FROM php:8.1-apache

# Installation des extensions PHP nécessaires pour SQLite :
#   pdo          → couche d'abstraction de base de données
#   pdo_sqlite   → driver PDO pour SQLite (nécessaire pour php-sqlite3)
#   sqlite3      → client SQLite en ligne de commande (sqlite3) utilisé
#                  pour initialiser la base via le script init.sql
# Le flag -y évite les prompts, rm -rf nettoie le cache apt
RUN docker-php-ext-install pdo pdo_sqlite \
    && apt-get update && apt-get install -y sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copie du code source de l'application vulnérable dans la racine web d'Apache
COPY app/ /var/www/html/

# Initialisation de la base de données SQLite :
#   COPY init.sql              → copie le script DDL/DML dans le conteneur
#   sqlite3 shop.db < init.sql → exécute le script pour créer tables et données
#   chown www-data:www-data    → donne la propriété à l'utilisateur Apache
#   chmod 666                  → permissions lecture/écriture pour tous
#   Le fichier .db réside dans /var/www/html/ — accessible directement via HTTP !
COPY db/init.sql /tmp/init.sql
RUN sqlite3 /var/www/html/shop.db < /tmp/init.sql \
    && chown www-data:www-data /var/www/html/shop.db \
    && chmod 666 /var/www/html/shop.db

# Exposition du port 80 — Apache écoute sur ce port
EXPOSE 80
