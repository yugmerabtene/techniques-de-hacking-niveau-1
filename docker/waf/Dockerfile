# =====================================================================
# Dockerfile — Lab de Contournement de WAF (ModSecurity)
# =====================================================================
# Construit un conteneur nginx avec ModSecurity CRS (Core Rule Set)
# protégeant une application PHP vulnérable.
# Objectif : apprendre à contourner les règles ModSecurity (bypass WAF)
# pour atteindre l'injection SQL sous-jacente.
# =====================================================================

# Image de base OWASP ModSecurity CRS avec nginx préconfiguré
# Inclut déjà ModSecurity + les règles CRS en mode blocage
FROM owasp/modsecurity-crs:nginx

# Installation de PHP-FPM pour servir l'application vulnérable :
#   php8.1-fpm     → PHP FastCGI Process Manager (écoute sur socket Unix)
#   php8.1-mysqli  → extension MySQLi pour PHP (connexion à la BDD)
# La connexion vers MySQL "db" est simulée — le lab se concentre
# sur le bypass WAF, pas sur l'injection elle-même.
# rm -rf nettoie le cache apt pour réduire la taille de l'image
RUN apt-get update && apt-get install -y php8.1-fpm php8.1-mysqli && rm -rf /var/lib/apt/lists/*

# Copie de l'application PHP vulnérable dans la racine web nginx
COPY app/index.php /usr/share/nginx/html/index.php

# Copie de la configuration nginx (virtual host) qui définit :
#   - le socket PHP-FPM à utiliser
#   - les règles de routage (try_files)
#   - le traitement des fichiers .php via fastcgi
COPY app/default.conf /etc/nginx/conf.d/default.conf

# Préparation de l'environnement :
#   mkdir -p /usr/share/nginx/html → s'assure que le dossier web existe
#   chown -R nginx:nginx           → donne la propriété à l'utilisateur nginx
#   mkdir -p /run/php              → crée le dossier pour le socket PHP-FPM
RUN mkdir -p /usr/share/nginx/html && chown -R nginx:nginx /usr/share/nginx/html && mkdir -p /run/php

# Exposition du port 80 — nginx écoute sur ce port
EXPOSE 80

# Démarrage des deux services :
#   php-fpm8.1 -D    → lance PHP-FPM en arrière-plan (daemon mode)
#   nginx -g ...     → lance nginx en foreground (daemon off = reste PID 1)
# Les deux services tournent dans le même conteneur via un script shell
CMD ["sh", "-c", "php-fpm8.1 -D && nginx -g 'daemon off;'"]

# Note : Les règles ModSecurity CRS sont actives en mode blocage par défaut
# (SecRuleEngine On). Toute requête malveillante sera bloquée avec un 403.
# L'objectif est de trouver des techniques de bypass pour contourner ces règles.
