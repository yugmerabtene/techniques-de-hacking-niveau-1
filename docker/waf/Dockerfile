# =====================================================================
# Dockerfile — Lab de Contournement de WAF (ModSecurity)
# =====================================================================
FROM owasp/modsecurity-crs:nginx

USER root

RUN apt-get update && apt-get install -y php-fpm php-mysqli && rm -rf /var/lib/apt/lists/*

COPY app/index.php /usr/share/nginx/html/index.php
COPY app/default.conf.template /etc/nginx/templates/conf.d/default.conf.template

RUN mkdir -p /usr/share/nginx/html && chown -R nginx:nginx /usr/share/nginx/html \
    && mkdir -p /run/php \
    && usermod -aG www-data nginx \
    && sed -i 's/^listen.mode = .*/listen.mode = 0666/' /etc/php/8.4/fpm/pool.d/www.conf

RUN printf '#!/bin/sh\nset -e\n/usr/sbin/php-fpm8.4 -D\n' > /docker-entrypoint.d/15-start-php-fpm.sh \
    && chmod +x /docker-entrypoint.d/15-start-php-fpm.sh

EXPOSE 80
