FROM owasp/modsecurity-crs:nginx

RUN apt-get update && apt-get install -y php8.1-fpm php8.1-mysqli && rm -rf /var/lib/apt/lists/*
COPY app/index.php /usr/share/nginx/html/index.php
COPY app/default.conf /etc/nginx/conf.d/default.conf
RUN mkdir -p /usr/share/nginx/html && chown -R nginx:nginx /usr/share/nginx/html && mkdir -p /run/php
EXPOSE 80

CMD ["sh", "-c", "php-fpm8.1 -D && nginx -g 'daemon off;'"]

# Note : ModSecurity CRS rules actives en mode blocage (SecRuleEngine On)
