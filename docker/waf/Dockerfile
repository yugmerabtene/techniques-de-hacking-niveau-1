FROM owasp/modsecurity-crs:nginx

COPY app/index.php /usr/share/nginx/html/index.php
COPY app/default.conf /etc/nginx/conf.d/default.conf

RUN mkdir -p /usr/share/nginx/html && chown -R nginx:nginx /usr/share/nginx/html
