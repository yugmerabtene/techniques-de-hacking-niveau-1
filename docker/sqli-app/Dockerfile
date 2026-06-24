FROM php:8.1-apache

RUN docker-php-ext-install pdo pdo_sqlite \
    && apt-get update && apt-get install -y sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY app/ /var/www/html/

# Initialize SQLite database
COPY db/init.sql /tmp/init.sql
RUN sqlite3 /var/www/html/shop.db < /tmp/init.sql \
    && chown www-data:www-data /var/www/html/shop.db \
    && chmod 666 /var/www/html/shop.db

EXPOSE 80
