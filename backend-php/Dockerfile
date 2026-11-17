# =========================================================================
# Production PHP Dockerfile for Cyber Threat Hunting REST API
# PHP 8.2 + Apache with PDO MySQL & Opcache
# =========================================================================

FROM php:8.2-apache-bullseye

LABEL maintainer="AegisHunt Platform Engineering <security@aegishunt.io>"
LABEL description="PHP REST API Backend Container for Threat Hunting & Correlation"

# Install required system libraries and PHP extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzip-dev \
    zip \
    unzip \
    default-mysql-client \
    && docker-php-ext-install pdo pdo_mysql mysqli opcache \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite headers expires

# Copy Apache VirtualHost configuration
COPY apache.conf /etc/apache2/sites-available/000-default.conf

# Set working directory
WORKDIR /var/www/html

# Copy source code
COPY . /var/www/html/

# Copy and set permissions for entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Ensure web server ownership
RUN chown -R www-data:www-data /var/www/html

# Set recommended production PHP settings
RUN echo "expose_php = Off" > /usr/local/etc/php/conf.d/security.ini \
    && echo "memory_limit = 256M" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "post_max_size = 32M" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "upload_max_filesize = 32M" >> /usr/local/etc/php/conf.d/security.ini \
    && echo "date.timezone = UTC" >> /usr/local/etc/php/conf.d/security.ini

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:80/api/scenarios || exit 1

EXPOSE 80

ENTRYPOINT ["/docker-entrypoint.sh"]
