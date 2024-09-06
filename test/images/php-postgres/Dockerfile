FROM php:8.0-apache
RUN apt-get update && apt-get upgrade -y && apt-get -y install libpq-dev systemctl
RUN docker-php-ext-install pgsql && docker-php-ext-enable pgsql
