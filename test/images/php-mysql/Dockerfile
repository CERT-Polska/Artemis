FROM php:8.0-apache
RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli
RUN apt-get update && apt-get upgrade -y && apt-get -y install libpq-dev systemctl
RUN a2enmod rewrite

COPY test/images/php-mysql/apache2.conf /etc/apache2/
