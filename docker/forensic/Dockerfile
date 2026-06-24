FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    apache2 \
    php \
    openssh-server \
    sudo \
    && rm -rf /var/lib/apt/lists/*

COPY app/ /var/www/html/

RUN mkdir /var/run/sshd \
    && echo 'root:changeme' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && echo "www-data ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

EXPOSE 80 22

CMD service ssh start && apache2ctl -D FOREGROUND
