FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ---- Install all services ----
RUN apt-get update && apt-get install -y \
    openssh-server \
    nginx \
    python3 \
    python3-pip \
    mysql-server \
    supervisor \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ---- MySQL ----
RUN mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld
COPY mysql/init.sql /docker-entrypoint-initdb.d/init.sql
COPY mysql/my.cnf /etc/mysql/conf.d/custom.cnf

# ---- SSH ----
RUN mkdir /var/run/sshd
COPY ssh/sshd_config /etc/ssh/sshd_config
RUN echo 'root:target2025' | chpasswd
RUN useradd -m -s /bin/bash admin && echo 'admin:admin2025' | chpasswd
RUN useradd -m -s /bin/bash deploy && echo 'deploy:deploy2025' | chpasswd
RUN useradd -m -s /bin/bash webapp && echo 'webapp:webapp2025' | chpasswd

# ---- Nginx ----
COPY nginx/default.conf /etc/nginx/sites-available/default

# ---- App Flask ----
WORKDIR /opt/app
COPY app/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY app/ .

# ---- Startup script ----
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 22 80 3306

CMD ["/start.sh"]
