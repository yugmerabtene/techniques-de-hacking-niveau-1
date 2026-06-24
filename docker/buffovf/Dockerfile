FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc \
    gdb \
    socat \
    && rm -rf /var/lib/apt/lists/*

COPY vuln.c /tmp/vuln.c

RUN gcc -fno-stack-protector -z execstack -no-pie -g -o /opt/vuln /tmp/vuln.c \
    && chmod 4755 /opt/vuln \
    && chown root:root /opt/vuln

EXPOSE 9001

CMD ["socat", "TCP-LISTEN:9001,reuseaddr,fork", "EXEC:/opt/vuln"]
