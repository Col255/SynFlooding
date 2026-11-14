FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update repository and install required tools:
# nginx, net-tools, iproute2, iptables, tcpdump, and supporting utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    net-tools \
    iproute2 \
    iptables \
    tcpdump \
    iputils-ping \
    procps \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /workspace

# Copy custom welcome page to Nginx docroot
RUN echo '<!DOCTYPE html><html><head><title>Victim Web Server</title></head><body><h1>Victim Server (192.168.100.10)</h1><p>Status: Active | TCP Port 80 Open</p></body></html>' > /var/www/html/index.html

# Expose default HTTP port
EXPOSE 80

# Copy and set execution permission for entrypoint script
COPY infrastructure/docker/victim/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Run entrypoint to ensure Nginx starts on port 80 and container stays active
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
