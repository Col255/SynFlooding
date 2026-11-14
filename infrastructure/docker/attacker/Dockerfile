FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update repository and install attack tools and network utilities:
# hping3, python3, python3-scapy, iputils-ping
RUN apt-get update && apt-get install -y --no-install-recommends \
    hping3 \
    python3 \
    python3-scapy \
    iputils-ping \
    net-tools \
    iproute2 \
    curl \
    tcpdump \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Keep container alive for interactive shell and automated attack runs
CMD ["tail", "-f", "/dev/null"]
