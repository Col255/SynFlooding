FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update repository and install required tools:
# curl, python3, iputils-ping, and networking diagnostic tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    python3 \
    python3-pip \
    iputils-ping \
    net-tools \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Keep container alive for background benchmark and verification loops
CMD ["tail", "-f", "/dev/null"]
