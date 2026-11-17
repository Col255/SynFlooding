FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    hping3 \
    iproute2 \
    iptables \
    curl \
    python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY slowloris_worker.py /app/slowloris_worker.py
CMD ["sleep", "infinity"]
