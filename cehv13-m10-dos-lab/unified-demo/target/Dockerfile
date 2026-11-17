FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    iproute2 \
    iptables \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY target_node.py /app/target_node.py
CMD ["python", "-u", "/app/target_node.py"]
