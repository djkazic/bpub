FROM ubuntu:24.04

WORKDIR /app

RUN apt-get update \
  && apt-get install -y python3.12 python3.12-dev python3-pip libsecp256k1-dev \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir secp256k1 python-bitcointx bip-utils requests --break-system-packages

COPY . .

CMD ["sleep", "infinity"]
