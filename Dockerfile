FROM ubuntu:24.04

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3.12 python3.12-dev python3-pip libsecp256k1-dev ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --break-system-packages

COPY . .

EXPOSE 8888

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8888"]
