FROM python:3.11-slim

WORKDIR /app

# whois CLI is required by python-whois at runtime
RUN apt-get update && apt-get install -y --no-install-recommends whois && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY backend/ .

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
