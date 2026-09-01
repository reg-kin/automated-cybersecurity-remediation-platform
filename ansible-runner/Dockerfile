FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ansible \
    sshpass \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# Use Gunicorn WSGI server instead of Flask built-in dev server
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "1900", "server:app"]
