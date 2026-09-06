FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

RUN apt-get update && apt-get install -y --no-install-recommends \
    sshpass \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged identity for the Runner service.
RUN groupadd --gid 10001 ansible-runner \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --create-home \
        --home-dir /home/ansible-runner \
        --shell /usr/sbin/nologin \
        ansible-runner

WORKDIR /workspace

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV HOME=/home/ansible-runner

USER ansible-runner

# Use Gunicorn WSGI server instead of Flask built-in dev server
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "1900", "server:app"]
