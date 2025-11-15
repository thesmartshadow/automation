FROM python:3.11-slim

ARG SUBFINDER_VERSION=2.6.6
ARG NUCLEI_VERSION=3.1.1

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/home/reconpanel/.local/bin:$PATH" \
    PYTHONPATH="/app:$PYTHONPATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -o /tmp/subfinder.zip \
    && unzip /tmp/subfinder.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip

RUN curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY reconpanel/ /app/reconpanel

RUN useradd -m reconpanel \
    && mkdir -p /data/wordlists /data/logs /data/db /tmp/reconpanel \
    && chown -R reconpanel:reconpanel /data /app /tmp/reconpanel

USER reconpanel

EXPOSE 9000

CMD ["gunicorn", "-b", "0.0.0.0:9000", "reconpanel.app:create_app()"]
