FROM projectdiscovery/nuclei:latest AS nuclei

FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY run_scan.py .

ENTRYPOINT ["python", "run_scan.py"]
