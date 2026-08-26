FROM python:3.12-slim
WORKDIR /app

# Dependencias nativas do WeasyPrint (renderiza HTML/CSS para PDF via Pango/Cairo)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY generate_report.py template.html ./

ENTRYPOINT ["python", "generate_report.py"]
