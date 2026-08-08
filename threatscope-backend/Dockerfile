FROM python:3.11-slim

WORKDIR /app

# ── System dependencies ──────────────────────────────────────
# libmagic: python-magic file type detection
# gcc: compile native extensions (bcrypt, yara-python)
# whois: system WHOIS client used by python-whois
# curl: download YARA rules
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    gcc \
    whois \
    curl \
    libfuzzy-dev \
    build-essential

# ── Python dependencies ─────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Playwright Chromium + system deps ────────────────────────
# install-deps pulls in fonts, libraries required by headless Chrome
RUN playwright install-deps chromium && \
    playwright install chromium

# ── Cleanup ──────────────────────────────────────────────────
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Copy application code ───────────────────────────────────
COPY . .

RUN chmod +x entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
