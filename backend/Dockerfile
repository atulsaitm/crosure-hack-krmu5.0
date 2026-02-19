FROM python:3.11-slim-bookworm

WORKDIR /app

# System deps for Playwright Chromium + build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 \
    libasound2 libatspi2.0-0 libexpat1 libdbus-1-3 \
    libglib2.0-0 libx11-6 libxcb1 libxext6 \
    fonts-liberation fonts-noto-color-emoji \
    wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 --retries=5 -r requirements.txt

# Install Chromium with extended timeout
ENV PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT=120000
RUN playwright install chromium

# Pre-download ChromaDB embedding model so it doesn't download at runtime
RUN python -c "import chromadb; c = chromadb.Client(); col = c.get_or_create_collection('warmup'); col.add(ids=['warmup'], documents=['warmup test']); print('Model downloaded successfully')" || true

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
