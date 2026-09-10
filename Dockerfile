FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /srv/ekyc

# build-essential/libpq for psycopg2; tesseract for OCR; libglib for opencv-headless
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential libpq-dev tesseract-ocr libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir ".[ocr,biometrics]"

COPY alembic.ini ./
COPY alembic ./alembic
COPY scripts ./scripts

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
