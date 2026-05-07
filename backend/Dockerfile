FROM python:3.12-slim

# System dependencies for WeasyPrint, psycopg2, python-magic
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libmagic1 \
    # pg_dump / psql for backup and restore
    postgresql-client \
    # git for system update pull
    git \
    # WeasyPrint dependencies
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libffi-dev \
    libjpeg62-turbo \
    libopenjp2-7 \
    # Fonts
    fonts-liberation \
    fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=120 --retries=5 -r requirements.txt

# Copy project
COPY . .

# Create directories for media, static, quarantine, backups
RUN mkdir -p /app/media /app/static /app/quarantine /app/backups

# Non-root user for security
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app /app/backups
USER appuser

EXPOSE 8000
