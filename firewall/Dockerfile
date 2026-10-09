FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps for psycopg2 build (kept minimal).
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput

EXPOSE 8000

# Migrate, seed, then serve. Seeding is idempotent.
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py seed_rules && python manage.py import_threatintel && gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 500"]
