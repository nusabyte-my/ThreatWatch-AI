FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download NLTK data at build time — cached in image layer
RUN python -c "import nltk; nltk.download('stopwords'); nltk.download('punkt'); nltk.download('punkt_tab')"

COPY . .

# Create model directory
RUN mkdir -p /app/ml

EXPOSE 8100

# Railway uses this CMD; local docker-compose overrides via `command:`
CMD ["sh", "-c", "python -m app.db.migrate && python -m app.ml.train --seed && uvicorn app.main:app --host 0.0.0.0 --port 8100"]
