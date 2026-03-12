FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for layer caching
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy application code
COPY src/ src/
COPY templates/ templates/
COPY static/ static/

# Re-install with local source so clawmon package is importable
RUN pip install --no-cache-dir -e .

# DB will be stored in a volume
ENV DB_PATH=/data/clawmon.db

EXPOSE 8000

CMD ["uvicorn", "clawmon.main:app", "--host", "0.0.0.0", "--port", "8000"]
