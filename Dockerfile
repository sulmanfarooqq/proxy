FROM python:3.12-slim

# Create non-root user for security
RUN groupadd -r proxyuser && useradd -r -g proxyuser proxyuser

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Disable Python's default site-packages behavior
    PYTHONNOUSERSITE=1

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir --no-compile -r requirements.txt

# Copy application code
COPY app.py .

# Drop privileges
USER proxyuser

# Expose port (but use a non-standard port for obscurity)
EXPOSE 8080

# Run with minimal logging
CMD ["python", "-O", "-u", "app.py"]