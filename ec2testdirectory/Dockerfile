FROM python:3.11-slim

# Prevent Python from buffering logs
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (needed for ansible + psutil)
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY app.py .
COPY templates ./templates

# Create ansible working dir
RUN mkdir -p /ansible/playbooks

# Expose Flask + metrics
EXPOSE 8000

CMD ["python", "app.py"]