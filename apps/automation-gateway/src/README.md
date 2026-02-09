# FastAPI Telemetry Application

A FastAPI application with OpenTelemetry auto-instrumentation, Prometheus metrics, MySQL, and Redis integration.

## Building the Docker Image

```bash
# Build the image
docker build -t fastapi-telemetry:latest .

# Or with a specific tag for your registry
docker build -t <your-registry>/fastapi-telemetry:v1.0.0 .
```

## Push to Container Registry

```bash
# For Docker Hub
docker push <your-dockerhub-username>/fastapi-telemetry:v1.0.0

# For GitHub Container Registry
docker tag fastapi-telemetry:latest ghcr.io/<your-github-username>/fastapi-telemetry:v1.0.0
docker push ghcr.io/<your-github-username>/fastapi-telemetry:v1.0.0

# For Amazon ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com
docker tag fastapi-telemetry:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/fastapi-telemetry:v1.0.0
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/fastapi-telemetry:v1.0.0
```

## Running Locally

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your values

# Install dependencies
pip install -r requirements.txt
opentelemetry-bootstrap -a install

# Run with OpenTelemetry
./run.sh

# Or run directly without OTel
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MYSQL_HOST` | mysql | MySQL hostname |
| `MYSQL_PORT` | 3306 | MySQL port |
| `MYSQL_USER` | root | MySQL username |
| `MYSQL_PASSWORD` | rootpassword | MySQL password |
| `MYSQL_DATABASE` | testdb | MySQL database name |
| `REDIS_HOST` | redis | Redis hostname |
| `REDIS_PORT` | 6379 | Redis port |
| `REDIS_PASSWORD` | (empty) | Redis password |

## API Endpoints

### Health & Metrics
- `GET /` - Health check
- `GET /health` - Detailed health (MySQL + Redis status)
- `GET /metrics` - Prometheus metrics

### MySQL (Items)
- `GET /items` - List all items
- `GET /items/{id}` - Get item by ID
- `POST /items?name=...&description=...` - Create item

### Redis (Cache)
- `GET /cache/{key}` - Get cached value
- `POST /cache/{key}?value=...&ttl=300` - Set cached value
- `DELETE /cache/{key}` - Delete cached key
- `POST /cache/counter/{key}?amount=1` - Increment counter
- `GET /cache/stats` - Cache hit/miss stats

### Testing
- `GET /slow` - Slow endpoint (1-3s delay)
- `GET /error` - Always returns 500
- `GET /random` - Random log levels
