# AIPT v2 Deployment Guide

This guide covers deploying AIPT v2 (AI-Powered Penetration Testing Framework) in various environments.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Environment Configuration](#environment-configuration)
4. [Deployment Options](#deployment-options)
   - [Docker Compose (Recommended)](#docker-compose-recommended)
   - [Kubernetes](#kubernetes)
   - [Manual Installation](#manual-installation)
5. [Health Checks & Monitoring](#health-checks--monitoring)
6. [Security Considerations](#security-considerations)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/aipt-v2.git
cd aipt-v2

# Copy environment template
cp .env.example .env

# Edit .env with your API keys
vim .env

# Start with Docker Compose
docker-compose up -d

# Verify deployment
curl http://localhost:8000/health
```

---

## Prerequisites

### Required
- **Docker** >= 20.10.0
- **Docker Compose** >= 2.0.0
- **Python** >= 3.11 (for manual installation)

### Recommended
- **LLM API Key**: Anthropic Claude or OpenAI GPT (for AI features)
- **4GB RAM** minimum (8GB recommended)
- **10GB disk space**

---

## Environment Configuration

Create a `.env` file from the template:

```bash
cp .env.example .env
```

### Required Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_PASSWORD` | PostgreSQL password | `aipt_secret` |
| `ANTHROPIC_API_KEY` | Anthropic API key | (none) |
| `OPENAI_API_KEY` | OpenAI API key | (none) |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AIPT_API_PORT` | API server port | `8000` |
| `AIPT_LOG_LEVEL` | Logging level | `INFO` |
| `AIPT_LOG_FORMAT` | Log format (json/console) | `json` |
| `AIPT_CORS_ORIGINS` | Allowed CORS origins | `http://localhost:3000` |
| `DATABASE_URL` | PostgreSQL connection URL | (auto-configured) |
| `REDIS_URL` | Redis connection URL | (auto-configured) |
| `GRAFANA_PASSWORD` | Grafana admin password | `admin` |

### Scanner Integration (Optional)

| Variable | Description |
|----------|-------------|
| `ACUNETIX_URL` | Acunetix API endpoint |
| `ACUNETIX_API_KEY` | Acunetix API key |
| `BURP_URL` | Burp Suite Enterprise URL |
| `BURP_API_KEY` | Burp Suite API key |

### Example `.env` File

```env
# Database
POSTGRES_PASSWORD=your_secure_password_here

# LLM API Keys (at least one required for AI features)
ANTHROPIC_API_KEY=sk-ant-api-xxxxx
# OPENAI_API_KEY=sk-xxxxx

# API Configuration
AIPT_API_PORT=8000
AIPT_LOG_LEVEL=INFO
AIPT_CORS_ORIGINS=http://localhost:3000,http://localhost:8080

# Monitoring
GRAFANA_PASSWORD=secure_grafana_password
```

---

## Deployment Options

### Docker Compose (Recommended)

#### Production Deployment

```bash
# Start core services (API, Database, Redis)
docker-compose up -d

# Verify all services are healthy
docker-compose ps
```

#### Development Deployment

```bash
# Start with hot-reload enabled
docker-compose --profile dev up -d
```

#### With Monitoring Stack

```bash
# Start with Prometheus + Grafana
docker-compose --profile monitoring up -d

# Access Grafana at http://localhost:3001
# Default credentials: admin / admin (or GRAFANA_PASSWORD)
```

#### With Background Worker

```bash
# Start with worker for background tasks
docker-compose --profile worker up -d
```

#### Full Stack (All Profiles)

```bash
docker-compose --profile dev --profile worker --profile monitoring up -d
```

### Service Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| API | http://localhost:8000 | REST API |
| API Docs | http://localhost:8000/docs | Swagger UI |
| Health | http://localhost:8000/health | Health check |
| Metrics | http://localhost:8000/metrics | Prometheus metrics |
| Grafana | http://localhost:3001 | Monitoring dashboard |
| Prometheus | http://localhost:9090 | Metrics storage |

---

### Kubernetes

#### Prerequisites

- Kubernetes cluster >= 1.25
- kubectl configured
- Helm >= 3.0 (optional)

#### Basic Deployment

Create Kubernetes manifests:

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: aipt

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aipt-config
  namespace: aipt
data:
  AIPT_LOG_LEVEL: "INFO"
  AIPT_LOG_FORMAT: "json"

---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: aipt-secrets
  namespace: aipt
type: Opaque
stringData:
  POSTGRES_PASSWORD: "your-secure-password"
  ANTHROPIC_API_KEY: "sk-ant-api-xxxxx"

---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aipt-api
  namespace: aipt
spec:
  replicas: 2
  selector:
    matchLabels:
      app: aipt-api
  template:
    metadata:
      labels:
        app: aipt-api
    spec:
      containers:
      - name: aipt-api
        image: aipt-v2:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: aipt-config
        - secretRef:
            name: aipt-secrets
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
```

Apply manifests:

```bash
kubectl apply -f k8s/
```

---

### Manual Installation

#### 1. Install Python Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

#### 2. Setup Database

```bash
# Install PostgreSQL (Ubuntu)
sudo apt-get install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql -c "CREATE USER aipt WITH PASSWORD 'your_password';"
sudo -u postgres psql -c "CREATE DATABASE aipt OWNER aipt;"

# Set environment variable
export DATABASE_URL="postgresql://aipt:your_password@localhost:5432/aipt"
```

#### 3. Setup Redis (Optional)

```bash
# Install Redis (Ubuntu)
sudo apt-get install redis-server

# Set environment variable
export REDIS_URL="redis://localhost:6379/0"
```

#### 4. Run the Application

```bash
# Set environment variables
export ANTHROPIC_API_KEY="sk-ant-api-xxxxx"
export AIPT_LOG_LEVEL="INFO"

# Run with uvicorn
uvicorn aipt_v2.app:app --host 0.0.0.0 --port 8000

# Or with hot-reload for development
uvicorn aipt_v2.app:app --host 0.0.0.0 --port 8000 --reload
```

---

## Health Checks & Monitoring

### Endpoints

| Endpoint | Description | Use Case |
|----------|-------------|----------|
| `GET /health` | Basic health check | General health |
| `GET /health/live` | Liveness probe | Kubernetes liveness |
| `GET /health/ready` | Readiness probe | Kubernetes readiness |
| `GET /health/info` | Service information | Debugging |
| `GET /metrics` | Prometheus metrics | Monitoring |

### Health Check Response

```json
{
  "status": "healthy",
  "version": "2.0.0",
  "timestamp": "2024-12-14T10:30:00Z",
  "uptime_seconds": 3600.5,
  "environment": "production"
}
```

### Readiness Check Response

```json
{
  "status": "healthy",
  "version": "2.0.0",
  "timestamp": "2024-12-14T10:30:00Z",
  "checks": {
    "database": {"status": "healthy", "latency_ms": 2.5},
    "redis": {"status": "healthy", "latency_ms": 0.8},
    "llm_api": {"status": "healthy", "message": "API key configured"},
    "disk": {"status": "healthy", "message": "85.2% free"},
    "memory": {"status": "healthy", "message": "45.3% used"}
  }
}
```

### Prometheus Metrics

Available metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `aipt_http_requests_total` | Counter | Total HTTP requests |
| `aipt_scan_requests_total` | Counter | Total scan requests |
| `aipt_tool_invocations_total` | Counter | Tool invocations |
| `aipt_errors_total` | Counter | Total errors |
| `aipt_active_scans` | Gauge | Currently active scans |
| `aipt_uptime_seconds` | Gauge | Service uptime |
| `process_resident_memory_bytes` | Gauge | Memory usage |
| `process_cpu_percent` | Gauge | CPU usage |

### Grafana Dashboard

Access Grafana at http://localhost:3001 (when using monitoring profile).

Pre-built dashboard includes:
- CPU and memory usage gauges
- Request rate graph
- Scan activity timeline
- Uptime indicator

---

## Security Considerations

### Network Security

1. **Firewall Rules**: Only expose port 8000 to trusted networks
2. **TLS/SSL**: Use a reverse proxy (nginx, Traefik) for HTTPS
3. **VPN**: Deploy in a private network when possible

### API Security

1. **Rate Limiting**: Default 10 req/min for scans, 5 req/min for tools
2. **CORS**: Restricted to configured origins (not `*`)
3. **Input Validation**: All inputs sanitized for command injection

### Secrets Management

1. **Environment Variables**: Use `.env` files (not committed to git)
2. **Docker Secrets**: Use Docker secrets for production
3. **Kubernetes Secrets**: Use sealed-secrets or external secret stores

### Database Security

1. **Strong Passwords**: Generate secure passwords for PostgreSQL
2. **Network Isolation**: Database should not be publicly accessible
3. **Backups**: Regular automated backups recommended

---

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs aipt-api

# Check health
docker-compose ps

# Restart services
docker-compose restart
```

### Database Connection Failed

```bash
# Check if PostgreSQL is running
docker-compose logs aipt-db

# Verify connection string
echo $DATABASE_URL

# Test connection manually
docker exec -it aipt-db psql -U aipt -d aipt -c "SELECT 1;"
```

### LLM API Errors

```bash
# Verify API key is set
echo $ANTHROPIC_API_KEY

# Check health endpoint for LLM status
curl http://localhost:8000/health/ready | jq '.checks.llm_api'
```

### Memory Issues

```bash
# Check memory usage
docker stats

# Increase memory limits in docker-compose.yml
# deploy:
#   resources:
#     limits:
#       memory: 4G
```

### Port Already in Use

```bash
# Find what's using port 8000
lsof -i :8000

# Use different port
AIPT_API_PORT=8001 docker-compose up -d
```

---

## Support

- **Issues**: https://github.com/yourusername/aipt-v2/issues
- **Documentation**: https://aipt.readthedocs.io
- **Email**: support@aipt.example.com

---

## License

AIPT v2 is released under the MIT License. See [LICENSE](LICENSE) for details.
