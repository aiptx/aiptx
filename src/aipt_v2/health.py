"""
AIPT v2 Health Checks & Metrics Module
=======================================

Provides:
- /health - Basic liveness probe
- /health/live - Kubernetes liveness probe
- /health/ready - Kubernetes readiness probe (checks dependencies)
- /metrics - Prometheus-compatible metrics

Usage:
    from health import health_router
    app.include_router(health_router)
"""

import os
import time
import psutil
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from functools import lru_cache

from fastapi import APIRouter, Response
from pydantic import BaseModel


# =============================================================================
# Configuration
# =============================================================================

VERSION = os.getenv("AIPT_VERSION", "2.0.0")
ENVIRONMENT = os.getenv("AIPT_ENVIRONMENT", "development")
START_TIME = time.time()


# =============================================================================
# Pydantic Models
# =============================================================================

class HealthStatus(BaseModel):
    """Health check response model."""
    status: str
    version: str
    timestamp: str
    uptime_seconds: float
    environment: str


class ReadinessStatus(BaseModel):
    """Readiness check response model."""
    status: str
    version: str
    timestamp: str
    checks: Dict[str, Dict[str, Any]]


class ComponentCheck(BaseModel):
    """Individual component check result."""
    status: str
    latency_ms: Optional[float] = None
    message: Optional[str] = None


# =============================================================================
# Metrics Storage (Simple in-memory counters)
# =============================================================================

class MetricsCollector:
    """Simple metrics collector for Prometheus-style metrics."""

    def __init__(self):
        self.counters: Dict[str, int] = {}
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, list] = {}

        # Initialize default metrics
        self.counters["http_requests_total"] = 0
        self.counters["scan_requests_total"] = 0
        self.counters["tool_invocations_total"] = 0
        self.counters["errors_total"] = 0
        self.gauges["active_scans"] = 0
        self.gauges["active_sessions"] = 0

    def increment(self, name: str, value: int = 1, labels: Dict[str, str] = None):
        """Increment a counter."""
        key = self._make_key(name, labels)
        self.counters[key] = self.counters.get(key, 0) + value

    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge value."""
        key = self._make_key(name, labels)
        self.gauges[key] = value

    def observe(self, name: str, value: float, labels: Dict[str, str] = None):
        """Record a histogram observation."""
        key = self._make_key(name, labels)
        if key not in self.histograms:
            self.histograms[key] = []
        self.histograms[key].append(value)

    def _make_key(self, name: str, labels: Dict[str, str] = None) -> str:
        """Create a metric key with labels."""
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def to_prometheus(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = [
            "# HELP aipt_http_requests_total Total HTTP requests",
            "# TYPE aipt_http_requests_total counter",
        ]

        # Export counters
        for key, value in self.counters.items():
            lines.append(f"aipt_{key} {value}")

        lines.extend([
            "",
            "# HELP aipt_active_scans Number of active scans",
            "# TYPE aipt_active_scans gauge",
        ])

        # Export gauges
        for key, value in self.gauges.items():
            lines.append(f"aipt_{key} {value}")

        # Add process metrics
        try:
            process = psutil.Process()
            memory_info = process.memory_info()

            lines.extend([
                "",
                "# HELP process_resident_memory_bytes Resident memory size in bytes",
                "# TYPE process_resident_memory_bytes gauge",
                f"process_resident_memory_bytes {memory_info.rss}",
                "",
                "# HELP process_virtual_memory_bytes Virtual memory size in bytes",
                "# TYPE process_virtual_memory_bytes gauge",
                f"process_virtual_memory_bytes {memory_info.vms}",
                "",
                "# HELP process_cpu_percent CPU percent usage",
                "# TYPE process_cpu_percent gauge",
                f"process_cpu_percent {process.cpu_percent()}",
                "",
                "# HELP process_open_fds Number of open file descriptors",
                "# TYPE process_open_fds gauge",
                f"process_open_fds {process.num_fds() if hasattr(process, 'num_fds') else 0}",
            ])
        except Exception:
            pass  # Skip process metrics if unavailable

        # Add uptime
        lines.extend([
            "",
            "# HELP aipt_uptime_seconds Time since service started",
            "# TYPE aipt_uptime_seconds gauge",
            f"aipt_uptime_seconds {time.time() - START_TIME}",
        ])

        return "\n".join(lines) + "\n"


# Global metrics collector
metrics = MetricsCollector()


# =============================================================================
# Health Check Functions
# =============================================================================

def check_database() -> ComponentCheck:
    """Check database connectivity."""
    start = time.time()
    try:
        # Try to import and use the repository
        from database.repository import Repository
        repo = Repository()
        # Simple query to verify connection
        repo.list_projects(status=None)
        latency = (time.time() - start) * 1000
        return ComponentCheck(status="healthy", latency_ms=round(latency, 2))
    except Exception as e:
        latency = (time.time() - start) * 1000
        return ComponentCheck(
            status="unhealthy",
            latency_ms=round(latency, 2),
            message=str(e)[:100]
        )


def check_redis() -> ComponentCheck:
    """Check Redis connectivity (if configured)."""
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        return ComponentCheck(status="skipped", message="REDIS_URL not configured")

    start = time.time()
    try:
        import redis
        client = redis.from_url(redis_url)
        client.ping()
        latency = (time.time() - start) * 1000
        return ComponentCheck(status="healthy", latency_ms=round(latency, 2))
    except ImportError:
        return ComponentCheck(status="skipped", message="redis package not installed")
    except Exception as e:
        latency = (time.time() - start) * 1000
        return ComponentCheck(
            status="unhealthy",
            latency_ms=round(latency, 2),
            message=str(e)[:100]
        )


def check_llm_api() -> ComponentCheck:
    """Check LLM API key configuration."""
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    llm_key = os.getenv("LLM_API_KEY")

    if anthropic_key or openai_key or llm_key:
        return ComponentCheck(status="healthy", message="API key configured")
    return ComponentCheck(status="warning", message="No LLM API key configured")


def check_disk_space() -> ComponentCheck:
    """Check available disk space."""
    try:
        disk = psutil.disk_usage("/")
        free_percent = (disk.free / disk.total) * 100

        if free_percent < 5:
            return ComponentCheck(
                status="unhealthy",
                message=f"Low disk space: {free_percent:.1f}% free"
            )
        elif free_percent < 15:
            return ComponentCheck(
                status="warning",
                message=f"Disk space warning: {free_percent:.1f}% free"
            )
        return ComponentCheck(
            status="healthy",
            message=f"{free_percent:.1f}% free"
        )
    except Exception as e:
        return ComponentCheck(status="unknown", message=str(e)[:100])


def check_memory() -> ComponentCheck:
    """Check memory usage."""
    try:
        memory = psutil.virtual_memory()
        used_percent = memory.percent

        if used_percent > 95:
            return ComponentCheck(
                status="unhealthy",
                message=f"Critical memory usage: {used_percent:.1f}%"
            )
        elif used_percent > 85:
            return ComponentCheck(
                status="warning",
                message=f"High memory usage: {used_percent:.1f}%"
            )
        return ComponentCheck(
            status="healthy",
            message=f"{used_percent:.1f}% used"
        )
    except Exception as e:
        return ComponentCheck(status="unknown", message=str(e)[:100])


# =============================================================================
# Router
# =============================================================================

health_router = APIRouter(tags=["Health"])


@health_router.get("/health", response_model=HealthStatus)
async def health_check():
    """
    Basic health check endpoint (liveness probe).

    Returns HTTP 200 if the service is running.
    Use /health/ready for dependency checks.
    """
    metrics.increment("http_requests_total", labels={"endpoint": "health"})

    return HealthStatus(
        status="healthy",
        version=VERSION,
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        uptime_seconds=round(time.time() - START_TIME, 2),
        environment=ENVIRONMENT,
    )


@health_router.get("/health/live")
async def liveness_probe():
    """
    Kubernetes liveness probe.

    Returns HTTP 200 if the process is alive.
    Kubernetes will restart the pod if this fails.
    """
    return {"status": "alive"}


@health_router.get("/health/ready", response_model=ReadinessStatus)
async def readiness_probe():
    """
    Kubernetes readiness probe.

    Checks all dependencies and returns their status.
    Returns HTTP 503 if any critical dependency is unhealthy.
    """
    metrics.increment("http_requests_total", labels={"endpoint": "health_ready"})

    checks = {
        "database": check_database().model_dump(),
        "redis": check_redis().model_dump(),
        "llm_api": check_llm_api().model_dump(),
        "disk": check_disk_space().model_dump(),
        "memory": check_memory().model_dump(),
    }

    # Determine overall status
    statuses = [c["status"] for c in checks.values()]
    if "unhealthy" in statuses:
        overall_status = "unhealthy"
    elif "warning" in statuses:
        overall_status = "degraded"
    else:
        overall_status = "healthy"

    response = ReadinessStatus(
        status=overall_status,
        version=VERSION,
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        checks=checks,
    )

    # Return 503 if unhealthy
    if overall_status == "unhealthy":
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail=response.model_dump())

    return response


@health_router.get("/metrics")
async def prometheus_metrics():
    """
    Prometheus-compatible metrics endpoint.

    Returns metrics in Prometheus text exposition format.
    """
    content = metrics.to_prometheus()
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8"
    )


@health_router.get("/health/info")
async def service_info():
    """
    Detailed service information.

    Returns version, build info, and configuration summary.
    """
    return {
        "service": "aipt-v2",
        "version": VERSION,
        "environment": ENVIRONMENT,
        "python_version": os.popen("python --version 2>&1").read().strip(),
        "uptime_seconds": round(time.time() - START_TIME, 2),
        "config": {
            "log_level": os.getenv("AIPT_LOG_LEVEL", "INFO"),
            "cors_origins": os.getenv("AIPT_CORS_ORIGINS", "localhost"),
            "database_configured": bool(os.getenv("DATABASE_URL")),
            "redis_configured": bool(os.getenv("REDIS_URL")),
            "llm_configured": bool(
                os.getenv("ANTHROPIC_API_KEY") or
                os.getenv("OPENAI_API_KEY") or
                os.getenv("LLM_API_KEY")
            ),
        },
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
    }


# =============================================================================
# Utility Functions (for use in middleware)
# =============================================================================

def record_request(method: str, path: str, status_code: int, duration_ms: float):
    """Record an HTTP request for metrics."""
    metrics.increment("http_requests_total", labels={
        "method": method,
        "path": path,
        "status": str(status_code),
    })
    metrics.observe("http_request_duration_ms", duration_ms, labels={
        "method": method,
        "path": path,
    })


def record_scan(scan_type: str):
    """Record a scan request."""
    metrics.increment("scan_requests_total", labels={"type": scan_type})


def record_tool_invocation(tool_name: str):
    """Record a tool invocation."""
    metrics.increment("tool_invocations_total", labels={"tool": tool_name})


def record_error(error_type: str):
    """Record an error."""
    metrics.increment("errors_total", labels={"type": error_type})


def set_active_scans(count: int):
    """Set the number of active scans."""
    metrics.set_gauge("active_scans", count)


def set_active_sessions(count: int):
    """Set the number of active sessions."""
    metrics.set_gauge("active_sessions", count)
