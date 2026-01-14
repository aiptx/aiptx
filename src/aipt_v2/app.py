"""
AIPT REST API - FastAPI application
Provides REST endpoints for AIPT operations.

Endpoints:
- /projects - Project management
- /sessions - Session management
- /findings - Finding management
- /scan - Run scans
- /tools - List available tools
- /auth - Authentication endpoints

Security:
- JWT-based authentication (optional but recommended)
- CORS restricted to configured origins
- Rate limiting per client IP
- Input validation on all endpoints
"""

import os
import re
import secrets
from pathlib import Path
from typing import Optional, List
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# JWT imports with fallback
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

# Import AIPT v2 components
from aipt_v2.database.repository import Repository
from aipt_v2.intelligence import ToolRAG, CVEIntelligence
from aipt_v2.tools.tool_processing import process_tool_invocations
from aipt_v2.utils.logging import logger
from .health import health_router, record_scan, record_tool_invocation

# Rate limiter instance
limiter = Limiter(key_func=get_remote_address)

# Security constants
ALLOWED_SCAN_PROTOCOLS = {"http", "https"}
MAX_TARGET_LENGTH = 2048
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ============== Pydantic Models ==============

class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Project name")
    target: str = Field(..., min_length=1, max_length=MAX_TARGET_LENGTH, description="Target URL or domain")
    description: Optional[str] = Field(None, max_length=2000, description="Project description")
    scope: Optional[List[str]] = Field(None, max_length=100, description="In-scope domains/IPs")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Validate target is a valid URL or domain."""
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")

        # If it looks like a URL, validate it
        if v.startswith(("http://", "https://")):
            parsed = urlparse(v)
            if parsed.scheme not in ALLOWED_SCAN_PROTOCOLS:
                raise ValueError(f"Protocol must be http or https, got: {parsed.scheme}")
            if not parsed.netloc:
                raise ValueError("Invalid URL: missing hostname")
        else:
            # Validate as domain - basic check for dangerous characters
            if any(c in v for c in [";", "&", "|", "$", "`", "\n", "\r"]):
                raise ValueError("Target contains invalid characters")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate project name."""
        v = v.strip()
        if not v:
            raise ValueError("Name cannot be empty")
        # Prevent path traversal in name
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError("Name contains invalid characters")
        return v


class ProjectResponse(BaseModel):
    id: int
    name: str
    target: str
    description: Optional[str]
    scope: List[str]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class SessionCreate(BaseModel):
    name: Optional[str] = None
    phase: str = "recon"
    max_iterations: int = 100


class SessionResponse(BaseModel):
    id: int
    project_id: int
    name: Optional[str]
    phase: str
    status: str
    iteration: int
    started_at: datetime

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: int
    type: str
    value: str
    description: Optional[str]
    severity: str
    phase: Optional[str]
    tool: Optional[str]
    verified: bool
    discovered_at: datetime

    class Config:
        from_attributes = True


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=MAX_TARGET_LENGTH, description="Target URL or domain")
    tools: Optional[List[str]] = Field(None, max_length=20, description="Tools to run")
    phase: str = Field(default="recon", description="Scan phase")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Validate and sanitize target."""
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")

        # Validate URL format
        if v.startswith(("http://", "https://")):
            parsed = urlparse(v)
            if parsed.scheme not in ALLOWED_SCAN_PROTOCOLS:
                raise ValueError(f"Protocol must be http or https")
            if not parsed.netloc:
                raise ValueError("Invalid URL: missing hostname")
        else:
            # Check for command injection characters
            dangerous_chars = [";", "&", "|", "$", "`", "\n", "\r", "'", '"', "(", ")", "{", "}", "<", ">"]
            if any(c in v for c in dangerous_chars):
                raise ValueError("Target contains invalid characters")
        return v

    @field_validator("phase")
    @classmethod
    def validate_phase(cls, v: str) -> str:
        """Validate phase is allowed."""
        allowed_phases = {"recon", "scan", "exploit", "report"}
        v = v.lower().strip()
        if v not in allowed_phases:
            raise ValueError(f"Phase must be one of: {', '.join(allowed_phases)}")
        return v

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate tool names."""
        if v is None:
            return v
        # Sanitize tool names - only allow alphanumeric and underscore/hyphen
        clean_tools = []
        for tool in v:
            tool = tool.strip().lower()
            if not re.match(r"^[a-z0-9_-]+$", tool):
                raise ValueError(f"Invalid tool name: {tool}")
            clean_tools.append(tool)
        return clean_tools


class ScanResponse(BaseModel):
    status: str
    message: str
    findings: List[dict] = []


class ToolInfo(BaseModel):
    name: str
    description: str
    phase: str
    keywords: List[str]


class CVERequest(BaseModel):
    cve_id: str = Field(..., min_length=9, max_length=20, description="CVE identifier")

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, v: str) -> str:
        """Validate CVE ID format."""
        v = v.strip().upper()
        if not CVE_PATTERN.match(v):
            raise ValueError("Invalid CVE ID format. Expected: CVE-YYYY-NNNNN")
        return v


class CVEResponse(BaseModel):
    cve_id: str
    cvss: float
    epss: float
    priority_score: float
    has_poc: bool
    description: str


# ============== Authentication Models ==============

class TokenRequest(BaseModel):
    """Request model for token generation."""
    api_key: str = Field(..., min_length=32, max_length=128, description="API key")


class TokenResponse(BaseModel):
    """Response model for token generation."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserInfo(BaseModel):
    """User information extracted from JWT."""
    sub: str  # Subject (user identifier)
    exp: datetime
    iat: datetime
    is_authenticated: bool = True


# ============== JWT Security ==============

# Security scheme for OpenAPI docs
security_scheme = HTTPBearer(auto_error=False)


class JWTAuth:
    """
    JWT Authentication handler.

    Security features:
    - HS256 algorithm with secure secret
    - Token expiration (default 24h)
    - API key validation before token issuance
    """

    def __init__(self, secret_key: Optional[str] = None, expires_hours: int = 24):
        """
        Initialize JWT auth handler.

        Args:
            secret_key: Secret for signing tokens. If not provided, uses
                       AIPT_JWT_SECRET env var or generates a random one.
            expires_hours: Token expiration time in hours.
        """
        self.secret_key = secret_key or os.getenv("AIPT_JWT_SECRET")
        if not self.secret_key:
            # Generate a secure random secret if not configured
            # Note: This means tokens won't survive server restarts
            self.secret_key = secrets.token_urlsafe(32)
            logger.warning(
                "JWT secret not configured (AIPT_JWT_SECRET). "
                "Using random secret - tokens will be invalid after restart."
            )
        self.expires_hours = expires_hours
        self.algorithm = "HS256"

        # Valid API keys - in production, load from secure storage
        self._valid_api_keys = set()
        env_keys = os.getenv("AIPT_API_KEYS", "")
        if env_keys:
            self._valid_api_keys = {k.strip() for k in env_keys.split(",") if k.strip()}

    def validate_api_key(self, api_key: str) -> bool:
        """Validate an API key."""
        if not self._valid_api_keys:
            # If no keys configured, accept any non-empty key (dev mode)
            logger.warning("No API keys configured (AIPT_API_KEYS). Accepting any key.")
            return bool(api_key and len(api_key) >= 32)
        return api_key in self._valid_api_keys

    def create_token(self, subject: str) -> tuple[str, int]:
        """
        Create a new JWT token.

        Args:
            subject: User/client identifier

        Returns:
            Tuple of (token, expires_in_seconds)
        """
        if not JWT_AVAILABLE:
            raise HTTPException(
                status_code=503,
                detail="JWT support not available. Install PyJWT: pip install PyJWT"
            )

        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=self.expires_hours)

        payload = {
            "sub": subject,
            "iat": now,
            "exp": expires,
            "iss": "aipt-api",
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        expires_in = int((expires - now).total_seconds())

        return token, expires_in

    def verify_token(self, token: str) -> Optional[UserInfo]:
        """
        Verify and decode a JWT token.

        Args:
            token: JWT token string

        Returns:
            UserInfo if valid, None otherwise
        """
        if not JWT_AVAILABLE:
            return None

        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"require": ["exp", "iat", "sub"]}
            )
            return UserInfo(
                sub=payload["sub"],
                exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
                iat=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
            )
        except jwt.ExpiredSignatureError:
            logger.debug("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.debug(f"Invalid token: {e}")
            return None


# Global JWT auth instance
jwt_auth: Optional[JWTAuth] = None


# ============== Security Headers Middleware ==============

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.

    Implements OWASP recommended security headers:
    - X-Content-Type-Options: Prevents MIME type sniffing
    - X-Frame-Options: Prevents clickjacking
    - X-XSS-Protection: Legacy XSS protection
    - Strict-Transport-Security: Enforces HTTPS
    - Content-Security-Policy: Restricts resource loading
    - Referrer-Policy: Controls referrer information
    - Permissions-Policy: Restricts browser features
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # HSTS - Only enable if using HTTPS in production
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # CSP - Restrictive policy for API responses
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'; "
            "form-action 'none'"
        )

        return response


# ============== WAF Middleware ==============

class WAFMiddleware(BaseHTTPMiddleware):
    """
    Simple Web Application Firewall middleware.

    Provides basic protection against common attacks:
    - SQL Injection patterns
    - XSS patterns
    - Path traversal attempts
    - Command injection patterns
    """

    # Suspicious patterns that may indicate attacks
    SUSPICIOUS_PATTERNS = [
        # SQL Injection
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(FROM|INTO|TABLE|DATABASE)\b)",
        r"(--|#|/\*|\*/|;)",
        r"(\bOR\b\s+\d+\s*=\s*\d+)",
        # XSS
        r"(<script|javascript:|on\w+\s*=)",
        # Path traversal
        r"(\.\./|\.\.\\|%2e%2e)",
        # Command injection
        r"(;|\||&&|\$\(|`)",
    ]

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
        self._patterns = None

    @property
    def patterns(self):
        if self._patterns is None:
            self._patterns = [
                re.compile(p, re.IGNORECASE)
                for p in self.SUSPICIOUS_PATTERNS
            ]
        return self._patterns

    def _is_suspicious(self, value: str) -> bool:
        """Check if a value contains suspicious patterns."""
        if not value:
            return False
        for pattern in self.patterns:
            if pattern.search(value):
                return True
        return False

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self.enabled:
            return await call_next(request)

        # Check query parameters
        for key, value in request.query_params.items():
            if self._is_suspicious(key) or self._is_suspicious(value):
                logger.warning(
                    "WAF blocked suspicious request",
                    path=request.url.path,
                    param=key,
                    client=request.client.host if request.client else "unknown",
                )
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Request blocked by security policy"}
                )

        # Check path
        if self._is_suspicious(request.url.path):
            logger.warning(
                "WAF blocked suspicious path",
                path=request.url.path,
                client=request.client.host if request.client else "unknown",
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Request blocked by security policy"}
            )

        return await call_next(request)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)
) -> Optional[UserInfo]:
    """
    Dependency to get current authenticated user.

    Returns UserInfo if authenticated, None otherwise.
    Authentication is optional - endpoints can work without auth.
    """
    if not credentials or not jwt_auth:
        return None

    return jwt_auth.verify_token(credentials.credentials)


async def require_auth(
    user: Optional[UserInfo] = Depends(get_current_user)
) -> UserInfo:
    """
    Dependency to require authentication.

    Raises HTTPException 401 if not authenticated.
    """
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# ============== FastAPI App ==============

# Default CORS origins - restricted for security
DEFAULT_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8080",
]


def create_app(
    db_url: str = "sqlite:///~/.aipt/aipt.db",
    title: str = "AIPT API",
    cors_origins: Optional[List[str]] = None,
    rate_limit: str = "100/minute",
) -> FastAPI:
    """
    Create FastAPI application with security middleware.

    Args:
        db_url: Database connection URL
        title: API title
        cors_origins: Allowed CORS origins (defaults to localhost only)
        rate_limit: Rate limit string (e.g., "100/minute")
    """
    # Get CORS origins from env or use defaults
    if cors_origins is None:
        env_origins = os.getenv("AIPT_CORS_ORIGINS", "")
        if env_origins:
            cors_origins = [o.strip() for o in env_origins.split(",") if o.strip()]
        else:
            cors_origins = DEFAULT_CORS_ORIGINS

    app = FastAPI(
        title=title,
        description="AI-Powered Penetration Testing Framework API",
        version="0.2.0",
    )

    # Rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # CORS - Restricted to configured origins only
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
        expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
    )

    # Security Headers Middleware - OWASP recommended headers
    app.add_middleware(SecurityHeadersMiddleware)

    # WAF Middleware - Basic attack protection
    # Can be disabled via AIPT_WAF_ENABLED=false for testing
    waf_enabled = os.getenv("AIPT_WAF_ENABLED", "true").lower() == "true"
    app.add_middleware(WAFMiddleware, enabled=waf_enabled)

    # Log security configuration
    logger.info(
        f"API security configured: cors_origins={cors_origins}, "
        f"rate_limit={rate_limit}, waf_enabled={waf_enabled}, security_headers=enabled"
    )

    # Initialize components
    repo = Repository(db_url)
    tools_path = Path(__file__).parent / "intelligence" / "tools.json"
    tools_rag = ToolRAG(tools_path=str(tools_path), lazy_load=True)
    cve_intel = CVEIntelligence()

    # Initialize JWT authentication
    global jwt_auth
    jwt_auth = JWTAuth()
    app.state.jwt_auth = jwt_auth

    # Store in app state
    app.state.repo = repo
    app.state.tools_rag = tools_rag
    app.state.cve_intel = cve_intel
    app.state.rate_limit = rate_limit

    # ============== Authentication ==============

    @app.post("/auth/token", response_model=TokenResponse, tags=["Authentication"])
    @limiter.limit("10/minute")  # Strict rate limit on token requests
    async def get_token(request: Request, token_request: TokenRequest):
        """
        Get JWT access token using API key.

        Security:
        - Rate limited to 10 requests per minute
        - API key must be at least 32 characters
        - Token expires in 24 hours

        Usage:
        1. Set AIPT_API_KEYS env var with comma-separated valid API keys
        2. POST to /auth/token with your API key
        3. Use returned token in Authorization header: Bearer <token>
        """
        if not jwt_auth.validate_api_key(token_request.api_key):
            raise HTTPException(
                status_code=401,
                detail="Invalid API key"
            )

        # Create token with API key hash as subject (don't expose full key)
        import hashlib
        subject = hashlib.sha256(token_request.api_key.encode()).hexdigest()[:16]
        token, expires_in = jwt_auth.create_token(subject)

        return TokenResponse(
            access_token=token,
            expires_in=expires_in
        )

    @app.get("/auth/me", tags=["Authentication"])
    async def get_current_user_info(user: UserInfo = Depends(require_auth)):
        """
        Get current authenticated user information.

        Requires valid JWT token in Authorization header.
        """
        return {
            "sub": user.sub,
            "authenticated": True,
            "expires": user.exp.isoformat(),
        }

    @app.get("/auth/status", tags=["Authentication"])
    async def auth_status(user: Optional[UserInfo] = Depends(get_current_user)):
        """
        Check authentication status.

        Returns whether JWT auth is available and if current request is authenticated.
        """
        return {
            "jwt_available": JWT_AVAILABLE,
            "authenticated": user is not None,
            "user": user.sub if user else None,
        }

    # ============== Health & Metrics ==============
    # Include comprehensive health check router with:
    # - /health - Basic liveness probe
    # - /health/live - Kubernetes liveness probe
    # - /health/ready - Readiness probe with dependency checks
    # - /metrics - Prometheus-compatible metrics
    # - /health/info - Service information
    app.include_router(health_router)

    # ============== Projects ==============

    @app.post("/projects", response_model=ProjectResponse)
    async def create_project(project: ProjectCreate):
        """Create a new project"""
        db_project = repo.create_project(
            name=project.name,
            target=project.target,
            description=project.description,
            scope=project.scope,
        )
        return db_project

    @app.get("/projects", response_model=List[ProjectResponse])
    async def list_projects(status: Optional[str] = None):
        """List all projects"""
        return repo.list_projects(status=status)

    @app.get("/projects/{project_id}", response_model=ProjectResponse)
    async def get_project(project_id: int):
        """Get project by ID"""
        project = repo.get_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        return project

    @app.delete("/projects/{project_id}")
    async def delete_project(project_id: int):
        """Delete a project"""
        if not repo.delete_project(project_id):
            raise HTTPException(status_code=404, detail="Project not found")
        return {"status": "deleted"}

    # ============== Sessions ==============

    @app.post("/projects/{project_id}/sessions", response_model=SessionResponse)
    async def create_session(project_id: int, session: SessionCreate):
        """Create a new session"""
        project = repo.get_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        from aipt_v2.database.models import PhaseType
        db_session = repo.create_session(
            project_id=project_id,
            name=session.name,
            phase=PhaseType(session.phase),
            max_iterations=session.max_iterations,
        )
        return db_session

    @app.get("/projects/{project_id}/sessions", response_model=List[SessionResponse])
    async def list_sessions(project_id: int):
        """List all sessions for a project"""
        return repo.list_sessions(project_id)

    # ============== Findings ==============

    @app.get("/projects/{project_id}/findings", response_model=List[FindingResponse])
    async def get_findings(
        project_id: int,
        type: Optional[str] = None,
        severity: Optional[str] = None,
        phase: Optional[str] = None,
    ):
        """Get findings for a project"""
        return repo.get_findings(
            project_id=project_id,
            type=type,
            severity=severity,
            phase=phase,
        )

    @app.get("/projects/{project_id}/findings/summary")
    async def get_findings_summary(project_id: int):
        """Get findings summary"""
        return repo.get_findings_summary(project_id)

    @app.post("/findings/{finding_id}/verify")
    async def verify_finding(finding_id: int, notes: Optional[str] = None):
        """Mark finding as verified"""
        repo.verify_finding(finding_id, verified=True, notes=notes)
        return {"status": "verified"}

    @app.post("/findings/{finding_id}/false-positive")
    async def mark_false_positive(finding_id: int, notes: Optional[str] = None):
        """Mark finding as false positive"""
        repo.mark_false_positive(finding_id, notes=notes)
        return {"status": "marked as false positive"}

    # ============== Scanning ==============

    @app.post("/scan/quick", response_model=ScanResponse)
    @limiter.limit("10/minute")  # Limit scan requests
    async def quick_scan(request: Request, scan_request: ScanRequest):
        """Run a quick scan on target (rate limited: 10/minute)"""
        import asyncio
        import shutil
        from aipt_v2.tools.parser import OutputParser

        findings = []

        # Check if nmap is available
        nmap_path = shutil.which("nmap")
        if nmap_path:
            try:
                proc = await asyncio.create_subprocess_shell(
                    f"nmap -F {scan_request.target}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
                output = stdout.decode() if stdout else ""

                if proc.returncode == 0:
                    parser = OutputParser()
                    parsed = parser.parse(output, "nmap")
                    findings.extend([{
                        "type": f.type,
                        "value": f.value,
                        "description": f.description,
                        "severity": f.severity,
                    } for f in parsed])
            except asyncio.TimeoutError:
                logger.warning("Tool execution timed out", tool="nmap", target=scan_request.target)
            except Exception as e:
                logger.error("Tool execution failed", tool="nmap", error=str(e))

        return ScanResponse(
            status="completed",
            message=f"Quick scan completed on {scan_request.target}",
            findings=findings,
        )

    @app.post("/scan/tool")
    @limiter.limit("5/minute")  # Stricter limit for tool execution
    async def run_tool(request: Request, tool_name: str, target: str, options: Optional[str] = None):
        """Run a specific tool (rate limited: 5/minute)"""
        import asyncio
        import time

        # Validate tool_name - only alphanumeric and underscore/hyphen
        if not re.match(r"^[a-zA-Z0-9_-]+$", tool_name):
            raise HTTPException(status_code=400, detail="Invalid tool name")

        # Validate target - check for command injection
        dangerous_chars = [";", "&", "|", "$", "`", "\n", "\r", "'", '"']
        if any(c in target for c in dangerous_chars):
            raise HTTPException(status_code=400, detail="Invalid target: contains dangerous characters")

        # Validate options if provided
        if options:
            if any(c in options for c in [";", "&", "|", "$", "`"]):
                raise HTTPException(status_code=400, detail="Invalid options: contains dangerous characters")

        # Get tool from RAG
        tool = tools_rag.get_tool_by_name(tool_name)
        if not tool:
            raise HTTPException(status_code=404, detail=f"Tool {tool_name} not found")

        # Build command
        cmd = tool.get("cmd", "").replace("{target}", target)
        if options:
            cmd = f"{cmd} {options}"

        # Execute
        start_time = time.time()
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            output = (stdout.decode() if stdout else "") + (stderr.decode() if stderr else "")
            return_code = proc.returncode
        except asyncio.TimeoutError:
            output = "Command timed out after 300 seconds"
            return_code = -1
        except Exception as e:
            output = f"Command failed: {str(e)}"
            return_code = -1

        duration = time.time() - start_time

        return {
            "tool": tool_name,
            "target": target,
            "command": cmd,
            "return_code": return_code,
            "output": output[:10000],  # Truncate
            "duration": duration,
        }

    # ============== Tools ==============

    @app.get("/tools", response_model=List[ToolInfo])
    async def list_tools(phase: Optional[str] = None):
        """List available tools"""
        tools = tools_rag.tools
        if phase:
            tools = [t for t in tools if t.get("phase") == phase]

        return [
            ToolInfo(
                name=t.get("name", ""),
                description=t.get("description", ""),
                phase=t.get("phase", ""),
                keywords=t.get("keywords", []),
            )
            for t in tools
        ]

    @app.get("/tools/{tool_name}")
    async def get_tool(tool_name: str):
        """Get tool details"""
        tool = tools_rag.get_tool_by_name(tool_name)
        if not tool:
            raise HTTPException(status_code=404, detail="Tool not found")
        return tool

    @app.get("/tools/search/{query}")
    async def search_tools(query: str, top_k: int = 5):
        """Search for tools by query"""
        results = tools_rag.search(query, top_k=top_k)
        return results

    # ============== CVE ==============

    @app.post("/cve/lookup", response_model=CVEResponse)
    async def lookup_cve(request: CVERequest):
        """Lookup CVE information"""
        info = cve_intel.lookup(request.cve_id)
        return CVEResponse(
            cve_id=info.cve_id,
            cvss=info.cvss,
            epss=info.epss,
            priority_score=info.priority_score,
            has_poc=info.has_poc,
            description=info.description[:500],
        )

    @app.post("/cve/prioritize")
    async def prioritize_cves(cve_ids: List[str]):
        """Prioritize CVEs by exploitability"""
        results = cve_intel.prioritize(cve_ids)
        return [
            {
                "cve_id": r.cve_id,
                "cvss": r.cvss,
                "epss": r.epss,
                "priority_score": r.priority_score,
                "has_poc": r.has_poc,
            }
            for r in results
        ]

    return app


# Default app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    # Security: Default to localhost to prevent accidental network exposure
    # Use --host 0.0.0.0 explicitly for production behind reverse proxy
    uvicorn.run(app, host="127.0.0.1", port=8000)
