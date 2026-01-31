"""
AIPTX Evidence Collector - Proof of Exploitation

Captures evidence during PoC validation:
- HTTP request/response pairs
- Screenshots (for visual vulnerabilities)
- Extracted data samples
- Timing measurements
- Error messages and stack traces
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class EvidenceType(str, Enum):
    """Types of evidence that can be collected."""
    HTTP_EXCHANGE = "http_exchange"      # Request/response pair
    SCREENSHOT = "screenshot"             # Visual proof
    DATA_EXTRACTION = "data_extraction"   # Extracted sensitive data
    TIMING = "timing"                     # Time-based evidence
    ERROR_MESSAGE = "error_message"       # Error/stack trace
    CALLBACK = "callback"                 # Out-of-band callback
    FILE_CONTENT = "file_content"         # Retrieved file content
    COMMAND_OUTPUT = "command_output"     # RCE command output


@dataclass
class HTTPExchange:
    """HTTP request/response pair as evidence."""
    request_method: str
    request_url: str
    request_headers: dict = field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: Optional[str] = None
    response_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

    def to_curl(self) -> str:
        """Generate curl command for reproduction."""
        cmd = f"curl -X {self.request_method}"

        for key, value in self.request_headers.items():
            # Skip some headers that curl adds automatically
            if key.lower() not in ["host", "content-length", "accept-encoding"]:
                cmd += f" -H '{key}: {value}'"

        if self.request_body:
            # Escape single quotes in body
            escaped_body = self.request_body.replace("'", "'\\''")
            cmd += f" -d '{escaped_body}'"

        cmd += f" '{self.request_url}'"
        return cmd

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "request": {
                "method": self.request_method,
                "url": self.request_url,
                "headers": self.request_headers,
                "body": self.request_body,
            },
            "response": {
                "status": self.response_status,
                "headers": self.response_headers,
                "body": self.response_body[:5000] if self.response_body else None,
            },
            "timing_ms": self.response_time_ms,
            "timestamp": self.timestamp.isoformat(),
            "curl": self.to_curl(),
        }


@dataclass
class Screenshot:
    """Screenshot evidence."""
    data: bytes                           # PNG image data
    filename: str = ""
    description: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    width: int = 0
    height: int = 0

    def save(self, path: str) -> str:
        """Save screenshot to file."""
        with open(path, "wb") as f:
            f.write(self.data)
        return path

    def to_base64(self) -> str:
        """Convert to base64 for embedding."""
        return base64.b64encode(self.data).decode("utf-8")

    def to_data_uri(self) -> str:
        """Convert to data URI for HTML embedding."""
        return f"data:image/png;base64,{self.to_base64()}"


@dataclass
class Evidence:
    """
    Evidence of successful exploitation.

    Captures all proof needed to demonstrate a vulnerability
    is real and exploitable.
    """
    id: str = ""
    evidence_type: EvidenceType = EvidenceType.HTTP_EXCHANGE
    description: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    # Different evidence types
    http_exchange: Optional[HTTPExchange] = None
    screenshot: Optional[Screenshot] = None
    extracted_data: Optional[str] = None
    timing_ms: Optional[float] = None
    error_message: Optional[str] = None
    callback_received: bool = False
    callback_data: Optional[dict] = None
    file_content: Optional[str] = None
    command_output: Optional[str] = None

    # Metadata
    finding_id: str = ""
    validator_notes: str = ""
    confidence: float = 0.0
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            # Generate unique ID
            content = f"{self.evidence_type.value}:{self.timestamp.isoformat()}"
            self.id = hashlib.sha256(content.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        result = {
            "id": self.id,
            "type": self.evidence_type.value,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "confidence": self.confidence,
            "validator_notes": self.validator_notes,
        }

        if self.http_exchange:
            result["http_exchange"] = self.http_exchange.to_dict()
        if self.screenshot:
            result["screenshot"] = {
                "filename": self.screenshot.filename,
                "description": self.screenshot.description,
                "data_uri": self.screenshot.to_data_uri()[:100] + "...",  # Truncate for JSON
            }
        if self.extracted_data:
            result["extracted_data"] = self.extracted_data[:1000]
        if self.timing_ms:
            result["timing_ms"] = self.timing_ms
        if self.error_message:
            result["error_message"] = self.error_message[:500]
        if self.callback_received:
            result["callback"] = {
                "received": True,
                "data": self.callback_data,
            }
        if self.file_content:
            result["file_content"] = self.file_content[:1000]
        if self.command_output:
            result["command_output"] = self.command_output[:1000]

        return result


class EvidenceCollector:
    """
    Collects and manages evidence during PoC validation.

    Provides methods to capture different types of evidence
    and generates comprehensive proof packages.

    Usage:
        collector = EvidenceCollector(finding_id="abc123")

        # Capture HTTP exchange
        evidence = await collector.capture_http(
            request=request,
            response=response
        )

        # Take screenshot
        evidence = await collector.capture_screenshot(page)

        # Get all evidence
        all_evidence = collector.get_evidence()
    """

    def __init__(
        self,
        finding_id: str,
        output_dir: Optional[str] = None,
    ):
        """
        Initialize evidence collector.

        Args:
            finding_id: ID of the finding being validated
            output_dir: Directory to store evidence files
        """
        self.finding_id = finding_id
        self.output_dir = output_dir or tempfile.mkdtemp(prefix="aiptx_evidence_")
        self._evidence: list[Evidence] = []
        self._callback_server: Optional[CallbackServer] = None

        # Ensure output directory exists
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    async def capture_http(
        self,
        method: str,
        url: str,
        request_headers: dict,
        request_body: Optional[str],
        response_status: int,
        response_headers: dict,
        response_body: str,
        response_time_ms: float,
        description: str = "",
    ) -> Evidence:
        """
        Capture an HTTP request/response exchange.

        Args:
            method: HTTP method
            url: Request URL
            request_headers: Request headers
            request_body: Request body
            response_status: Response status code
            response_headers: Response headers
            response_body: Response body
            response_time_ms: Response time in milliseconds
            description: Description of why this is evidence

        Returns:
            Evidence object
        """
        http_exchange = HTTPExchange(
            request_method=method,
            request_url=url,
            request_headers=request_headers,
            request_body=request_body,
            response_status=response_status,
            response_headers=dict(response_headers),
            response_body=response_body[:10000] if response_body else None,
            response_time_ms=response_time_ms,
        )

        evidence = Evidence(
            evidence_type=EvidenceType.HTTP_EXCHANGE,
            description=description or "HTTP exchange showing vulnerability",
            http_exchange=http_exchange,
            finding_id=self.finding_id,
        )

        self._evidence.append(evidence)
        logger.debug(f"Captured HTTP evidence: {method} {url} -> {response_status}")

        return evidence

    async def capture_http_from_response(
        self,
        response: Any,
        request_body: Optional[str] = None,
        description: str = "",
    ) -> Evidence:
        """
        Capture HTTP evidence from an aiohttp response.

        Args:
            response: aiohttp ClientResponse
            request_body: Original request body
            description: Evidence description

        Returns:
            Evidence object
        """
        import time

        start_time = time.time()
        body = await response.text()
        response_time = (time.time() - start_time) * 1000

        return await self.capture_http(
            method=response.method,
            url=str(response.url),
            request_headers=dict(response.request_info.headers),
            request_body=request_body,
            response_status=response.status,
            response_headers=dict(response.headers),
            response_body=body,
            response_time_ms=response_time,
            description=description,
        )

    async def capture_screenshot(
        self,
        page: Any,
        description: str = "",
        full_page: bool = False,
    ) -> Evidence:
        """
        Capture a screenshot using Playwright.

        Args:
            page: Playwright page object
            description: Description of what the screenshot shows
            full_page: Capture full page or just viewport

        Returns:
            Evidence object
        """
        try:
            # Take screenshot
            screenshot_data = await page.screenshot(full_page=full_page)

            # Get viewport size
            viewport = page.viewport_size or {"width": 0, "height": 0}

            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{self.finding_id}_{timestamp}.png"
            filepath = os.path.join(self.output_dir, filename)

            screenshot = Screenshot(
                data=screenshot_data,
                filename=filename,
                description=description,
                width=viewport["width"],
                height=viewport["height"],
            )

            # Save to file
            screenshot.save(filepath)

            evidence = Evidence(
                evidence_type=EvidenceType.SCREENSHOT,
                description=description or "Screenshot showing vulnerability",
                screenshot=screenshot,
                finding_id=self.finding_id,
            )

            self._evidence.append(evidence)
            logger.debug(f"Captured screenshot: {filename}")

            return evidence

        except Exception as e:
            logger.warning(f"Failed to capture screenshot: {e}")
            raise

    async def capture_data_extraction(
        self,
        data: str,
        description: str = "",
        data_type: str = "unknown",
    ) -> Evidence:
        """
        Capture extracted sensitive data as evidence.

        Args:
            data: Extracted data (will be partially redacted)
            description: Description of what was extracted
            data_type: Type of data (credentials, pii, etc.)

        Returns:
            Evidence object
        """
        # Redact potentially sensitive data for storage
        redacted_data = self._redact_sensitive(data)

        evidence = Evidence(
            evidence_type=EvidenceType.DATA_EXTRACTION,
            description=description or f"Extracted {data_type} data",
            extracted_data=redacted_data,
            finding_id=self.finding_id,
            confidence=0.9,  # High confidence if we extracted data
            metadata={"data_type": data_type, "original_length": len(data)},
        )

        self._evidence.append(evidence)
        logger.debug(f"Captured data extraction: {data_type}, {len(data)} bytes")

        return evidence

    async def capture_timing(
        self,
        baseline_ms: float,
        delayed_ms: float,
        expected_delay_ms: float,
        description: str = "",
    ) -> Evidence:
        """
        Capture timing-based evidence (e.g., for blind SQLi).

        Args:
            baseline_ms: Baseline response time
            delayed_ms: Delayed response time (with payload)
            expected_delay_ms: Expected delay from payload
            description: Description

        Returns:
            Evidence object
        """
        actual_delay = delayed_ms - baseline_ms
        confidence = min(1.0, actual_delay / expected_delay_ms) if expected_delay_ms > 0 else 0

        evidence = Evidence(
            evidence_type=EvidenceType.TIMING,
            description=description or f"Time-based detection: {actual_delay:.0f}ms delay",
            timing_ms=actual_delay,
            finding_id=self.finding_id,
            confidence=confidence,
            metadata={
                "baseline_ms": baseline_ms,
                "delayed_ms": delayed_ms,
                "expected_delay_ms": expected_delay_ms,
            },
        )

        self._evidence.append(evidence)
        logger.debug(f"Captured timing evidence: {actual_delay:.0f}ms delay")

        return evidence

    async def capture_error(
        self,
        error_message: str,
        description: str = "",
    ) -> Evidence:
        """
        Capture error message as evidence.

        Args:
            error_message: Error message or stack trace
            description: Description

        Returns:
            Evidence object
        """
        evidence = Evidence(
            evidence_type=EvidenceType.ERROR_MESSAGE,
            description=description or "Error message revealing vulnerability",
            error_message=error_message[:2000],
            finding_id=self.finding_id,
        )

        self._evidence.append(evidence)
        logger.debug(f"Captured error evidence: {len(error_message)} chars")

        return evidence

    async def capture_callback(
        self,
        callback_id: str,
        callback_data: dict,
        description: str = "",
    ) -> Evidence:
        """
        Capture out-of-band callback as evidence (SSRF, XXE, etc.).

        Args:
            callback_id: Unique callback identifier
            callback_data: Data received in callback
            description: Description

        Returns:
            Evidence object
        """
        evidence = Evidence(
            evidence_type=EvidenceType.CALLBACK,
            description=description or "Out-of-band callback received",
            callback_received=True,
            callback_data=callback_data,
            finding_id=self.finding_id,
            confidence=0.95,  # High confidence if callback received
            metadata={"callback_id": callback_id},
        )

        self._evidence.append(evidence)
        logger.debug(f"Captured callback evidence: {callback_id}")

        return evidence

    async def capture_file_content(
        self,
        content: str,
        filename: str,
        description: str = "",
    ) -> Evidence:
        """
        Capture file content as evidence (LFI, path traversal).

        Args:
            content: File content
            filename: Name of file read
            description: Description

        Returns:
            Evidence object
        """
        evidence = Evidence(
            evidence_type=EvidenceType.FILE_CONTENT,
            description=description or f"File content from {filename}",
            file_content=content[:5000],
            finding_id=self.finding_id,
            confidence=0.9,
            metadata={"filename": filename, "content_length": len(content)},
        )

        self._evidence.append(evidence)
        logger.debug(f"Captured file content: {filename}")

        return evidence

    async def capture_command_output(
        self,
        output: str,
        command: str,
        description: str = "",
    ) -> Evidence:
        """
        Capture command output as evidence (RCE).

        Args:
            output: Command output
            command: Command that was executed
            description: Description

        Returns:
            Evidence object
        """
        evidence = Evidence(
            evidence_type=EvidenceType.COMMAND_OUTPUT,
            description=description or f"Command output from: {command}",
            command_output=output[:5000],
            finding_id=self.finding_id,
            confidence=0.95,  # High confidence if we got command output
            metadata={"command": command},
        )

        self._evidence.append(evidence)
        logger.debug(f"Captured command output: {command}")

        return evidence

    def _redact_sensitive(self, data: str, show_chars: int = 4) -> str:
        """Partially redact sensitive data for storage."""
        if len(data) <= show_chars * 2:
            return "*" * len(data)

        return data[:show_chars] + "*" * (len(data) - show_chars * 2) + data[-show_chars:]

    def get_evidence(self) -> list[Evidence]:
        """Get all collected evidence."""
        return self._evidence.copy()

    def get_strongest_evidence(self) -> Optional[Evidence]:
        """Get the evidence with highest confidence."""
        if not self._evidence:
            return None
        return max(self._evidence, key=lambda e: e.confidence)

    def get_total_confidence(self) -> float:
        """Calculate combined confidence from all evidence."""
        if not self._evidence:
            return 0.0

        # Use probabilistic combination
        # P(A or B) = P(A) + P(B) - P(A)*P(B)
        confidence = 0.0
        for evidence in self._evidence:
            confidence = confidence + evidence.confidence - (confidence * evidence.confidence)

        return min(1.0, confidence)

    def clear(self) -> None:
        """Clear all collected evidence."""
        self._evidence.clear()

    async def cleanup(self) -> None:
        """Cleanup temporary files."""
        import shutil

        if self.output_dir and os.path.exists(self.output_dir):
            try:
                shutil.rmtree(self.output_dir)
            except Exception as e:
                logger.warning(f"Failed to cleanup evidence directory: {e}")


class CallbackServer:
    """
    Simple callback server for out-of-band detection.

    Used for SSRF, XXE, and other OOB vulnerabilities.
    """

    def __init__(self, port: int = 8888):
        self.port = port
        self.callbacks: dict[str, dict] = {}
        self._server = None

    async def start(self) -> str:
        """Start the callback server and return the URL."""
        # Implementation would use aiohttp to create a simple server
        # For now, return a placeholder
        return f"http://callback.aiptx.io:{self.port}"

    async def wait_for_callback(
        self,
        callback_id: str,
        timeout: float = 30.0,
    ) -> Optional[dict]:
        """
        Wait for a callback with the given ID.

        Args:
            callback_id: Unique callback identifier
            timeout: Timeout in seconds

        Returns:
            Callback data if received, None if timeout
        """
        start_time = asyncio.get_event_loop().time()

        while asyncio.get_event_loop().time() - start_time < timeout:
            if callback_id in self.callbacks:
                return self.callbacks.pop(callback_id)
            await asyncio.sleep(0.5)

        return None

    async def stop(self) -> None:
        """Stop the callback server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
