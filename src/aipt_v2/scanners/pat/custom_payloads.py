"""
Custom Payload Loading for PAT Scanner

Load user-defined payloads from YAML/JSON files with variable templating.
Supports payload organization, tagging, and integration with PayloadDatabase.

Features:
- YAML and JSON payload file formats
- Variable templating with ${var_name} syntax
- Payload metadata (technique, severity, tags)
- Directory-based organization
- Hot reloading for development
- Validation and sanitization

Example YAML format:
```yaml
name: "My Custom SQLi Payloads"
version: "1.0"
author: "security-team"
vuln_type: sql_injection

variables:
  table_name: users
  column_name: password
  sleep_time: 5

payloads:
  - payload: "' OR 1=1--"
    technique: boolean_based
    description: "Simple OR bypass"

  - payload: "'; SELECT ${column_name} FROM ${table_name}--"
    technique: union_based
    description: "UNION select with variables"
    requires_encoding: true

  - payload: "'; WAITFOR DELAY '00:00:0${sleep_time}'--"
    technique: time_based
    description: "MSSQL time-based"
    tags: [mssql, blind]
```

Example JSON format:
```json
{
  "name": "Custom XSS Payloads",
  "vuln_type": "xss",
  "payloads": [
    {
      "payload": "<script>alert(1)</script>",
      "technique": "direct",
      "tags": ["basic"]
    }
  ]
}
```

Usage:
    from aipt_v2.scanners.pat.custom_payloads import CustomPayloadLoader

    loader = CustomPayloadLoader()

    # Load single file
    result = loader.load_file("my_payloads.yaml")
    print(f"Loaded {len(result.payloads)} payloads")

    # Load directory
    results = loader.load_directory("./custom_payloads/")

    # Load with variable overrides
    result = loader.load_file(
        "template.yaml",
        variables={"target_table": "admin_users"},
    )
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from string import Template
from typing import Iterator, Optional, Union

logger = logging.getLogger(__name__)

# Try to import yaml
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None

from .config import VulnerabilityType, PayloadTechnique
from .payload_parser import ParsedPayload


@dataclass
class CustomPayloadFile:
    """Parsed custom payload file."""
    name: str
    version: str
    vuln_type: VulnerabilityType
    variables: dict[str, str]
    payloads: list[ParsedPayload]
    source_file: str
    author: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class PayloadTemplate:
    """A payload template with variables."""
    payload: str
    variables: list[str]  # Variable names found in payload
    technique: PayloadTechnique = PayloadTechnique.DIRECT
    description: str = ""
    tags: list[str] = field(default_factory=list)
    requires_encoding: bool = False
    is_dangerous: bool = False
    severity: str = ""

    def render(self, variables: dict[str, str]) -> str:
        """Render template with variables."""
        template = Template(self.payload)
        return template.safe_substitute(variables)


class CustomPayloadLoader:
    """
    Load custom payloads from YAML/JSON files.

    Features:
    - Variable substitution using ${var_name} syntax
    - Validation of payload structure
    - Support for YAML and JSON formats
    - Payload templating with context

    Usage:
        loader = CustomPayloadLoader()

        # Load single file
        payloads = loader.load_file("my_payloads.yaml")

        # Load directory of payload files
        payloads = loader.load_directory("./custom_payloads/")

        # Load with variable overrides
        payloads = loader.load_file(
            "template.yaml",
            variables={"target_table": "admin_users"},
        )
    """

    # Map technique strings to enum
    TECHNIQUE_MAP = {
        "direct": PayloadTechnique.DIRECT,
        "error_based": PayloadTechnique.ERROR_BASED,
        "union_based": PayloadTechnique.UNION_BASED,
        "boolean_based": PayloadTechnique.BOOLEAN_BASED,
        "time_based": PayloadTechnique.TIME_BASED,
        "stacked_queries": PayloadTechnique.STACKED_QUERIES,
        "out_of_band": PayloadTechnique.OUT_OF_BAND,
        "filter_bypass": PayloadTechnique.FILTER_BYPASS,
        "waf_bypass": PayloadTechnique.WAF_BYPASS,
        "encoding_bypass": PayloadTechnique.ENCODING_BYPASS,
    }

    # Map vuln type strings to enum
    VULN_TYPE_MAP = {vt.value: vt for vt in VulnerabilityType}

    def __init__(
        self,
        default_variables: Optional[dict[str, str]] = None,
        strict_mode: bool = False,
    ):
        """
        Initialize custom payload loader.

        Args:
            default_variables: Default variables for all payload files
            strict_mode: Raise errors on invalid payloads instead of skipping
        """
        self.default_variables = default_variables or {}
        self.strict_mode = strict_mode
        self._loaded_files: dict[str, CustomPayloadFile] = {}

    def load_file(
        self,
        file_path: Union[str, Path],
        variables: Optional[dict[str, str]] = None,
    ) -> CustomPayloadFile:
        """
        Load payloads from a single YAML/JSON file.

        Args:
            file_path: Path to payload file
            variables: Override variables defined in file

        Returns:
            CustomPayloadFile with parsed payloads

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is invalid
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Payload file not found: {path}")

        # Parse file based on extension
        content = path.read_text(encoding="utf-8")

        if path.suffix in (".yaml", ".yml"):
            if not YAML_AVAILABLE:
                raise ImportError("PyYAML required for YAML payload files: pip install pyyaml")
            data = yaml.safe_load(content)
        elif path.suffix == ".json":
            data = json.loads(content)
        else:
            # Try to auto-detect format
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                if YAML_AVAILABLE:
                    data = yaml.safe_load(content)
                else:
                    raise ValueError(f"Unsupported file format: {path.suffix}")

        result = self._parse_payload_file(data, str(path), variables)
        self._loaded_files[str(path)] = result

        return result

    def load_directory(
        self,
        directory: Union[str, Path],
        pattern: str = "*.yaml",
        recursive: bool = False,
        variables: Optional[dict[str, str]] = None,
    ) -> list[CustomPayloadFile]:
        """
        Load all payload files from directory.

        Args:
            directory: Directory path
            pattern: Glob pattern for files
            recursive: Search subdirectories
            variables: Variable overrides

        Returns:
            List of CustomPayloadFile objects
        """
        path = Path(directory)

        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {path}")

        results = []
        glob_method = path.rglob if recursive else path.glob

        # Search for YAML and JSON files
        patterns = [pattern]
        if pattern == "*.yaml":
            patterns.extend(["*.yml", "*.json"])

        for file_pattern in patterns:
            for file_path in glob_method(file_pattern):
                try:
                    result = self.load_file(file_path, variables)
                    results.append(result)
                    logger.info(f"Loaded {len(result.payloads)} payloads from {file_path}")
                except Exception as e:
                    if self.strict_mode:
                        raise
                    logger.warning(f"Failed to load {file_path}: {e}")

        return results

    def load_inline(
        self,
        payloads: list[str],
        vuln_type: str,
        name: str = "Inline Payloads",
    ) -> CustomPayloadFile:
        """
        Load payloads from inline list.

        Args:
            payloads: List of payload strings
            vuln_type: Vulnerability type
            name: Name for this payload set

        Returns:
            CustomPayloadFile
        """
        # Convert vuln type
        try:
            vtype = VulnerabilityType(vuln_type)
        except ValueError:
            vtype = VulnerabilityType.SQL_INJECTION  # Default

        parsed = []
        for payload in payloads:
            parsed.append(ParsedPayload(
                content=payload,
                category=vtype,
                technique=PayloadTechnique.DIRECT,
                source_file="inline",
            ))

        return CustomPayloadFile(
            name=name,
            version="1.0",
            vuln_type=vtype,
            variables={},
            payloads=parsed,
            source_file="inline",
        )

    def _parse_payload_file(
        self,
        data: dict,
        source_file: str,
        variable_overrides: Optional[dict[str, str]] = None,
    ) -> CustomPayloadFile:
        """Parse payload file data structure."""
        # Validate required fields
        if "vuln_type" not in data:
            raise ValueError("Payload file must specify 'vuln_type'")

        # Parse vuln type
        vuln_type_str = data["vuln_type"].lower().replace(" ", "_").replace("-", "_")
        if vuln_type_str not in self.VULN_TYPE_MAP:
            # Try to find close match
            for key, vtype in self.VULN_TYPE_MAP.items():
                if vuln_type_str in key or key in vuln_type_str:
                    vuln_type = vtype
                    break
            else:
                raise ValueError(f"Unknown vuln_type: {data['vuln_type']}")
        else:
            vuln_type = self.VULN_TYPE_MAP[vuln_type_str]

        # Merge variables: default < file < override
        variables = dict(self.default_variables)
        variables.update(data.get("variables", {}))
        if variable_overrides:
            variables.update(variable_overrides)

        # Parse payloads
        payloads = []
        for payload_data in data.get("payloads", []):
            try:
                payload = self._parse_payload(
                    payload_data,
                    vuln_type,
                    variables,
                    source_file,
                )
                payloads.append(payload)
            except Exception as e:
                if self.strict_mode:
                    raise
                logger.warning(f"Skipping invalid payload in {source_file}: {e}")

        return CustomPayloadFile(
            name=data.get("name", Path(source_file).stem),
            version=data.get("version", "1.0"),
            vuln_type=vuln_type,
            variables=variables,
            payloads=payloads,
            source_file=source_file,
            author=data.get("author", ""),
            description=data.get("description", ""),
            tags=data.get("tags", []),
        )

    def _parse_payload(
        self,
        data: Union[dict, str],
        vuln_type: VulnerabilityType,
        variables: dict[str, str],
        source_file: str,
    ) -> ParsedPayload:
        """Parse single payload entry."""
        # Handle simple string format
        if isinstance(data, str):
            payload = self._substitute_variables(data, variables)
            return ParsedPayload(
                content=payload,
                category=vuln_type,
                technique=PayloadTechnique.DIRECT,
                source_file=source_file,
            )

        # Get raw payload
        raw_payload = data.get("payload", "")
        if not raw_payload:
            raise ValueError("Payload entry must have 'payload' field")

        # Substitute variables
        payload = self._substitute_variables(raw_payload, variables)

        # Parse technique
        technique_str = data.get("technique", "direct")
        technique = self.TECHNIQUE_MAP.get(
            technique_str.lower(),
            PayloadTechnique.DIRECT,
        )

        # Parse tags
        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        return ParsedPayload(
            content=payload,
            category=vuln_type,
            subcategory=data.get("subcategory", ""),
            technique=technique,
            description=data.get("description", ""),
            language=data.get("language", ""),
            source_file=source_file,
            requires_encoding=data.get("requires_encoding", False),
            is_dangerous=data.get("is_dangerous", False),
            tags=tags,
        )

    def _substitute_variables(
        self,
        payload: str,
        variables: dict[str, str],
    ) -> str:
        """Substitute ${var} placeholders with values."""
        # Use safe_substitute to leave unknown vars unchanged
        template = Template(payload)
        return template.safe_substitute(variables)

    def get_loaded_files(self) -> dict[str, CustomPayloadFile]:
        """Get all loaded payload files."""
        return self._loaded_files.copy()

    def get_all_payloads(self) -> list[ParsedPayload]:
        """Get all payloads from all loaded files."""
        payloads = []
        for pf in self._loaded_files.values():
            payloads.extend(pf.payloads)
        return payloads

    def get_payloads_by_type(
        self,
        vuln_type: VulnerabilityType,
    ) -> list[ParsedPayload]:
        """Get payloads filtered by vulnerability type."""
        payloads = []
        for pf in self._loaded_files.values():
            if pf.vuln_type == vuln_type:
                payloads.extend(pf.payloads)
        return payloads

    def clear(self):
        """Clear all loaded files."""
        self._loaded_files.clear()


class PayloadTemplateEngine:
    """
    Advanced payload templating with conditionals and loops.

    Supports:
    - Simple variable substitution: ${var}
    - Conditional: ${if:condition}...${endif}
    - List expansion: ${foreach:var}...${endforeach}
    - Built-in functions: ${encode:url:value}, ${random:8}

    Example:
        engine = PayloadTemplateEngine()
        template = "' OR username='${user}' AND password='${encode:url:pass}'--"
        payload = engine.render(template, {"user": "admin", "pass": "test&123"})
    """

    def __init__(self):
        self._functions = {
            "encode": self._fn_encode,
            "random": self._fn_random,
            "upper": self._fn_upper,
            "lower": self._fn_lower,
            "hex": self._fn_hex,
            "base64": self._fn_base64,
        }

    def render(
        self,
        template: str,
        variables: dict[str, str],
    ) -> str:
        """Render template with variables and functions."""
        result = template

        # First pass: function substitution
        result = self._process_functions(result, variables)

        # Second pass: variable substitution
        result = Template(result).safe_substitute(variables)

        return result

    def _process_functions(
        self,
        template: str,
        variables: dict[str, str],
    ) -> str:
        """Process ${fn:args} function calls."""
        pattern = r'\$\{(\w+):([^}]+)\}'

        def replace_fn(match):
            fn_name = match.group(1).lower()
            args = match.group(2)

            if fn_name in self._functions:
                # Substitute variables in args first
                args = Template(args).safe_substitute(variables)
                return self._functions[fn_name](args)
            return match.group(0)

        return re.sub(pattern, replace_fn, template)

    def _fn_encode(self, args: str) -> str:
        """Encoding function: ${encode:type:value}"""
        parts = args.split(":", 1)
        if len(parts) != 2:
            return args

        encode_type, value = parts

        import urllib.parse
        import base64

        if encode_type == "url":
            return urllib.parse.quote(value, safe="")
        elif encode_type == "double_url":
            return urllib.parse.quote(urllib.parse.quote(value, safe=""), safe="")
        elif encode_type == "html":
            return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        elif encode_type == "base64":
            return base64.b64encode(value.encode()).decode()
        elif encode_type == "hex":
            return value.encode().hex()

        return value

    def _fn_random(self, args: str) -> str:
        """Random string: ${random:length}"""
        import random
        import string

        try:
            length = int(args)
        except ValueError:
            length = 8

        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def _fn_upper(self, args: str) -> str:
        """Uppercase: ${upper:value}"""
        return args.upper()

    def _fn_lower(self, args: str) -> str:
        """Lowercase: ${lower:value}"""
        return args.lower()

    def _fn_hex(self, args: str) -> str:
        """Hex encode: ${hex:value}"""
        return args.encode().hex()

    def _fn_base64(self, args: str) -> str:
        """Base64 encode: ${base64:value}"""
        import base64
        return base64.b64encode(args.encode()).decode()


# Convenience functions

def load_custom_payloads(file_path: str) -> list[ParsedPayload]:
    """
    Quick function to load payloads from file.

    Args:
        file_path: Path to payload file

    Returns:
        List of parsed payloads
    """
    loader = CustomPayloadLoader()
    result = loader.load_file(file_path)
    return result.payloads


def load_payloads_directory(
    directory: str,
) -> dict[VulnerabilityType, list[ParsedPayload]]:
    """
    Load all payloads from directory, grouped by vuln type.

    Args:
        directory: Directory containing payload files

    Returns:
        Dict mapping vuln types to payload lists
    """
    loader = CustomPayloadLoader()
    results = loader.load_directory(directory)

    grouped: dict[VulnerabilityType, list[ParsedPayload]] = {}
    for file_result in results:
        if file_result.vuln_type not in grouped:
            grouped[file_result.vuln_type] = []
        grouped[file_result.vuln_type].extend(file_result.payloads)

    return grouped


def create_payload_file(
    payloads: list[str],
    vuln_type: str,
    output_path: str,
    name: str = "Custom Payloads",
    variables: Optional[dict[str, str]] = None,
    format: str = "yaml",
) -> str:
    """
    Create a payload file from list of payloads.

    Args:
        payloads: List of payload strings
        vuln_type: Vulnerability type
        output_path: Output file path
        name: Name for payload set
        variables: Variables to include
        format: Output format (yaml or json)

    Returns:
        Output file path
    """
    data = {
        "name": name,
        "version": "1.0",
        "vuln_type": vuln_type,
        "payloads": [{"payload": p} for p in payloads],
    }

    if variables:
        data["variables"] = variables

    path = Path(output_path)

    if format == "yaml":
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML required: pip install pyyaml")
        content = yaml.dump(data, default_flow_style=False)
    else:
        content = json.dumps(data, indent=2)

    path.write_text(content, encoding="utf-8")
    return str(path)
