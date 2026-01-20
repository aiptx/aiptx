"""
Cross-Platform Compatibility Tests
==================================

Tests for Windows, Linux, and macOS compatibility of AIPTX modules.
These tests verify that platform-specific code paths work correctly.

Run with: pytest tests/test_cross_platform.py -v
"""

import asyncio
import platform
import sys
import unittest
from unittest.mock import patch, MagicMock
import pytest


# Test the terminal module
class TestTerminalCrossPlatform:
    """Tests for terminal.py cross-platform compatibility."""

    def test_platform_detection(self):
        """Test that IS_WINDOWS is correctly detected."""
        from aipt_v2.execution.terminal import IS_WINDOWS

        if platform.system() == "Windows":
            assert IS_WINDOWS is True
        else:
            assert IS_WINDOWS is False

    def test_terminal_initialization(self):
        """Test Terminal class can be initialized on any platform."""
        from aipt_v2.execution.terminal import Terminal

        terminal = Terminal()
        assert terminal is not None
        assert terminal.default_timeout == 300
        assert terminal.max_output == 50000

    def test_shell_selection(self):
        """Test correct shell selection for platform."""
        from aipt_v2.execution.terminal import Terminal, IS_WINDOWS

        terminal = Terminal()

        if IS_WINDOWS:
            assert terminal.shell is None  # Windows uses default shell
        else:
            assert terminal.shell == "/bin/bash"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_popen_kwargs_windows(self):
        """Test Popen kwargs generation for Windows."""
        from aipt_v2.execution.terminal import Terminal
        import subprocess

        terminal = Terminal()
        kwargs = terminal._get_popen_kwargs("/tmp", {})

        assert kwargs["shell"] is True
        assert kwargs["cwd"] == "/tmp"
        assert "creationflags" in kwargs
        assert kwargs["creationflags"] == subprocess.CREATE_NEW_PROCESS_GROUP

    def test_popen_kwargs_unix(self):
        """Test Popen kwargs generation for Unix."""
        from aipt_v2.execution.terminal import Terminal
        import os

        with patch('aipt_v2.execution.terminal.IS_WINDOWS', False):
            terminal = Terminal()
            terminal.shell = "/bin/bash"  # Force Unix shell
            kwargs = terminal._get_popen_kwargs("/tmp", {})

            assert kwargs["shell"] is True
            assert kwargs["cwd"] == "/tmp"
            assert "executable" in kwargs
            assert "preexec_fn" in kwargs

    def test_execute_simple_command(self):
        """Test executing a simple cross-platform command."""
        from aipt_v2.execution.terminal import Terminal

        terminal = Terminal()

        # Use platform-appropriate command
        if platform.system() == "Windows":
            result = terminal.execute("echo hello", timeout=10)
        else:
            result = terminal.execute("echo hello", timeout=10)

        assert result.return_code == 0
        assert "hello" in result.output.lower()

    def test_check_tool_available_cross_platform(self):
        """Test tool availability check works on all platforms."""
        from aipt_v2.execution.terminal import Terminal

        terminal = Terminal()

        # Python should be available on all platforms
        is_available = terminal.check_tool_available("python3") or terminal.check_tool_available("python")
        assert is_available is True

    def test_streaming_methods_exist(self):
        """Test that both streaming implementations exist."""
        from aipt_v2.execution.terminal import Terminal

        terminal = Terminal()

        assert hasattr(terminal, '_streaming_windows')
        assert hasattr(terminal, '_streaming_unix')
        assert hasattr(terminal, '_stream_reader_thread')


class TestInteractiveShellCrossPlatform:
    """Tests for interactive_shell.py cross-platform compatibility."""

    def test_platform_detection(self):
        """Test that IS_WINDOWS is correctly detected."""
        from aipt_v2.interactive_shell import IS_WINDOWS

        if platform.system() == "Windows":
            assert IS_WINDOWS is True
        else:
            assert IS_WINDOWS is False

    def test_conditional_imports(self):
        """Test that Unix modules are only imported on Unix."""
        from aipt_v2.interactive_shell import IS_WINDOWS

        if IS_WINDOWS:
            # On Windows, Unix modules should not be imported at module level
            import aipt_v2.interactive_shell as shell_module
            # pty, termios, tty should not be in the module namespace
            assert not hasattr(shell_module, 'termios')
            assert not hasattr(shell_module, 'tty')
        else:
            # On Unix, these modules should be available
            import aipt_v2.interactive_shell as shell_module
            # They are imported into the module globals when not Windows
            pass  # Just verify no import errors

    def test_shell_initialization(self):
        """Test InteractiveShell can be initialized on any platform."""
        from aipt_v2.interactive_shell import InteractiveShell

        shell = InteractiveShell()
        assert shell is not None
        assert shell.running is False

    def test_readline_handling(self):
        """Test readline availability is handled gracefully."""
        from aipt_v2.interactive_shell import HAS_READLINE

        # HAS_READLINE should be True or False depending on availability
        assert isinstance(HAS_READLINE, bool)

    def test_command_methods_exist(self):
        """Test that both command execution methods exist."""
        from aipt_v2.interactive_shell import InteractiveShell

        shell = InteractiveShell()

        assert hasattr(shell, '_run_command_windows')
        assert hasattr(shell, '_run_command_unix')
        assert hasattr(shell, 'run_command')


class TestPrerequisitesChecker:
    """Tests for prerequisites.py functionality."""

    def test_checker_initialization(self):
        """Test PrerequisitesChecker can be initialized."""
        from aipt_v2.prerequisites import PrerequisitesChecker

        checker = PrerequisitesChecker()
        assert checker is not None

    @pytest.mark.asyncio
    async def test_check_python_version(self):
        """Test Python version check."""
        from aipt_v2.prerequisites import PrerequisitesChecker

        checker = PrerequisitesChecker()
        report = await checker.check_all(include_optional=False)

        # Should have at least the Python version check
        python_checks = [c for c in report.checks if "Python" in c.name]
        assert len(python_checks) > 0

        # Current Python should pass (we're running it!)
        python_check = python_checks[0]
        assert python_check.status.value == "passed"

    @pytest.mark.asyncio
    async def test_check_core_packages(self):
        """Test core package checks."""
        from aipt_v2.prerequisites import PrerequisitesChecker

        checker = PrerequisitesChecker()
        report = await checker.check_all(include_optional=False)

        # Should check for litellm, rich, click, pydantic
        package_names = [c.name for c in report.checks]
        assert any("rich" in name.lower() for name in package_names)

    def test_sync_check(self):
        """Test synchronous prerequisites check."""
        from aipt_v2.prerequisites import check_prerequisites_sync

        is_ready, errors = check_prerequisites_sync(
            require_llm=False,  # Don't require LLM for this test
            require_tools=False,
        )

        # Core packages should be available
        assert isinstance(is_ready, bool)
        assert isinstance(errors, list)

    def test_check_status_enum(self):
        """Test CheckStatus enum values."""
        from aipt_v2.prerequisites import CheckStatus

        assert CheckStatus.PASSED.value == "passed"
        assert CheckStatus.WARNING.value == "warning"
        assert CheckStatus.FAILED.value == "failed"

    def test_check_category_enum(self):
        """Test CheckCategory enum values."""
        from aipt_v2.prerequisites import CheckCategory

        assert CheckCategory.CORE.value == "core"
        assert CheckCategory.LLM.value == "llm"
        assert CheckCategory.SECURITY_TOOLS.value == "tools"

    @pytest.mark.asyncio
    async def test_system_info_collection(self):
        """Test system information is collected correctly."""
        from aipt_v2.prerequisites import PrerequisitesChecker

        checker = PrerequisitesChecker()
        report = await checker.check_all(include_optional=False)

        assert "platform" in report.system_info
        assert "python_version" in report.system_info
        assert "architecture" in report.system_info

        # Verify platform matches
        assert report.system_info["platform"] == platform.system()

    def test_report_json_output(self):
        """Test report can be serialized to JSON."""
        from aipt_v2.prerequisites import PrerequisitesReport, CheckResult, CheckStatus, CheckCategory
        import json

        report = PrerequisitesReport()
        report.checks.append(CheckResult(
            name="Test Check",
            status=CheckStatus.PASSED,
            category=CheckCategory.CORE,
            message="Test passed",
        ))

        json_output = report.to_json()
        parsed = json.loads(json_output)

        assert "checks" in parsed
        assert "summary" in parsed
        assert parsed["summary"]["passed"] == 1


class TestCLIIntegration:
    """Tests for CLI integration with prerequisites."""

    def test_check_command_parser(self):
        """Test check command is registered in CLI parser."""
        import argparse
        from aipt_v2 import cli

        # The parser setup happens in main(), so we verify the command handler exists
        assert hasattr(cli, 'run_check')

    def test_run_check_function_exists(self):
        """Test run_check function is defined."""
        from aipt_v2.cli import run_check

        assert callable(run_check)


# Additional edge case tests
class TestEdgeCases:
    """Edge case and error handling tests."""

    def test_terminal_with_nonexistent_dir(self):
        """Test Terminal handles nonexistent working directory gracefully."""
        from aipt_v2.execution.terminal import Terminal
        import tempfile
        import os

        # Create and delete a temp dir to get a nonexistent path
        temp_dir = tempfile.mkdtemp()
        os.rmdir(temp_dir)

        # Terminal should create the directory
        terminal = Terminal(working_dir=temp_dir)
        assert os.path.exists(temp_dir)

        # Cleanup
        os.rmdir(temp_dir)

    def test_execution_result_properties(self):
        """Test ExecutionResult dataclass properties."""
        from aipt_v2.execution.terminal import ExecutionResult

        # Success case
        result = ExecutionResult(
            command="echo test",
            output="test",
            error=None,
            return_code=0,
            timed_out=False,
            duration=0.1,
        )
        assert result.success is True

        # Failure case
        result = ExecutionResult(
            command="false",
            output="",
            error="error",
            return_code=1,
            timed_out=False,
            duration=0.1,
        )
        assert result.success is False

        # Timeout case
        result = ExecutionResult(
            command="sleep 100",
            output="",
            error=None,
            return_code=0,
            timed_out=True,
            duration=10.0,
        )
        assert result.success is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
