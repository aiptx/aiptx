"""
AIPT Event Loop Manager - Centralized asyncio event loop management

This module provides a singleton event loop manager that solves the common
problem of multiple asyncio.run() calls causing "event loop is closed" errors.

Key Features:
- Single shared event loop across the application
- Thread-safe loop access
- Graceful shutdown with task cancellation
- Automatic loop recreation if closed
- Context manager support for clean resource management

Usage:
    from aipt_v2.core.event_loop_manager import EventLoopManager, run_async

    # Simple async execution
    result = run_async(my_coroutine())

    # Or with context manager
    async with EventLoopManager.managed_loop() as loop:
        await my_coroutine()
"""
from __future__ import annotations

import asyncio
import atexit
import contextlib
import logging
import signal
import sys
import threading
from typing import Any, Coroutine, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class EventLoopManager:
    """
    Singleton event loop manager for AIPTX.

    This class ensures a single event loop is used throughout the application
    lifecycle, preventing "event loop is closed" errors that occur when
    asyncio.run() is called multiple times.

    Thread Safety:
        All methods are thread-safe using a reentrant lock.

    Example:
        # Get the shared loop
        loop = EventLoopManager.get_loop()

        # Run a coroutine
        result = EventLoopManager.run_until_complete(my_coro())

        # Run and auto-cleanup
        result = EventLoopManager.run(my_coro())
    """

    _instance: EventLoopManager | None = None
    _lock = threading.RLock()
    _loop: asyncio.AbstractEventLoop | None = None
    _loop_thread: threading.Thread | None = None
    _shutdown_registered: bool = False
    _is_shutting_down: bool = False

    def __new__(cls) -> EventLoopManager:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._register_shutdown_handlers()
            return cls._instance

    @classmethod
    def _register_shutdown_handlers(cls) -> None:
        """Register cleanup handlers for graceful shutdown."""
        if cls._shutdown_registered:
            return

        atexit.register(cls.shutdown)

        # Handle SIGINT and SIGTERM gracefully
        if sys.platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    signal.signal(sig, cls._signal_handler)
                except (OSError, ValueError):
                    # Signal handling may not work in all contexts
                    pass

        cls._shutdown_registered = True

    @classmethod
    def _signal_handler(cls, signum: int, frame: Any) -> None:
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        cls.shutdown()
        sys.exit(0)

    @classmethod
    def get_loop(cls) -> asyncio.AbstractEventLoop:
        """
        Get the shared event loop, creating one if necessary.

        Returns:
            The shared asyncio event loop.

        Note:
            If the loop was closed, a new one will be created.
        """
        with cls._lock:
            if cls._is_shutting_down:
                raise RuntimeError("EventLoopManager is shutting down")

            if cls._loop is None or cls._loop.is_closed():
                cls._loop = cls._create_loop()
                logger.debug("Created new event loop")

            return cls._loop

    @classmethod
    def _create_loop(cls) -> asyncio.AbstractEventLoop:
        """Create and configure a new event loop."""
        # Use the appropriate event loop policy for the platform
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Configure loop for better debugging in development
        if logger.isEnabledFor(logging.DEBUG):
            loop.set_debug(True)

        return loop

    @classmethod
    def run_until_complete(cls, coro: Coroutine[Any, Any, T]) -> T:
        """
        Run a coroutine to completion on the shared event loop.

        Args:
            coro: The coroutine to run.

        Returns:
            The result of the coroutine.

        Raises:
            RuntimeError: If called from within the event loop.
        """
        loop = cls.get_loop()

        if loop.is_running():
            # If loop is already running, schedule the coro and wait
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result()

        return loop.run_until_complete(coro)

    @classmethod
    def run(cls, coro: Coroutine[Any, Any, T], cleanup: bool = False) -> T:
        """
        Run a coroutine with optional cleanup.

        This is the recommended way to run async code from sync context.

        Args:
            coro: The coroutine to run.
            cleanup: If True, cancel pending tasks after completion.

        Returns:
            The result of the coroutine.
        """
        try:
            result = cls.run_until_complete(coro)
            return result
        finally:
            if cleanup:
                cls._cleanup_pending_tasks()

    @classmethod
    def _cleanup_pending_tasks(cls) -> None:
        """Cancel and cleanup pending tasks on the event loop."""
        if cls._loop is None or cls._loop.is_closed():
            return

        try:
            # Get all pending tasks
            pending = asyncio.all_tasks(cls._loop)
            if not pending:
                return

            logger.debug(f"Cleaning up {len(pending)} pending tasks")

            # Cancel all pending tasks
            for task in pending:
                task.cancel()

            # Wait for cancellation to complete
            cls._loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
        except Exception as e:
            logger.warning(f"Error during task cleanup: {e}")

    @classmethod
    def shutdown(cls) -> None:
        """
        Gracefully shutdown the event loop manager.

        This method:
        1. Sets the shutdown flag
        2. Cancels all pending tasks
        3. Closes the event loop
        4. Resets the singleton state
        """
        with cls._lock:
            if cls._is_shutting_down:
                return

            cls._is_shutting_down = True
            logger.info("Shutting down EventLoopManager")

            if cls._loop is not None and not cls._loop.is_closed():
                try:
                    # Cancel pending tasks
                    cls._cleanup_pending_tasks()

                    # Run pending callbacks
                    cls._loop.run_until_complete(cls._loop.shutdown_asyncgens())

                    # Close the loop
                    cls._loop.close()
                    logger.debug("Event loop closed")
                except Exception as e:
                    logger.warning(f"Error during shutdown: {e}")

            cls._loop = None
            cls._is_shutting_down = False

    @classmethod
    def is_loop_running(cls) -> bool:
        """Check if the event loop is currently running."""
        with cls._lock:
            return cls._loop is not None and cls._loop.is_running()

    @classmethod
    def reset(cls) -> None:
        """
        Reset the event loop manager state.

        Warning: Only use this in testing or when you need a fresh loop.
        """
        cls.shutdown()
        with cls._lock:
            cls._instance = None

    @classmethod
    @contextlib.asynccontextmanager
    async def managed_loop(cls):
        """
        Async context manager for scoped event loop usage.

        Example:
            async with EventLoopManager.managed_loop() as loop:
                await my_async_operation()
        """
        loop = cls.get_loop()
        try:
            yield loop
        finally:
            # Cleanup can be done here if needed
            pass

    @classmethod
    def create_task(cls, coro: Coroutine[Any, Any, T]) -> asyncio.Task[T]:
        """
        Create a task on the shared event loop.

        Args:
            coro: The coroutine to wrap in a task.

        Returns:
            The created task.
        """
        loop = cls.get_loop()
        return loop.create_task(coro)

    @classmethod
    def run_coroutine_threadsafe(
        cls, coro: Coroutine[Any, Any, T]
    ) -> asyncio.Future[T]:
        """
        Schedule a coroutine to run on the event loop from another thread.

        Args:
            coro: The coroutine to schedule.

        Returns:
            A concurrent.futures.Future for the result.
        """
        loop = cls.get_loop()
        return asyncio.run_coroutine_threadsafe(coro, loop)


# Convenience function for simple usage
def run_async(coro: Coroutine[Any, Any, T], cleanup: bool = False) -> T:
    """
    Run an async coroutine from synchronous code.

    This is the recommended way to run async code in AIPTX.
    It uses the shared EventLoopManager to avoid "event loop closed" errors.

    Args:
        coro: The coroutine to run.
        cleanup: If True, cleanup pending tasks after completion.

    Returns:
        The result of the coroutine.

    Example:
        result = run_async(fetch_data())
    """
    return EventLoopManager.run(coro, cleanup=cleanup)


def get_current_loop() -> asyncio.AbstractEventLoop:
    """
    Get the current event loop safely.

    This function replaces the deprecated asyncio.get_event_loop()
    by first trying to get the running loop, then falling back to
    the EventLoopManager's shared loop.

    Returns:
        The current or shared event loop.
    """
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        # No running loop, use the shared one
        return EventLoopManager.get_loop()


def current_time() -> float:
    """
    Get the current time from the event loop.

    This is a safe replacement for asyncio.get_event_loop().time()

    Returns:
        The current time as a float.
    """
    try:
        loop = asyncio.get_running_loop()
        return loop.time()
    except RuntimeError:
        # Fall back to time.time() if no loop is running
        import time
        return time.time()
