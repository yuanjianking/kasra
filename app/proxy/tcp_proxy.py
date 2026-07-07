"""TCP CONNECT proxy for HTTPS traffic tunneling.

Provides CONNECT tunneling support so that HTTPS_PROXY env var
works with Kasra. Tunneled traffic is encrypted end-to-end and
cannot be inspected without MITM mode. For full content inspection
on HTTPS, use MCP integration or deploy with an MITM-capable
forward proxy (mitmproxy, fiddler, charles) in front of Kasra.

Usage::

    proxy = ConnectProxy(host="0.0.0.0", port=8443)
    await proxy.start()
    ...
    await proxy.stop()
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger("kasra.proxy.connect")


class ConnectProxy:
    """TCP-level HTTPS CONNECT proxy server.

    Accepts raw TCP connections, parses HTTP CONNECT requests,
    and establishes bidirectional tunnels to target hosts.

    Started and stopped via the application lifespan. Disabled by
    default — set ``KASRA_APP_HTTPS_PROXY_ENABLED=true`` to opt in.

    Args:
        host: Bind address (default: ``0.0.0.0``).
        port: Listen port (default: ``8443``).
        allowed_upstreams: Optional list of hostnames to allow.
            Empty list means all hosts are allowed.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8443,
        allowed_upstreams: Optional[list[str]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.allowed_upstreams = allowed_upstreams or []
        self._server: Optional[asyncio.AbstractServer] = None
        self._tasks: set[asyncio.Task] = set()

    # ── Properties ───────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """Whether the proxy server is currently listening."""
        return self._server is not None

    @property
    def active_connections(self) -> int:
        """Number of active tunnel connections."""
        return len(self._tasks)

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the TCP proxy server."""
        self._server = await asyncio.start_server(
            self._on_connect,
            host=self.host,
            port=self.port,
            limit=65536,
        )
        addr = self._server.sockets[0].getsockname()
        logger.info(
            "CONNECT proxy listening on %s:%s (upstreams=%s)",
            addr[0], addr[1],
            len(self.allowed_upstreams) if self.allowed_upstreams else "ANY",
        )

    async def stop(self) -> None:
        """Stop the TCP proxy server and clean up active connections."""
        # Cancel all active relay tasks
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks.clear()

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("CONNECT proxy stopped")

    # ── Connection handling ──────────────────────────────────────────────

    async def _on_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming TCP connection."""
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            await self._handle_connect(reader, writer)
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Error handling CONNECT connection")
        finally:
            self._tasks.discard(task)

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Parse and handle a single CONNECT request."""
        # ── 1. Read the CONNECT request line ──
        request_line = await reader.readline()
        if not request_line:
            self._close_writer(writer)
            return

        line = request_line.decode("utf-8", errors="replace").strip()
        logger.debug("CONNECT << %s", line)

        parts = line.split()
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            await self._respond(writer, 400, b"Bad Request: expected CONNECT")
            return

        # ── 2. Parse target host:port ──
        target = parts[1]
        target_host, _, target_port_str = target.partition(":")
        try:
            target_port = int(target_port_str) if target_port_str else 443
        except ValueError:
            await self._respond(writer, 400, b"Bad Request: invalid port")
            return

        if target_port < 1 or target_port > 65535:
            await self._respond(writer, 400, b"Bad Request: port out of range")
            return

        # ── 3. Consume remaining headers ──
        while True:
            header_line = await reader.readline()
            if header_line in (b"\r\n", b"\n", b""):
                break

        # ── 4. Validate against allowed upstreams ──
        if self.allowed_upstreams and target_host not in self.allowed_upstreams:
            logger.warning("CONNECT target not allowed: %s:%d", target_host, target_port)
            await self._respond(writer, 403, b"Forbidden: target not allowed")
            return

        # ── 5. Connect to target ──
        logger.info("CONNECT tunnel: %s:%d", target_host, target_port)
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=15.0,
            )
        except asyncio.TimeoutError:
            logger.warning("CONNECT timeout to %s:%d", target_host, target_port)
            await self._respond(writer, 504, b"Gateway Timeout")
            return
        except (OSError, ConnectionError) as e:
            logger.warning(
                "CONNECT connection failed to %s:%d: %s",
                target_host, target_port, e,
            )
            await self._respond(writer, 502, b"Bad Gateway")
            return

        # ── 6. Send 200 Connection Established ──
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        # ── 7. Bidirectional relay ──
        await self._relay(reader, writer, remote_reader, remote_writer)

    # ── Bidirectional relay ──────────────────────────────────────────────

    @staticmethod
    async def _relay(
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
    ) -> None:
        """Relay data bidirectionally between client and remote.

        Two coroutines run concurrently — one forwards data from
        client → remote, the other from remote → client. When either
        side closes, both directions are torn down.
        """

        async def _forward(
            src: asyncio.StreamReader,
            dst: asyncio.StreamWriter,
        ) -> None:
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        tasks = [
            asyncio.create_task(_forward(client_reader, remote_writer)),
            asyncio.create_task(_forward(remote_reader, client_writer)),
        ]

        done, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
        for t in done:
            if not t.cancelled():
                try:
                    t.result()
                except Exception:
                    pass

        try:
            client_writer.close()
        except Exception:
            pass
        try:
            remote_writer.close()
        except Exception:
            pass

    # ── Response helpers ─────────────────────────────────────────────────

    @staticmethod
    async def _respond(
        writer: asyncio.StreamWriter,
        status: int,
        body: bytes,
    ) -> None:
        """Send an HTTP error response and close the connection."""
        reasons = {
            400: b"Bad Request",
            403: b"Forbidden",
            502: b"Bad Gateway",
            504: b"Gateway Timeout",
            501: b"Not Implemented",
        }
        reason = reasons.get(status, b"Unknown")
        response = (
            f"HTTP/1.1 {status} {reason.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        writer.write(response)
        if body:
            writer.write(body)
        await writer.drain()
        try:
            writer.close()
        except Exception:
            pass

    @staticmethod
    def _close_writer(writer: asyncio.StreamWriter) -> None:
        """Safely close a writer."""
        try:
            writer.close()
        except Exception:
            pass
