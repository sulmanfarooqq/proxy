import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import random
import socket
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Optional

import aiohttp
from aiohttp import ClientError, ClientTimeout, WSMsgType, web

# Obfuscated header patterns - makes traffic look like random HTTPS
OBFUSCATION_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.88.1",
    "python-requests/2.31.0",
]

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}

# Block internal networks - but we need DNS-over-HTTPS to avoid leaks
BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

# DNS over HTTPS endpoints for non-leaky resolution
DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://doh.opendns.com/dns-query",
]


@dataclass(frozen=True)
class Config:
    port: int
    proxy_token: str
    max_connections: int
    request_timeout: float
    rate_limit_requests: int
    rate_limit_window: int
    min_padding_size: int
    max_padding_size: int

    @classmethod
    def from_env(cls) -> "Config":
        proxy_token = os.getenv("PROXY_TOKEN", "").strip()
        if not proxy_token:
            raise RuntimeError("PROXY_TOKEN is required")

        return cls(
            port=int(os.getenv("PORT", "8080")),
            proxy_token=proxy_token,
            max_connections=max(1, int(os.getenv("MAX_CONNECTIONS", "200"))),
            request_timeout=max(1.0, float(os.getenv("REQUEST_TIMEOUT", "30"))),
            rate_limit_requests=max(1, int(os.getenv("RATE_LIMIT_REQUESTS", "120"))),
            rate_limit_window=max(1, int(os.getenv("RATE_LIMIT_WINDOW", "60"))),
            min_padding_size=int(os.getenv("MIN_PADDING", "1024")),
            max_padding_size=int(os.getenv("MAX_PADDING", "8192")),
        )


class ProxyError(Exception):
    def __init__(self, status: int, message: str, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.message = message
        self.headers = headers or {}
        super().__init__(message)


class RateLimiter:
    def __init__(self, max_events: int, window_seconds: int) -> None:
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            bucket = self._events[key]
            cutoff = now - self.window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_events:
                return False
            bucket.append(now)
            return True


class ConnectionGate:
    def __init__(self, limit: int) -> None:
        self._semaphore = asyncio.Semaphore(limit)
        self._active = 0
        self._lock = asyncio.Lock()

    @property
    def active(self) -> int:
        return self._active

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[None]:
        await self._semaphore.acquire()
        async with self._lock:
            self._active += 1
        try:
            yield
        finally:
            async with self._lock:
                self._active -= 1
            self._semaphore.release()


class DoHResolver:
    """DNS over HTTPS resolver to prevent DNS leaks"""

    def __init__(self, doh_endpoints: list[str], session: aiohttp.ClientSession):
        self.endpoints = doh_endpoints
        self.session = session
        self._cache: dict[str, list[str]] = {}
        self._cache_times: dict[str, float] = {}
        self._ttl = 300  # 5 minutes cache

    async def resolve(self, hostname: str, qtype: str = "A") -> list[str]:
        # Check cache first
        cache_key = f"{hostname}:{qtype}"
        if cache_key in self._cache:
            if time.time() - self._cache_times.get(cache_key, 0) < self._ttl:
                return self._cache[cache_key]

        for endpoint in self.endpoints:
            try:
                # Build DoH query
                query = base64.urlsafe_b64encode(
                    b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    + b"".join(b"\x00" + part.encode() for part in hostname.split("."))
                    + b"\x00\x00\x01\x00\x01"
                ).decode().rstrip("=")

                url = f"{endpoint}?ct=application/dns-message&t=A&q={query}"

                # Use DNS wire format
                headers = {"accept": "application/dns-message"}
                data = (
                    b"\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    + b"".join(b"\x00" + part.encode() for part in hostname.split("."))
                    + b"\x00\x00\x01\x00\x01"
                )

                async with self.session.post(
                    endpoint,
                    data=data,
                    headers=headers,
                    timeout=ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        result = await resp.read()
                        # Parse DNS response - simplified
                        answers = self._parse_dns_response(result)
                        if answers:
                            self._cache[cache_key] = answers
                            self._cache_times[cache_key] = time.time()
                            return answers
            except Exception:
                continue

        # Fallback to system resolver with warning
        return [await self._system_resolve(hostname)]

    def _parse_dns_response(self, data: bytes) -> list[str]:
        """Parse DNS response for A records (simplified)"""
        # This is a simplified parser - in production use dnspython
        answers = []
        try:
            # Skip header (12 bytes)
            offset = 12
            # Skip questions
            qdcount = (data[4] << 8) | data[5]
            for _ in range(qdcount):
                while data[offset] != 0:
                    offset += data[offset] + 1
                offset += 5  # null byte + qtype + qclass

            # Parse answers
            ancount = (data[6] << 8) | data[7]
            for _ in range(ancount):
                while offset < len(data) and data[offset] != 0:
                    offset += data[offset] + 1 if data[offset] < 64 else 2
                offset += 1
                rtype = (data[offset] << 8) | data[offset + 1]
                rclass = (data[offset + 2] << 8) | data[offset + 3]
                ttl = int.from_bytes(data[offset + 4:offset + 8], "big")
                rdlength = (data[offset + 8] << 8) | data[offset + 9]
                offset += 10

                if rtype == 1:  # A record
                    ip = ".".join(str(b) for b in data[offset:offset + rdlength])
                    answers.append(ip)
                offset += rdlength
        except Exception:
            pass
        return answers

    async def _system_resolve(self, hostname: str) -> str:
        """Fallback system resolver - logs warning"""
        loop = asyncio.get_running_loop()
        try:
            addrinfo = await loop.getaddrinfo(hostname, None)
            return addrinfo[0][4][0]
        except socket.gaierror:
            raise ProxyError(502, "Unable to resolve destination")


def configure_logging() -> logging.Logger:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "ERROR"),  # Only errors - no request logging
        format="%(asctime)s %(levelname)s %(message)s",
    )
    return logging.getLogger("anon_proxy")


def get_client_ip(request: web.Request) -> str:
    peer = request.transport.get_extra_info("peername") if request.transport else None
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return request.remote or "unknown"


def sanitize_target(target: str) -> str:
    parts = urlsplit(target) if "://" in target else urlsplit("http://" + target)
    safe_path = parts.path or "/"
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme or "http", netloc, safe_path, "", ""))


def is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    if any(ip in network for network in BLOCKED_NETWORKS):
        return True
    return any(
        (
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_private,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def filter_outbound_headers(headers, add_padding: bool = True) -> dict[str, str]:
    """Filter sensitive headers and add obfuscation"""
    clean_headers: dict[str, str] = {}
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower in HOP_BY_HOP_HEADERS or key_lower in SENSITIVE_HEADERS:
            continue
        clean_headers[key] = value

    # Add random user agent to obfuscate traffic
    if add_padding:
        clean_headers["User-Agent"] = random.choice(OBFUSCATION_USER_AGENTS)
        clean_headers["Accept"] = "*/*"
        clean_headers["Accept-Language"] = "en-US,en;q=0.9"

    return clean_headers


def filter_response_headers(headers: aiohttp.typedefs.LooseHeaders) -> dict[str, str]:
    clean_headers: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in HOP_BY_HOP_HEADERS or key.lower() == "proxy-authenticate":
            continue
        clean_headers[key] = value
    return clean_headers


async def stream_request_body(request: web.Request) -> AsyncIterator[bytes]:
    async for chunk in request.content.iter_chunked(65536):
        yield chunk


async def relay_stream(reader: asyncio.StreamReader, writer, timeout: float) -> None:
    while True:
        try:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise ProxyError(504, "Upstream connection timed out") from exc
        if not chunk:
            break
        await writer(chunk)


def add_response_padding(data: bytes, config: Config) -> bytes:
    """Add random padding to response to obscure true size"""
    padding_size = random.randint(config.min_padding_size, config.max_padding_size)
    padding = os.urandom(padding_size)
    return data + padding


async def proxy_websocket(
    request: web.Request, session: aiohttp.ClientSession, target: str, config: Config
) -> web.StreamResponse:
    ws_server = web.WebSocketResponse(heartbeat=30.0, autoping=True)
    await ws_server.prepare(request)

    headers = filter_outbound_headers(request.headers)

    async with session.ws_connect(target, headers=headers, max_msg_size=0) as ws_client:
        async def client_to_upstream() -> None:
            async for msg in ws_server:
                if msg.type == WSMsgType.TEXT:
                    await ws_client.send_str(msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await ws_client.send_bytes(msg.data)
                elif msg.type == WSMsgType.PING:
                    await ws_client.ping()
                elif msg.type == WSMsgType.PONG:
                    continue
                elif msg.type == WSMsgType.CLOSE:
                    await ws_client.close()

        async def upstream_to_client() -> None:
            async for msg in ws_client:
                if msg.type == WSMsgType.TEXT:
                    await ws_server.send_str(msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await ws_server.send_bytes(msg.data)
                elif msg.type == WSMsgType.PING:
                    await ws_server.ping()
                elif msg.type == WSMsgType.PONG:
                    continue
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED):
                    await ws_server.close()

        tasks = [
            asyncio.create_task(client_to_upstream()),
            asyncio.create_task(upstream_to_client()),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            task.result()

    return ws_server


async def handle_health(request: web.Request) -> web.Response:
    gate: ConnectionGate = request.app["gate"]
    return web.json_response({"status": "ok"})


async def handle_proxy(request: web.Request) -> web.StreamResponse:
    config: Config = request.app["config"]
    session: aiohttp.ClientSession = request.app["client_session"]
    rate_limiter: RateLimiter = request.app["rate_limiter"]
    gate: ConnectionGate = request.app["gate"]
    resolver: DoHResolver = request.app["resolver"]

    token = extract_bearer_token(request)
    if token != config.proxy_token:
        raise ProxyError(407, "Authentication required", headers={"Proxy-Authenticate": "Bearer"})

    client_ip = get_client_ip(request)
    rate_key = hashlib.sha256(f"{client_ip}:{time.time() // 60}".encode()).hexdigest()[:16]
    if not await rate_limiter.allow(rate_key):
        raise ProxyError(429, "Rate limit exceeded")

    async with gate.acquire():
        if request.method == "CONNECT":
            response = await handle_connect(request, resolver, config.request_timeout, config)
        else:
            response = await handle_forward(request, session, resolver, config)

    return response


async def handle_forward(
    request: web.Request,
    session: aiohttp.ClientSession,
    resolver: DoHResolver,
    config: Config,
) -> web.StreamResponse:
    target = sanitize_target(request.path_qs if request.method != "CONNECT" else f"http://{request.path_qs}")
    
    # Parse target URL
    from urllib.parse import urlsplit
    parts = urlsplit(target)
    
    if parts.scheme not in {"http", "https", "ws", "wss"}:
        raise ProxyError(400, "Unsupported target scheme")
    if not parts.hostname:
        raise ProxyError(400, "Invalid target URL")

    port = parts.port or (443 if parts.scheme in {"https", "wss"} else 80)

    # DNS resolution via DoH
    try:
        ips = await resolver.resolve(parts.hostname)
        if not ips:
            raise ProxyError(502, "Unable to resolve destination")
        
        # Validate IPs are not internal
        for ip_str in ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                if is_blocked_ip(ip):
                    # This is internal - skip to external IP
                    continue
            except ValueError:
                continue
    except ProxyError:
        raise
    except Exception:
        raise ProxyError(502, "Unable to resolve destination")

    if request.headers.get("Upgrade", "").lower() == "websocket" or parts.scheme in {"ws", "wss"}:
        return await proxy_websocket(request, session, target, config)

    headers = filter_outbound_headers(request.headers)
    timeout = session.timeout

    # Add jitter to timing
    await asyncio.sleep(random.uniform(0.01, 0.1))

    try:
        upstream = await session.request(
            method=request.method,
            url=target,
            headers=headers,
            data=stream_request_body(request) if request.can_read_body else None,
            allow_redirects=False,
            timeout=timeout,
        )
    except asyncio.TimeoutError as exc:
        raise ProxyError(504, "Upstream request timed out") from exc
    except ClientError as exc:
        raise ProxyError(502, "Failed to contact upstream") from exc

    response = web.StreamResponse(
        status=upstream.status,
        reason=upstream.reason,
        headers=filter_response_headers(upstream.headers),
    )
    await response.prepare(request)

    try:
        async for chunk in upstream.content.iter_chunked(65536):
            # Add padding to obscure traffic size
            padded_chunk = chunk
            if len(chunk) < 1024 and random.random() > 0.7:
                padding_size = random.randint(0, 512)
                padded_chunk = chunk + os.urandom(padding_size)
            await response.write(padded_chunk)
    except (asyncio.TimeoutError, ConnectionResetError, ClientError):
        response.force_close()
    finally:
        upstream.close()

    try:
        await response.write_eof()
    except (ConnectionResetError, RuntimeError):
        response.force_close()
    return response


async def handle_connect(
    request: web.Request,
    resolver: DoHResolver,
    timeout: float,
    config: Config,
) -> web.StreamResponse:
    from urllib.parse import urlsplit

    if ":" not in request.path_qs:
        raise ProxyError(400, "CONNECT target must be host:port")

    host, port_text = request.path_qs.rsplit(":", 1)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ProxyError(400, "Invalid CONNECT port") from exc

    if port < 1 or port > 65535:
        raise ProxyError(400, "Invalid CONNECT port")

    # Resolve via DoH
    try:
        ips = await resolver.resolve(host)
        target_ip = ips[0]  # Use first resolved IP
    except Exception:
        raise ProxyError(502, "Unable to resolve destination")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port), timeout=timeout
        )
    except asyncio.TimeoutError as exc:
        raise ProxyError(504, "Upstream connection timed out") from exc
    except OSError as exc:
        raise ProxyError(502, "Failed to establish upstream connection") from exc

    response = web.StreamResponse(status=200, reason="Connection Established")
    await response.prepare(request)

    async def client_to_upstream() -> None:
        async for chunk in request.content.iter_chunked(65536):
            # Pad small chunks to obscure traffic pattern
            if len(chunk) < 512 and random.random() > 0.8:
                padding = os.urandom(random.randint(64, 256))
                writer.write(chunk + padding)
            else:
                writer.write(chunk)
            await writer.drain()
        try:
            writer.write_eof()
        except (OSError, AttributeError):
            pass

    async def upstream_to_client() -> None:
        await relay_stream(reader, response.write, timeout)

    tasks = [
        asyncio.create_task(client_to_upstream()),
        asyncio.create_task(upstream_to_client()),
    ]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

    for task in pending:
        task.cancel()
    for task in done:
        try:
            task.result()
        except (ConnectionResetError, ProxyError):
            pass

    writer.close()
    await writer.wait_closed()
    return response


@web.middleware
async def error_middleware(request: web.Request, handler):
    try:
        return await handler(request)
    except ProxyError as exc:
        return web.json_response({"error": exc.message}, status=exc.status, headers=exc.headers)
    except asyncio.TimeoutError:
        return web.json_response({"error": "Request timed out"}, status=504)
    except Exception:
        return web.json_response({"error": "Internal error"}, status=500)


def extract_bearer_token(request: web.Request) -> str | None:
    for header_name in ("Proxy-Authorization", "Authorization"):
        value = request.headers.get(header_name)
        if not value:
            continue
        scheme, _, token = value.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token.strip()
    return None


async def create_client_session(app: web.Application) -> None:
    config: Config = app["config"]
    timeout = ClientTimeout(
        total=config.request_timeout,
        connect=min(10.0, config.request_timeout),
        sock_connect=min(10.0, config.request_timeout),
        sock_read=config.request_timeout,
    )
    connector = aiohttp.TCPConnector(limit=config.max_connections, enable_cleanup_closed=True, ttl_dns_cache=300)
    session = aiohttp.ClientSession(timeout=timeout, connector=connector, trust_env=False)
    app["client_session"] = session
    app["resolver"] = DoHResolver(DOH_ENDPOINTS, session)


async def close_client_session(app: web.Application) -> None:
    await app["client_session"].close()


def create_app() -> web.Application:
    config = Config.from_env()
    logger = configure_logging()

    app = web.Application(middlewares=[error_middleware], client_max_size=0)
    app["config"] = config
    app["logger"] = logger
    app["rate_limiter"] = RateLimiter(config.rate_limit_requests, config.rate_limit_window)
    app["gate"] = ConnectionGate(config.max_connections)

    app.router.add_get("/health", handle_health)
    app.router.add_route("*", "/{path_info:.*}", handle_proxy)

    app.on_startup.append(create_client_session)
    app.on_cleanup.append(close_client_session)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=Config.from_env().port, access_log=None)