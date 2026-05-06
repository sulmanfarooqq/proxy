import asyncio
import ipaddress
import logging
import os
import random
import secrets
import socket
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from http import HTTPStatus
from typing import AsyncIterator
from urllib.parse import urlsplit, urlunsplit

import dns.asyncquery
import dns.exception
import dns.message
import dns.rdatatype

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
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

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

DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://doh.opendns.com/dns-query",
]

MAX_HEADER_BYTES = 64 * 1024


@dataclass(frozen=True)
class Config:
    port: int
    proxy_token: str
    max_connections: int
    request_timeout: float
    rate_limit_requests: int
    rate_limit_window: int

    @classmethod
    def from_env(cls) -> "Config":
        proxy_token = os.getenv("PROXY_TOKEN", "").strip()
        if not proxy_token:
            proxy_token = secrets.token_urlsafe(32)
            print(
                "WARNING: PROXY_TOKEN was not set. Generated an ephemeral token for this deployment.",
                flush=True,
            )

        return cls(
            port=int(os.getenv("PORT", "8080")),
            proxy_token=proxy_token,
            max_connections=max(1, int(os.getenv("MAX_CONNECTIONS", "200"))),
            request_timeout=max(1.0, float(os.getenv("REQUEST_TIMEOUT", "30"))),
            rate_limit_requests=max(1, int(os.getenv("RATE_LIMIT_REQUESTS", "120"))),
            rate_limit_window=max(1, int(os.getenv("RATE_LIMIT_WINDOW", "60"))),
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
    def __init__(self, endpoints: list[str]) -> None:
        self.endpoints = endpoints
        self._cache: dict[str, list[str]] = {}
        self._cache_times: dict[str, float] = {}
        self._ttl = 300
        self._doh_timeout = 2.0

    async def resolve_hostname(
        self, hostname: str, family: socket.AddressFamily = socket.AF_UNSPEC
    ) -> list[str]:
        try:
            ipaddress.ip_address(hostname)
            return [hostname]
        except ValueError:
            pass

        cache_key = f"{hostname}:{family}"
        if cache_key in self._cache and time.time() - self._cache_times.get(cache_key, 0) < self._ttl:
            return self._cache[cache_key]

        if family == socket.AF_INET:
            qtypes = ["A"]
        elif family == socket.AF_INET6:
            qtypes = ["AAAA"]
        else:
            qtypes = ["A", "AAAA"]

        answers = await self._resolve_via_doh(hostname, qtypes)
        if answers:
            self._cache[cache_key] = answers
            self._cache_times[cache_key] = time.time()
            return answers

        fallback_ip = await self._system_resolve(hostname, family=family)
        self._cache[cache_key] = [fallback_ip]
        self._cache_times[cache_key] = time.time()
        return [fallback_ip]

    async def _resolve_via_doh(self, hostname: str, qtypes: list[str]) -> list[str]:
        tasks = [
            asyncio.create_task(self._query_endpoint(hostname, endpoint, qtype))
            for endpoint in self.endpoints
            for qtype in qtypes
        ]
        try:
            for future in asyncio.as_completed(tasks, timeout=self._doh_timeout):
                answers = await future
                if answers:
                    return answers
        except TimeoutError:
            return []
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        return []

    async def _query_endpoint(self, hostname: str, endpoint: str, qtype: str) -> list[str]:
        try:
            query = dns.message.make_query(hostname, qtype)
            response = await dns.asyncquery.https(query, endpoint, timeout=self._doh_timeout)
        except (dns.exception.DNSException, OSError, TimeoutError):
            return []

        answers: list[str] = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.from_text(qtype):
                answers.extend(record.address for record in rrset)
        return answers

    async def _system_resolve(
        self, hostname: str, family: socket.AddressFamily = socket.AF_UNSPEC
    ) -> str:
        loop = asyncio.get_running_loop()
        try:
            addrinfo = await loop.getaddrinfo(hostname, None, family=family, type=socket.SOCK_STREAM)
            return addrinfo[0][4][0]
        except socket.gaierror as exc:
            raise ProxyError(502, "Unable to resolve destination") from exc


class BufferedReader:
    def __init__(self, reader: asyncio.StreamReader, initial: bytes = b"") -> None:
        self.reader = reader
        self.buffer = bytearray(initial)

    async def read(self, n: int = -1) -> bytes:
        if n == -1:
            chunks = [bytes(self.buffer)] if self.buffer else []
            self.buffer.clear()
            while True:
                chunk = await self.reader.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)

        if self.buffer:
            chunk = bytes(self.buffer[:n])
            del self.buffer[:n]
            if len(chunk) == n:
                return chunk
            return chunk + await self.reader.read(n - len(chunk))
        return await self.reader.read(n)

    async def readexactly(self, n: int) -> bytes:
        if len(self.buffer) >= n:
            chunk = bytes(self.buffer[:n])
            del self.buffer[:n]
            return chunk

        prefix = bytes(self.buffer)
        self.buffer.clear()
        return prefix + await self.reader.readexactly(n - len(prefix))

    async def readline(self) -> bytes:
        newline_index = self.buffer.find(b"\n")
        if newline_index >= 0:
            index = newline_index + 1
            line = bytes(self.buffer[:index])
            del self.buffer[:index]
            return line

        prefix = bytes(self.buffer)
        self.buffer.clear()
        return prefix + await self.reader.readline()


def configure_logging() -> logging.Logger:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "ERROR"),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    return logging.getLogger("anon_proxy")


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


def sanitize_target(target: str) -> str:
    parts = urlsplit(target) if "://" in target else urlsplit("http://" + target)
    safe_path = parts.path or "/"
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme or "http", netloc, safe_path, parts.query, ""))


def build_forward_target(target: str, headers: list[tuple[str, str]]) -> str:
    if "://" in target:
        return sanitize_target(target)

    host = get_header(headers, "Host")
    if not host:
        raise ProxyError(400, "Missing target host")
    return sanitize_target(f"http://{host}{target}")


def extract_bearer_token(headers: list[tuple[str, str]]) -> str | None:
    for header_name in ("Proxy-Authorization", "Authorization"):
        value = get_header(headers, header_name)
        if not value:
            continue
        scheme, _, token = value.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token.strip()
    return None


def get_header(headers: list[tuple[str, str]], name: str) -> str | None:
    name_lower = name.lower()
    for key, value in reversed(headers):
        if key.lower() == name_lower:
            return value
    return None


def get_client_ip(headers: list[tuple[str, str]], writer: asyncio.StreamWriter) -> str:
    forwarded_for = get_header(headers, "X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return "unknown"


def is_health_request(method: str, target: str) -> bool:
    if method != "GET":
        return False
    parts = urlsplit(target) if "://" in target else None
    path = parts.path if parts else target.split("?", 1)[0]
    return path == "/health"


def build_response(status: int, body: bytes, headers: dict[str, str] | None = None) -> bytes:
    reason = HTTPStatus(status).phrase
    merged_headers = {
        "Content-Length": str(len(body)),
        "Connection": "close",
        **(headers or {}),
    }
    header_blob = "".join(f"{key}: {value}\r\n" for key, value in merged_headers.items())
    return (
        f"HTTP/1.1 {status} {reason}\r\n{header_blob}\r\n".encode("latin1")
        + body
    )


async def send_json(
    writer: asyncio.StreamWriter,
    status: int,
    payload: str,
    headers: dict[str, str] | None = None,
) -> None:
    body = payload.encode("utf-8")
    response_headers = {"Content-Type": "application/json; charset=utf-8"}
    if headers:
        response_headers.update(headers)
    writer.write(build_response(status, body, response_headers))
    await writer.drain()


async def read_request_head(reader: asyncio.StreamReader, timeout: float) -> tuple[str, str, str, list[tuple[str, str]], bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        if not chunk:
            raise ProxyError(400, "Invalid request")
        data.extend(chunk)
        if len(data) > MAX_HEADER_BYTES:
            raise ProxyError(431, "Request headers too large")

    head, remainder = bytes(data).split(b"\r\n\r\n", 1)
    try:
        lines = head.decode("latin1").split("\r\n")
        method, target, version = lines[0].split(" ", 2)
    except ValueError as exc:
        raise ProxyError(400, "Invalid request line") from exc

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ProxyError(400, "Invalid request header")
        key, value = line.split(":", 1)
        headers.append((key.strip(), value.lstrip()))
    return method, target, version, headers, remainder


async def resolve_public_ips(
    resolver: DoHResolver, hostname: str, family: socket.AddressFamily = socket.AF_UNSPEC
) -> list[str]:
    resolved_ips = await resolver.resolve_hostname(hostname, family=family)
    public_ips = []
    for resolved_ip in resolved_ips:
        ip = ipaddress.ip_address(resolved_ip)
        if not is_blocked_ip(ip):
            public_ips.append(resolved_ip)
    if not public_ips:
        raise ProxyError(403, "Destination IP is not allowed")
    return public_ips


def filter_outbound_headers(headers: list[tuple[str, str]], host_header: str) -> list[tuple[str, str]]:
    clean_headers: list[tuple[str, str]] = []
    seen = set()
    for key, value in headers:
        key_lower = key.lower()
        if key_lower in HOP_BY_HOP_HEADERS:
            continue
        if key_lower == "host":
            continue
        clean_headers.append((key, value))
        seen.add(key_lower)

    clean_headers.append(("Host", host_header))
    if "user-agent" not in seen:
        clean_headers.append(("User-Agent", random.choice(OBFUSCATION_USER_AGENTS)))
    if "accept" not in seen:
        clean_headers.append(("Accept", "*/*"))
    if "accept-language" not in seen:
        clean_headers.append(("Accept-Language", "en-US,en;q=0.9"))
    clean_headers.append(("Connection", "close"))
    return clean_headers


def format_headers(headers: list[tuple[str, str]]) -> bytes:
    return b"".join(f"{key}: {value}\r\n".encode("latin1") for key, value in headers)


async def relay_exact_bytes(
    source: BufferedReader,
    destination: asyncio.StreamWriter,
    total_bytes: int,
    timeout: float,
) -> None:
    remaining = total_bytes
    while remaining > 0:
        chunk = await asyncio.wait_for(source.read(min(65536, remaining)), timeout=timeout)
        if not chunk:
            raise ProxyError(400, "Client closed request body early")
        destination.write(chunk)
        await destination.drain()
        remaining -= len(chunk)


async def relay_chunked_body(
    source: BufferedReader,
    destination: asyncio.StreamWriter,
    timeout: float,
) -> None:
    while True:
        line = await asyncio.wait_for(source.readline(), timeout=timeout)
        if not line:
            raise ProxyError(400, "Invalid chunked request body")
        destination.write(line)
        await destination.drain()

        chunk_size = int(line.split(b";", 1)[0].strip(), 16)
        if chunk_size == 0:
            while True:
                trailer = await asyncio.wait_for(source.readline(), timeout=timeout)
                if not trailer:
                    raise ProxyError(400, "Invalid chunked trailer")
                destination.write(trailer)
                await destination.drain()
                if trailer == b"\r\n":
                    return

        chunk = await asyncio.wait_for(source.readexactly(chunk_size + 2), timeout=timeout)
        destination.write(chunk)
        await destination.drain()


async def pipe_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: float,
) -> None:
    while True:
        chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        if not chunk:
            break
        writer.write(chunk)
        await writer.drain()


class ProxyServer:
    def __init__(self, config: Config, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.rate_limiter = RateLimiter(config.rate_limit_requests, config.rate_limit_window)
        self.gate = ConnectionGate(config.max_connections)
        self.resolver = DoHResolver(DOH_ENDPOINTS)

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            method, target, version, headers, remainder = await read_request_head(
                reader, self.config.request_timeout
            )

            if is_health_request(method, target):
                await send_json(writer, 200, '{"status": "ok"}')
                return

            token = extract_bearer_token(headers)
            if not token or not secrets.compare_digest(token, self.config.proxy_token):
                await send_json(
                    writer,
                    407,
                    '{"error": "Authentication required"}',
                    headers={"Proxy-Authenticate": "Bearer"},
                )
                return

            client_ip = get_client_ip(headers, writer)
            if not await self.rate_limiter.allow(client_ip):
                await send_json(writer, 429, '{"error": "Rate limit exceeded"}')
                return

            async with self.gate.acquire():
                if method.upper() == "CONNECT":
                    await self.handle_connect(target, headers, reader, writer)
                else:
                    await self.handle_forward(method, target, version, headers, remainder, reader, writer)
        except ProxyError as exc:
            try:
                await send_json(writer, exc.status, f'{{"error": "{exc.message}"}}', headers=exc.headers)
            except Exception:
                pass
        except Exception:
            self.logger.exception("Unhandled proxy error")
            with suppress(Exception):
                await send_json(writer, 500, '{"error": "Internal error"}')
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    async def handle_forward(
        self,
        method: str,
        target: str,
        version: str,
        headers: list[tuple[str, str]],
        remainder: bytes,
        reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        upstream_target = build_forward_target(target, headers)
        parts = urlsplit(upstream_target)
        if parts.scheme not in {"http"}:
            raise ProxyError(400, "Unsupported target scheme")
        if not parts.hostname:
            raise ProxyError(400, "Invalid target URL")

        upstream_port = parts.port or 80
        upstream_host = parts.hostname
        upstream_ip = (await resolve_public_ips(self.resolver, upstream_host))[0]

        await asyncio.sleep(random.uniform(0.01, 0.05))

        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(upstream_ip, upstream_port),
                timeout=self.config.request_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ProxyError(504, "Upstream connection timed out") from exc
        except OSError as exc:
            raise ProxyError(502, "Failed to contact upstream") from exc

        body_reader = BufferedReader(reader, remainder)
        path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        host_header = parts.netloc or upstream_host
        outbound_headers = filter_outbound_headers(headers, host_header)

        try:
            request_head = (
                f"{method} {path} {version}\r\n".encode("latin1")
                + format_headers(outbound_headers)
                + b"\r\n"
            )
            upstream_writer.write(request_head)
            await upstream_writer.drain()

            transfer_encoding = (get_header(headers, "Transfer-Encoding") or "").lower()
            content_length = get_header(headers, "Content-Length")

            if transfer_encoding == "chunked":
                await relay_chunked_body(body_reader, upstream_writer, self.config.request_timeout)
            elif content_length is not None:
                await relay_exact_bytes(
                    body_reader,
                    upstream_writer,
                    int(content_length),
                    self.config.request_timeout,
                )

            await pipe_stream(upstream_reader, client_writer, self.config.request_timeout)
        finally:
            upstream_writer.close()
            with suppress(Exception):
                await upstream_writer.wait_closed()

    async def handle_connect(
        self,
        target: str,
        headers: list[tuple[str, str]],
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        connect_target = target
        if ":" not in connect_target:
            connect_target = get_header(headers, "Host") or ""
        if ":" not in connect_target:
            raise ProxyError(400, "CONNECT target must be host:port")

        host, port_text = connect_target.rsplit(":", 1)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ProxyError(400, "Invalid CONNECT port") from exc
        if port < 1 or port > 65535:
            raise ProxyError(400, "Invalid CONNECT port")

        target_ip = (await resolve_public_ips(self.resolver, host))[0]

        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=self.config.request_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise ProxyError(504, "Upstream connection timed out") from exc
        except OSError as exc:
            raise ProxyError(502, "Failed to establish upstream connection") from exc

        client_writer.write(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
        await client_writer.drain()

        try:
            client_to_upstream = asyncio.create_task(
                pipe_stream(client_reader, upstream_writer, self.config.request_timeout)
            )
            upstream_to_client = asyncio.create_task(
                pipe_stream(upstream_reader, client_writer, self.config.request_timeout)
            )
            done, pending = await asyncio.wait(
                {client_to_upstream, upstream_to_client},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                task.result()
        finally:
            upstream_writer.close()
            with suppress(Exception):
                await upstream_writer.wait_closed()


async def main() -> None:
    config = Config.from_env()
    logger = configure_logging()
    server = ProxyServer(config, logger)

    listener = await asyncio.start_server(
        server.handle_client,
        host="0.0.0.0",
        port=config.port,
        limit=65536,
    )

    async with listener:
        await listener.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
