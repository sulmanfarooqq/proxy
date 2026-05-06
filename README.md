# Secure Authenticated Python HTTP/HTTPS Proxy

This service is a bearer-token authenticated HTTP proxy built with `aiohttp`. It supports:

- HTTP proxying
- HTTPS `CONNECT` tunneling
- WebSocket proxying for `ws://` and `wss://` traffic when the client speaks proxy-compatible WebSocket requests

It is designed for deployment on Render or Railway and is intentionally **not** an open proxy.

## What IP is hidden

When a client explicitly configures this proxy and sends traffic through it, destination websites see the **deployed server's public IP** instead of the client's public IP.

## What traffic is protected

Only traffic explicitly configured to use this proxy is routed through it, such as:

- `curl` requests using `--proxy`
- apps or scripts configured to use an HTTP/HTTPS proxy
- browser traffic only when the browser is explicitly configured to use this proxy

## What is not protected

This is **not** a full VPN and does not automatically protect all device traffic.

It does **not**:

- protect apps that are not configured to use the proxy
- hide browser fingerprinting characteristics
- prevent websites from linking activity through account logins
- guarantee anonymity
- stop DNS leaks for apps/browsers that do their own DNS resolution outside the proxy path
- protect traffic outside the proxy-aware application

## Why WireGuard on a VPS is better for real VPN protection

If you need device-wide protection, use WireGuard on a VPS instead of an HTTP proxy. WireGuard is better because it:

- routes all selected device traffic through the tunnel
- protects non-browser and non-proxy-aware apps
- reduces accidental DNS leakage when configured correctly
- is a better fit for full-device privacy and network path control

An HTTP proxy is narrower: it only covers traffic that the client intentionally sends through it.

## Security properties

This proxy:

- requires a bearer token on every proxied request
- rejects unauthenticated requests
- blocks requests to private/internal/reserved destinations
- streams request and response bodies instead of buffering full payloads in memory
- applies in-memory rate limiting per client IP and token
- enforces connection limits and timeouts
- exposes a safe `/health` endpoint
- avoids logging query strings, authorization headers, cookies, or request bodies

## Environment variables

Required:

- `PROXY_TOKEN`: shared bearer token

Supported:

- `PORT`: listening port, default `8080`
- `MAX_CONNECTIONS`: maximum concurrent upstream connections, default `200`
- `REQUEST_TIMEOUT`: upstream timeout in seconds, default `30`

Optional tuning:

- `RATE_LIMIT_REQUESTS`: max requests per window, default `120`
- `RATE_LIMIT_WINDOW`: window length in seconds, default `60`

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PROXY_TOKEN="replace-with-a-long-random-token"
export PORT=8080
python app.py
```

PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PROXY_TOKEN="replace-with-a-long-random-token"
$env:PORT="8080"
python app.py
```

## Authentication

Send either:

- `Proxy-Authorization: Bearer <token>`
- or `Authorization: Bearer <token>`

Use `Proxy-Authorization` where possible because it matches normal proxy behavior.

## curl examples

HTTP request through the proxy:

```bash
curl \
  --proxy https://your-render-or-railway-host \
  --proxy-header "Proxy-Authorization: Bearer YOUR_TOKEN" \
  http://httpbin.org/ip
```

HTTPS request through a `CONNECT` tunnel:

```bash
curl \
  --proxy https://your-render-or-railway-host \
  --proxy-header "Proxy-Authorization: Bearer YOUR_TOKEN" \
  https://httpbin.org/ip
```

If your deployment terminates TLS at the platform and exposes an HTTPS URL, use the platform URL as the proxy endpoint. `curl` will use `CONNECT` for HTTPS destinations.

## Render deployment

1. Create a new Web Service from this repository.
2. Set the runtime to Docker, or use:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python app.py`
3. Set environment variables:
   - `PROXY_TOKEN`: a long random token
   - `MAX_CONNECTIONS`: for example `200`
   - `REQUEST_TIMEOUT`: for example `30`
4. Render will provide `PORT` automatically.
5. Deploy and test:

```bash
curl https://YOUR_RENDER_HOST/health
```

## Railway deployment

1. Create a new project from this repository.
2. Deploy using the included `Dockerfile`, or configure:
   - Start Command: `python app.py`
3. Add environment variables:
   - `PROXY_TOKEN`
   - `MAX_CONNECTIONS`
   - `REQUEST_TIMEOUT`
4. Railway will provide `PORT` automatically.
5. After deploy, test:

```bash
curl https://YOUR_RAILWAY_HOST/health
```

## Operational notes

- Use a long random token, not a guessable string.
- Prefer HTTPS platform endpoints so clients authenticate over TLS.
- Do not disable the private/internal address blocking.
- Do not trust this for anonymity against sophisticated tracking.
- In-memory rate limiting is per instance. If you scale horizontally, limits are not shared across instances.
