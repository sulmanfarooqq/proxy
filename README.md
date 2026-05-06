# Anonymous Traffic Proxy

A high-anonymity HTTP/HTTPS proxy with obfuscation features designed to hide your traffic patterns from network observers and prevent fingerprinting.

## Key Features for Anonymity

- **DNS-over-HTTPS Resolution**: Prevents DNS leaks by resolving hostnames through encrypted DoH endpoints
- **Timing Jitter**: Random delays added to mask traffic patterns
- **User Agent Rotation**: Makes traffic appear as various clients
- **No Request Logging**: Zero logging of client activity

## What IP is Hidden

When you configure this proxy and send traffic through it, destination websites see the deployed server's public IP instead of your client IP.

## What Traffic is Protected

Only traffic explicitly configured to use this proxy is protected:

- `curl` requests using `--proxy`
- Apps/scripts configured to use the proxy
- Browser traffic when explicitly configured

## Critical: DNS Leak Prevention

Your applications must be configured to use this proxy for DNS resolution, OR you must use a local DNS-over-HTTPS client. Common DNS leaks happen when:

- Your browser does its own DNS lookups outside the proxy
- Your application ignores system proxy settings for DNS
- Your OS uses default DNS (ISP's DNS servers)

## Security Properties

- Requires bearer token authentication on every request
- Blocks requests to private/internal/reserved destinations
- DNS resolution via encrypted DoH (Cloudflare, Google, OpenDNS)
- Timing jitter to prevent pattern analysis
- No request/response logging
- In-memory rate limiting per client
- Connection limiting and timeouts

## Environment Variables

Required:
- `PROXY_TOKEN`: Long random bearer token (generate with `openssl rand -hex 32`)

Optional:
- `PORT`: Listening port, default `8080`
- `MAX_CONNECTIONS`: Max concurrent connections, default `200`
- `REQUEST_TIMEOUT`: Timeout in seconds, default `30`
- `RATE_LIMIT_REQUESTS`: Max requests per window, default `120`
- `RATE_LIMIT_WINDOW`: Window length seconds, default `60`

## Local Run

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
pip install -r requirements.txt

# Generate secure token
export PROXY_TOKEN="$(openssl rand -hex 32)"
export PORT=8080
python app.py
```

PowerShell:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PROXY_TOKEN = (python -c "import secrets; print(secrets.token_hex(32))")
python app.py
```

## Authentication

Include either header with your token:
```
Proxy-Authorization: Bearer YOUR_TOKEN
```
or
```
Authorization: Bearer YOUR_TOKEN
```

## curl Examples

HTTP request:
```bash
curl \
  --proxy http://localhost:8080 \
  --proxy-header "Proxy-Authorization: Bearer YOUR_TOKEN" \
  http://httpbin.org/ip
```

HTTPS request (CONNECT tunnel):
```bash
curl \
  --proxy http://localhost:8080 \
  --proxy-header "Proxy-Authorization: Bearer YOUR_TOKEN" \
  https://httpbin.org/ip
```

## Docker Deployment

```bash
docker build -t anon-proxy .
docker run -d -p 8080:8080 \
  -e PROXY_TOKEN="$(openssl rand -hex 32)" \
  --restart unless-stopped \
  anon-proxy
```

## Operational Notes

1. **Generate a strong token**: `openssl rand -hex 32`
2. **Use HTTPS in production**: Deploy behind a reverse proxy like Caddy or nginx with TLS
3. **Don't trust for anonymity against nation-state actors**: This provides network-level obfuscation, not perfect anonymity
4. **Combine with Tor**: For serious anonymity, chain this proxy after Tor
5. **Monitor access logs at reverse proxy only**: Don't log requests in this proxy

## Architecture for Maximum Anonymity

For best privacy, deploy this behind a reverse proxy with these additional measures:

1. **Caddy** with automatic HTTPS and no logging
2. Multiple instances behind a load balancer for traffic mixing
3. Different exit IPs for different sessions
4. Consider chaining with Tor for multi-layer obfuscation
