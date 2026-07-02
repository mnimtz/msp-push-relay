# msp-push-relay

Central push notification relay for the **MySecurePrint** iOS app.

Customer-hosted `mysecureprint-server` instances register with the relay and obtain a `relay_token`. From then on they call the relay to deliver APNs pushes — the APNs private key never leaves this server.

## Architecture

```
mysecureprint-server (customer)
        │  POST /api/notify  Bearer {relay_token}
        ▼
  msp-push-relay  (central, Azure Web App)
        │  HTTP/2 + APNs JWT (ES256)
        ▼
  Apple APNs
        │
        ▼
  MySecurePrint iOS App
```

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | — | Liveness check |
| `POST` | `/api/register` | — (rate limited) | Register instance, get relay token |
| `POST` | `/api/notify` | Bearer relay_token | Send push via APNs |

### `POST /api/register`

**Rate limited:** 5 requests per IP per hour.

```json
// Request
{ "instance_url": "https://customer.azurewebsites.net" }

// Response 200
{ "relay_token": "550e8400-e29b-41d4-a716-446655440000" }
```

### `POST /api/notify`

```json
// Request
{
  "device_token": "abc123...hex",
  "title": "Print job ready",
  "body": "Your document is waiting at Printer 3.",
  "data": { "job_id": "42" },
  "environment": "production",
  "collapse_id": "job-42"
}

// Response 200
{ "ok": true }
```

`environment` must be `"production"` or `"sandbox"`. `collapse_id` is optional.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `APNS_KEY_ID` | Yes | Apple APNs key ID (e.g. `ABCDEF1234`) |
| `APNS_TEAM_ID` | Yes | Apple Team ID (e.g. `TEAM123456`) |
| `APNS_PRIVATE_KEY` | Yes | P8 private key contents (full multiline string incl. header/footer) |
| `PORT` | No | Server port (default `8080`) |
| `DB_PATH` | No | SQLite path (default `/data/relay.db`) |

Set `APNS_PRIVATE_KEY` with newlines preserved. In Azure App Service use the "Advanced edit" in Application Settings and paste the raw P8 content.

## Local Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export APNS_KEY_ID=ABCDEF1234
export APNS_TEAM_ID=TEAM123456
export APNS_PRIVATE_KEY="$(cat /path/to/AuthKey_ABCDEF1234.p8)"
export DB_PATH=./relay.db

uvicorn src.main:app --reload --port 8080
```

## Docker

```bash
docker build -t msp-push-relay .
docker run -p 8080:8080 \
  -e APNS_KEY_ID=... \
  -e APNS_TEAM_ID=... \
  -e APNS_PRIVATE_KEY="..." \
  -v $(pwd)/data:/data \
  msp-push-relay
```

## Deployment (Azure Web App)

1. Create an Azure Web App (Linux, Docker container)
2. Point it to `ghcr.io/mnimtz/msp-push-relay:latest`
3. Set all env vars under **Configuration → Application settings**
4. Mount a persistent storage volume to `/data` so the SQLite DB survives restarts
5. GitHub Actions builds and pushes on every push to `main` — restart the Web App to pull the new image

## Versioning

Bump `VERSION` and push to `main`. GitHub Actions tags the image as both `:latest` and `:vX.Y.Z`.
