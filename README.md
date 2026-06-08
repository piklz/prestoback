# PrestoBack 

Self-hosted Docker config backup & restore manager for your Presto Pi stack.
Single Go binary · embedded web UI · no external dependencies.

## Quick start

```bash
cd /home/pi/presto/prestoback
docker compose up -d --build
```

Your **API key** is printed in the container logs on first start:

```bash
docker logs prestoback | grep "API Key"
```

Open **http://your-pi-ip:8765** — paste the key when prompted.

---

## What's new in v3

| Feature | Details |
|---|---|
| **API key auth** | Every endpoint requires `X-API-Key` header. Auto-generated on first run, shown in logs. |
| **Telegram bot** | `/status`, `/backup <name>`, `/history`, `/help`. Inline buttons for one-tap backups. |
| **Discord / Ntfy / Webhook** | Auto-detected by URL shape. Generic JSON POST for anything else. |
| **Scheduled backups** | Per-app cron expressions. Standard 5-field format. |
| **Pin / freeze** | Mark an app to skip scheduled backups without deleting the schedule. |
| **History log** | Persisted audit log of all backup/restore/push events with duration and size. |
| **Proper SSE fan-out** | Multiple browser tabs all receive live updates. |

---

## Telegram setup

1. Message **@BotFather** → `/newbot` → copy the token
2. Message **@userinfobot** → copy your chat ID
3. In PrestoBack UI → Notifications → paste token + chat ID → Save
4. Bot commands: `/status` · `/backup plex` · `/history` · `/help`

---

## Notification channels

| Channel | URL format |
|---|---|
| **Ntfy** | `https://ntfy.sh/your-topic` |
| **Discord** | `https://discord.com/api/webhooks/...` |
| **Gotify** | `https://gotify.example.com/message?token=...` |
| **Custom** | Any URL — receives JSON POST |

---

## API reference

All endpoints require `X-API-Key: <key>` header (or `?api_key=<key>` query param for SSE).

| Method | Path | Description |
|---|---|---|
| GET | `/healthz` | Health check (no auth) |
| GET | `/api/status` | Server info |
| GET | `/api/volumes` | Discover volume directories |
| GET/POST | `/api/apps` | List / add apps |
| GET/PUT/DELETE | `/api/apps/:id` | Get / update / delete app |
| POST | `/api/apps/:id/backup[?remote=id]` | Trigger backup |
| POST | `/api/apps/:id/restore/:backupID` | Restore a backup |
| GET/DELETE | `/api/backups/:appID[/:backupID]` | List / delete backups |
| POST | `/api/backups/:appID/:backupID/push?remote=id` | Push archive to remote |
| GET/POST | `/api/remotes` | List / add remotes |
| DELETE | `/api/remotes/:id` | Remove remote |
| POST | `/api/remotes/:id/test` | Test SSH connectivity |
| GET/PUT | `/api/notify` | Get / update notification settings |
| POST | `/api/notify/test` | Send test notification |
| GET | `/api/history` | Audit log (last 100 events) |
| POST | `/api/apikey/regenerate` | Rotate API key |
| GET | `/api/update/check` | Check for DockerHub update |
| POST | `/api/update/apply` | Apply self-update |
| GET | `/api/events?api_key=` | SSE live event stream |

---

## Upgrading from v2

Your `config.json` and backup archives are fully compatible. Just replace the
container — the new config fields (api_key, notify, schedule) will be added
with safe defaults on first load.

```bash
docker compose down && docker compose up -d --build
# Paste new API key shown in logs
```
