# ThreatScope AI — Backend

This is the FastAPI backend application for ThreatScope AI, a threat intelligence and malware analysis platform. It handles file/URL scanning submission, coordinates background processing using Redis/RQ, parses Portable Executables, performs static heuristics (including YARA signatures), and generates AI summaries via Ollama.

## Setup & Running

### Using Docker Compose (Recommended)
The simplest way to run the entire backend stack (including PostgreSQL, Redis, MinIO, Ollama, and workers) is using Docker Compose:

1. Copy the environment template:
   ```bash
   cp .env.example .env
   ```
2. Build and run the services:
   ```bash
   docker compose up -d --build
   ```

### Running Locally (Manual Setup)
To run the server natively for local development outside Docker:

1. Install Python 3.11.
2. Install system-level dependencies required for file-type analysis and ssdeep hashing:
   - **Debian/Ubuntu**:
     ```bash
     sudo apt-get update && sudo apt-get install -y libmagic1 libfuzzy-dev gcc build-essential
     ```
   - **macOS**:
     ```bash
     brew install libmagic ssdeep
     ```
   - **Windows**: Installing these libraries natively can be complex. You can use the Dockerized setup, or run the pytest suite (which mocks these interfaces).
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run migrations:
   ```bash
   alembic upgrade head
   ```
5. Start the development server:
   ```bash
   uvicorn app.main:app --reload
   ```

## Running Tests

Tests are executed using `pytest`. 

```bash
python -m pytest
```

### Local Testing & Mocks
To make local test execution easier across different development environments (particularly on platforms like Windows where installing `libmagic1` or `libfuzzy-dev` is difficult), we define automatic mocks in [conftest.py](file:///d:/E%20drive/sandbox/threatscope-backend/tests/conftest.py).

The mock mechanism intercepts imports and function calls for the following libraries:
- `ssdeep`
- `yara` (yara-python)
- `magic` (python-magic)

If you are running the app itself locally outside Docker (using `uvicorn`), you **must** install the system libraries. If you are only running `pytest`, the test suite runs successfully on any OS without native library compilation, thanks to the mock overrides.

---

## Cloud Deployment Guide (Production-Ready)

To take ThreatScope AI from local Docker Compose containers to a resilient, enterprise-ready deployed infrastructure on free-tier services, follow these setup steps:

### 1. Hosted Infrastructure Services
*   **Database (Neon or Supabase)**: Create a free PostgreSQL database. Obtain the connection string (e.g. `postgres://user:pass@host/neondb?sslmode=require`). The backend configuration automatically normalises this URL to use `postgresql+asyncpg://` for asynchronous database pooling.
*   **Redis Cache & Message Queue (Upstash)**: Spawn a free hosted Redis instance. Enable SSL and grab the TLS URL (`rediss://:password@host:port`). The RQ workers use this connection string natively for secure queue handling.
*   **Object Storage (Cloudflare R2)**: Create a Cloudflare R2 bucket. In the Cloudflare console:
    1. Retrieve your R2 API keys (Access Key ID and Secret Access Key).
    2. Retrieve your Account ID endpoint URL (e.g. `https://<account_id>.r2.cloudflarestorage.com`). Set this as `MINIO_ENDPOINT` (without `https://` prefix) and check `MINIO_SECURE=true` in your environment.

### 2. Backend Deployment on Render
We provide a Render blueprint specification at [render.yaml](file:///d:/E%20drive/sandbox/render.yaml) which automatically deploys:
1.  **FastAPI Web Service**: The public-facing endpoint routing scan submissions.
2.  **Default Queue Worker**: An asynchronous worker executing file analyses, entropy assessments, and AI analysis.
3.  **Screenshots Queue Worker**: A specialized worker performing isolated URL scanning.
4.  **YARA Rules Sync Cron**: A daily cron job updating the platform signatures at midnight.

**Steps to Deploy**:
1.  Push the repository to GitHub.
2.  Go to Render -> **Blueprints** -> **New Blueprint Instance**.
3.  Connect this repository. Render will parse `render.yaml` and prompt you to fill the `threatscope-env-group` environment variables.
4.  Input the cloud service credentials and set `CORS_ORIGINS` to allow your deployed Vercel frontend.

### 3. Frontend Deployment on Vercel
1.  Import `threatscope-frontend` to Vercel.
2.  Configure the build framework as **Next.js**.
3.  Add the environment variable:
    *   `NEXT_PUBLIC_API_URL`: Set this to your deployed Render FastAPI Web Service URL (e.g., `https://threatscope-api.onrender.com`).
4.  Deploy. Vercel will build and static-compile the frontend optimized for production.

### 4. Monitoring & Observability (Sentry & UptimeRobot)
*   **Sentry Error Tracking**: Set the `SENTRY_DSN` environment variable on Render (for API and worker services) and `NEXT_PUBLIC_SENTRY_DSN` / `SENTRY_DSN` on Vercel (frontend) to enable automated real-time error reporting and performance tracking.
*   **UptimeRobot Ping Targets**: To monitor API availability and prevent Render's free-tier containers from going to sleep:
    1. Create a free account on [UptimeRobot](https://uptimerobot.com).
    2. Create a new **HTTPS Monitor** targeting your deployed FastAPI health check: `https://<your-render-url>/api/health`.
    3. Set the check interval to **5 minutes**. This automatically pings the service, keeping the backend container warm and monitoring system-wide health (PostgreSQL, Redis, Storage) continuously.

### 5. Incident Response & Security Operations
In the event of a platform abuse incident (e.g. rate-limit bypass attempts, malicious bulk scanning, or credential stuffing):
*   **Audit User Activity**: Query the logs to search for high-frequency submissions matching specific user IDs or API keys. Slowapi logs rate-limit violations with client key identification details.
*   **Enforce User Account Banning**: Administrators can programmatically ban an offending account by hitting the admin endpoint with an admin API key:
    ```bash
    curl -X POST https://<your-render-url>/api/admin/ban \
      -H "x-api-key: <admin-api-key>" \
      -H "Content-Type: application/json" \
      -d '{"email": "attacker@example.com", "is_banned": true}'
    ```
    Once a user is banned, the authentication middleware instantly blocks all subsequent requests from their API keys or JWT sessions with a `403 Forbidden` response before any expensive static scan computations occur.
*   **Revoke API Keys**: If a user's programmatic token has been leaked, set a new value for their `api_key` field in the `users` database table to instantly terminate their access session.



