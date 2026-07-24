# Secure Banking App

A Flask-based digital banking application built as a security-focused learning
project. It covers the full lifecycle of a simple retail bank: customer
registration and login (with OTP email verification and password reset),
IBAN-based money transfers, deposits, credit cards, downloadable statements,
and a Security Operations Center (SOC) dashboard for monitoring login
activity, security events, and audit logs.

## Features

- **Customer accounts** — registration, login, "forgot password" flow with
  emailed one-time codes, and an editable profile page.
- **Banking** — open Savings and/or Current accounts, each with its own
  IBAN and credit card; send IBAN-to-IBAN transfers (validated against the
  recipient's name and a daily transfer limit), make deposits, and download
  a CSV account statement.
- **Security Operations Center (SOC)** — a dedicated dashboard for admin
  users to review login history, audit logs, and security events (e.g.
  brute-force lockouts, transfers blocked for exceeding the daily limit).
- **SQLite persistence** — the database schema and seed data are created
  automatically on first run; no separate migration step is required.

## Tech Stack

- **Backend:** Python 3.11+, Flask, Flask-Login, Flask-WTF (CSRF), Flask-Limiter,
  Flask-Talisman
- **Database:** SQLite (file-based, auto-initialized)
- **Frontend:** Jinja2 templates, Bootstrap 5
- **Containerization:** Docker / Docker Compose

## Project Structure

```text
banking_app/
├── app.py            # Application factory and entry point
├── config.py         # Environment-driven configuration
├── db.py             # Schema, queries, and business logic
├── models.py         # Flask-Login user model
├── create_admin.py   # CLI to create/promote an Admin user
├── routes/           # Blueprints: auth, account, banking, support, soc, main
├── templates/        # Jinja2 templates
├── static/           # CSS, JS, and images
└── instance/         # SQLite database file (created automatically)
```

## Getting Started

You can run the app either with Docker (recommended, no local Python setup
required) or directly on your machine.

### 1. Environment Variables

The app reads its configuration from environment variables, most easily
supplied via a `.env` file in the project root. Start by copying the example
file:

```bash
cp .env.example .env
```

`.env.example` (already included in the repo) looks like this:

```env
# Copy this file to .env before running the app.
#   cp .env.example .env

# Required. Any random string works for local/lab use.
SECRET_KEY=dev-secret-change-me

# Set to "true" only once the app is served over HTTPS (e.g. behind a
# reverse proxy in production). Leave "false" for local Docker/lab testing
# over plain http://localhost:5000, otherwise the login session cookie
# will silently fail to be stored by the browser.
SESSION_COOKIE_SECURE=false

# Optional: only needed if you want registration/transfer OTP emails to
# actually be delivered via Gmail SMTP. Leave blank to just read the OTP
# from the app logs during local development.
EMAIL_FROM=no-reply@bank.com
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_USE_TLS=true

# Optional: where "Send Us A Message" contact-form submissions on the
# Support page get forwarded. Defaults to EMAIL_FROM if unset.
SUPPORT_NOTIFICATION_EMAIL=
```

| Variable                     | Required | Description                                                                 |
|--------------------------------|:--------:|-------------------------------------------------------------------------------|
| `SECRET_KEY`                  | Yes      | Flask session/CSRF signing key. Use any random string for local use.         |
| `SESSION_COOKIE_SECURE`       | No       | Set to `true` only when served over HTTPS; keep `false` for local HTTP.      |
| `EMAIL_FROM`                  | No       | "From" address shown on OTP emails.                                          |
| `SMTP_HOST`                   | No       | SMTP server host (e.g. `smtp.gmail.com`) for sending real OTP emails.        |
| `SMTP_PORT`                   | No       | SMTP port (typically `587` for TLS).                                        |
| `SMTP_USERNAME`               | No       | SMTP account username (e.g. your Gmail address).                            |
| `SMTP_PASSWORD`               | No       | SMTP account password (use a Google App Password for Gmail, not your login). |
| `SMTP_USE_TLS`                | No       | Whether to use TLS when connecting to the SMTP server. Defaults to `true`.    |
| `SUPPORT_NOTIFICATION_EMAIL`  | No       | Inbox that contact-form submissions are forwarded to. Defaults to `EMAIL_FROM`. |

If SMTP settings are left blank, the app still runs — OTP codes just won't be
emailed, so check the application logs or on-screen prompts during
registration/transfers instead.

### 2. Run with Docker

**Prerequisites:** Docker Desktop (or Docker Engine) installed and running.

**Option A — Docker Compose (recommended):**

```bash
docker compose up --build
```

This builds the image, mounts the project directory for live code reloads,
and starts the app on [http://localhost:5000](http://localhost:5000).

To stop it, press `Ctrl+C`, or run `docker compose down` from another
terminal.

**Option B — Plain Docker:**

```bash
# Build the image
docker build -t secure-banking-app:latest .

# Run the container, passing your .env file
docker run --env-file .env -p 5000:5000 secure-banking-app:latest
```

> If the app isn't reachable in your browser, confirm the container is
> actually running (`docker ps`) and that nothing else on your machine is
> already bound to port 5000.

**Creating an admin user (Docker):**

The SOC dashboard requires an Admin account. With the container running,
open another terminal and run:

```bash
# Interactive prompts
docker compose exec app python banking_app/create_admin.py

# Or fully non-interactive
docker compose exec app python banking_app/create_admin.py \
  --email admin@bank.com --password "Str0ngPass!" \
  --first-name Ada --last-name Admin \
  --phone "+32 2 555 0100" --address "1 Rue de la Banque, Brussels" \
  --dob 1990-01-01
```

### 3. Run Locally (without Docker)

**Prerequisites:** Python 3.11 or newer.

```bash
# 1. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows (PowerShell/cmd)

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set up environment variables
cp .env.example .env             # then edit .env as needed

# 4. Run the app
python -m banking_app.app
```

The app will be available at [http://localhost:5000](http://localhost:5000).

On Windows, a convenience script is included that activates the virtual
environment (if present) and starts the app in one step:

```powershell
.\run.ps1
```

**Creating an admin user (local):**

```bash
python banking_app/create_admin.py
# or with flags, same as the Docker example above
```

## Database

The app initializes a local SQLite database automatically on first run —
no manual migration step is needed. The database file lives at:

```text
instance/banking.sqlite3
```

This file is created and managed by the app; it's the single source of
truth for all users, accounts, transactions, and security data. Tables
created on startup include:

- `users`, `roles`, `user_roles`
- `accounts`, `credit_cards`, `transactions`, `beneficiaries`
- `notifications`, `login_history`, `audit_logs`, `security_events`

Registration creates a new customer, assigns the `Customer` role, and opens
a default bank account. All login attempts (successful or failed) are
recorded in `login_history`, `audit_logs`, and — where relevant —
`security_events`.

> **Timezone note:** timestamped records (`login_history`, `audit_logs`,
> `security_events`) are stored in Europe/Brussels local time.

To inspect the database manually, open the file with any SQLite browser, or
use the `sqlite3` CLI:

```bash
sqlite3 instance/banking.sqlite3
```

## Email OTP Delivery

Registration and outgoing transfers send a one-time passcode (OTP) to the
customer's email address. To have these actually delivered via Gmail SMTP:

1. Turn on 2-Step Verification on the Google account you want to send from.
2. Create a [Google App Password](https://myaccount.google.com/apppasswords) for Mail.
3. Set the SMTP variables in your `.env` file (see the table above),
   using that App Password as `SMTP_PASSWORD`.
4. Start (or restart) the app.

If SMTP isn't configured, the app still functions for local development —
the OTP is simply not emailed anywhere, so use the app logs to retrieve it.

## Intentional Vulnerability (CTF Disclosure)

This app ships with a deliberate deception layer, **ARGUS**, built for the
Red vs. Blue CTF exercise. It is not a real vulnerability in the banking
app itself — no real user, account, or transaction data is ever exposed by
it — but it's designed to look exactly like one to a Red Team running
reconnaissance:

| Route | What it looks like | What it actually does |
|---|---|---|
| `GET /admin` | An internal admin login panel | Logs the visit as a threat event; any submitted credentials are logged (with password *length* only, never the password itself) and always rejected with a generic "verification required" message |
| `GET /config.json` | A leaked internal config file | Serves fabricated internal hostnames and a fake `database_password` — bait, not a real credential |
| `GET /backup/database.sqlite3` | An exposed database backup | Serves a separate, fully fake SQLite file (`bank_archive_2025.sqlite3`) seeded with realistic but entirely fictional customers, accounts, and transactions |
| `GET /argus/status` | An internal service health check | Confirms the deception engine is active; no real data |

Every interaction with any of these routes is logged with the source IP,
endpoint, method, and a threat score, for the Defensive Analysis / Incident
Response report. See `banking_app/ARGUS_ARCHITECTURE.md` for the full design
rationale.

**Grading note:** this is the one intentional vulnerability for this
exercise. Everything else in the app (real auth, real transfers, real
account data) is the actual, hardened banking application and is not meant
to be discoverable or exploitable.
