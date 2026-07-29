# Corrections to Red Team Exploitation Report

**Reviewing:** `03-exploitation-report.md`
**Reviewed by:** Blue Team 1 (with source-code access to verify ground truth)
**Purpose:** The report shows genuinely good methodology (the statement-download false-alarm test in particular is exactly the right instinct), but it misclassifies several findings because the team didn't have visibility into which routes are wired to the ARGUS honeypot/detection system. This document corrects that, with code evidence.

---

## TL;DR

| Report's claim | Reality |
|---|---|
| Vuln 1 (`config.json`) is an **unintended** real misconfiguration | It's **100% intentional honeypot bait** — a decoy route, logged, threat-scored |
| Vuln 2 (DB backup) is an **unintended** real misconfiguration | It's **100% intentional honeypot bait** — a *separate fake database file*, logged, threat-scored |
| `/admin` SQLi/weak-creds testing = legitimate auth-bypass attempts against a real panel | `/admin` **is also a honeypot decoy** — every attempt was logged with your typed username and password length |
| `/security` is "the" honeypot, correctly avoided | `/security` is real, but is the **least-monitored** trap of the bunch (client-side only, nothing sent to the server). The three routes you actively exploited (`config.json`, backup, `/admin`) are the ones that are actually logged |
| `"internal_api": "/api/internal/accounts"` is a real path to keep hunting for | It's **fictional flavor text** inside the fake config — no such route exists anywhere in the codebase |
| Vuln 6 (2FA bypass via direct DB edit) is a CWE-287 app vulnerability | It's **not an application vulnerability at all** — it required direct database access, which means SSH access to the server, which is a completely different (and more serious) issue than anything the web app itself does wrong |

So: of the "5 found + 1 reported" vulnerabilities, **3 are the intended ones you correctly identified** (Stored XSS, IDOR, non-atomic transfer), **2 are honeypot interactions being misreported as real bugs** (config.json, DB backup), and **1 is out of scope entirely** (the DB-edit "bypass"). Your actual findable-vulnerability count against the real attack surface is **3**, which is exactly right — that's how many are there.

---

## Correction 1 — `config.json` and the DB backup are the honeypot, not real mistakes

Both routes live in `banking_app/routes/admin.py`, in a module explicitly commented as deception infrastructure:

```python
# Deception routes (CTF honeypot: ARGUS) -- see routes/argus.py and
# routes/admin.py.
```

The actual code:

```python
@admin_bp.route("/config.json")
def fake_config():
    record_event(
        event_type="CONFIG_HONEYPOT_ACCESS",
        request=request,
        threat_score=30,
    )
    return jsonify({
        "application": "Bank of Belgium Internal Services",
        "environment": "production",
        "database_host": "db-core.internal.local",
        "database": "customer_accounts",
        "database_user": "svc_backup",
        "database_password": "B0B-Vault-Prod-2026!",
        "internal_api": "/api/internal/accounts",
        "backup_path": "/backup/database.sqlite3",
    })


@admin_bp.route("/backup/database.sqlite3")
def download_honey_database():
    database_path = Path(current_app.root_path).parent / "instance" / "bank_archive_2025.sqlite3"
    record_event(
        event_type="DATABASE_HONEYPOT_DOWNLOAD",
        request=request,
        threat_score=60,
        details={"file": "bank_archive_2025.sqlite3", "exists": database_path.exists()},
    )
    ...
```

Every field in that JSON — the DB password, the host, the user, the "internal API" path — is **fabricated bait**, hand-written into the route. There is no real `svc_backup` account, no real `db-core.internal.local` host. The downloaded file (`bank_archive_2025.sqlite3`) is not a backup of the production database at all — it's a **separate file**, regenerated with deterministic fake data on every app restart (you'll see `"Honey database expanded successfully... Users: 20 Accounts: 20..."` in the container logs on every boot). The real application database is `banking.sqlite3`, which is never exposed by any route.

Your report actually noticed the honeytoken pattern correctly ("the data is fake bait... every `password_hash` is the placeholder `scrypt:fake-honey-password-hash`") — that observation was right. The miss was concluding the *exposure itself* was an accident rather than realizing the fake data was the whole point of the route existing.

**Every single request you made to these two endpoints was logged** with a threat score, visible on `/argus/dashboard` and `/soc`. Your curl-based recon and download were fully captured.

---

## Correction 2 — `/admin` is also a honeypot; your SQLi/creds testing was fully logged

Same file, same pattern:

```python
@admin_bp.route("/admin", methods=["GET", "POST"])
def fake_admin():
    if request.method == "GET":
        record_event(event_type="ADMIN_HONEYPOT_VISIT", request=request, threat_score=20)
        return render_template("admin_login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    record_event(
        event_type="ADMIN_HONEYPOT_LOGIN",
        request=request,
        threat_score=40,
        details={"username": username, "password_length": len(password)},
    )
    return render_template("admin_login.html", error="Additional verification required. Please contact your system administrator."), 401
```

This always returns the same "Additional verification required" message **no matter what you submit** — there is no real authentication logic behind it to bypass. Every one of your tests (`admin'--`, `admin'#`, `admin' or '1'='1'--`, `admin/admin`, `admin/password`, the DB-creds-reuse attempt) was recorded as an `ADMIN_HONEYPOT_LOGIN` event, with your submitted username and password length logged. Your "Failed — same wall" observations were correct in the sense that there was never anything to actually break through.

**Net effect:** three of your test targets (`config.json`, the DB backup, `/admin`) generated honeypot detections. Worth pulling up `/argus/dashboard` and `/soc` together with Blue Team to see the full timeline of what got logged.

---

## Correction 3 — `/security` is real, but it's the *quietest* trap, not "the" honeypot

`/security` is a legitimate honeypot page, but structurally different from the other three: it's a static demo page with client-side-only "gotchas." Checked directly in the template — the fake "decoy file" clicks and the fake admin-login button never make a network request at all:

```javascript
document.querySelectorAll('.honeypot-item').forEach(function (item) {
    item.addEventListener('click', function () {
        item.style.borderColor = 'var(--danger)';
        item.innerHTML += ' 🚨';
    });
});
```

That's a pure DOM style change — nothing is sent to the server, so nothing lands in `security_events` or ARGUS from interacting with it. Your instinct to leave it alone was good practice regardless, but it's worth knowing that avoiding it didn't actually avoid detection — the detection was on the other three routes you did test.

---

## Correction 4 — `"internal_api": "/api/internal/accounts"` doesn't exist; stop looking for it

This string is hardcoded directly into the `fake_config()` JSON shown above — it's flavor text, written by hand as bait, exactly like the fake password. Confirmed by searching the entire codebase:

```
$ grep -rn "api/internal" banking_app --include="*.py"
banking_app/routes/admin.py:74:    "internal_api": "/api/internal/accounts",
```

That's the only occurrence in the whole project — it's a string literal inside a `jsonify()` call, not a registered route anywhere. The 404 you got is expected and final; there's no real endpoint hiding elsewhere for this specific lead. (There may of course be other undiscovered surface in the app — just not down this particular thread.)

---

## Correction 5 — Vuln 6 (2FA bypass) is out of scope, not an app vulnerability

This is the important one. The report states the bypass was achieved by *"setting it manually in the database"* — i.e., your teammate had direct write access to the SQLite database. That is not something the web application exposes to a normal attacker; it means they had **filesystem or SSH access to the server itself**, separate from anything the Flask app does or doesn't validate.

To be concrete about why this matters: once someone can execute arbitrary SQL against the app's database directly, they aren't testing the application anymore — they can already do anything (set `is_active=1`, grant themselves the Admin role, rewrite any balance, dump every password hash *for real* if they wanted). Reporting "I flipped `email_verified` in the database" as an app-level CWE-287 finding is a bit like reporting "I have root on the box, therefore I can read any file" as a file-permissions bug in one specific application — technically true, but it's describing the access level, not a flaw in the app's logic. The app's actual server-side check (`authenticate_user()` in `db.py`) *does* enforce `email_verified` on every login attempt, with no client-supplied way to skip it through the web interface.

**Recommendation:** pull this finding from the report, or reclassify it clearly as "infrastructure access, not an application vulnerability," and separately flag to your coach *how* that database access was obtained. If it was via the shared server SSH credential handed out in the onboarding guide (`hamilton` / a shared password) for lab setup purposes, that credential being usable by Red Team is the actual issue worth raising — it gives blanket access that makes every other finding in this category moot. That's a scoping/access-control problem for the exercise organizers, not something `authenticate_user()` needs to be patched against.

---

## Correction 6 — the `<script>` vs `<img onerror>` distinction, precisely

Small clarification on Vuln 3's mechanics, since the report's wording ("the app blocks the obvious `<script>` tag") implies the *application* is filtering input. It isn't — confirmed in `account.py`, the description field is stored completely as-is with **no sanitization of any kind**:

```python
# [CTF-VULN #2] The description below is stored as-is (no sanitization
# -- that's intentional) and later rendered unescaped
```

What actually stopped `<script>alert(1)</script>` from firing is almost certainly the site's Content-Security-Policy (`script-src 'self' https://cdn.jsdelivr.net 'nonce-...'`, no `'unsafe-inline'`) — a **browser-side** defense-in-depth layer, not application-side input filtering. The payload is still stored and rendered completely unescaped in the page HTML (verifiable via View Source); the CSP is what refuses to *execute* an unnonced inline script. This is a meaningful distinction for the report: the vulnerability (unsanitized stored input reflected as raw HTML) is fully present regardless of what the CSP blocks.

One more thing worth double-checking on your end: the SOC's XSS detector matches on more than the `<script>` tag —

```python
re.search(r"<script|onerror\s*=|onload\s*=|javascript:|<iframe|<img[^>]+onerror", description, re.IGNORECASE)
```

— so your `<img src=x onerror=...>` payload should have generated a `Stored XSS Payload Detected` event (High severity) regardless of whether it visually executed. Worth confirming on `/soc` that it's there; if it's not, that's a genuine detection gap worth its own line item.

---

## Suggested revised summary table

| # | Item | Correct classification |
|---|---|---|
| 1 | Stored XSS (transfer description) | **Confirmed real vulnerability** — intended, correctly exploited |
| 2 | IDOR on `/accounts/<id>` | **Confirmed real vulnerability** — intended, correctly exploited, methodology (A/B swap test) was solid |
| 3 | Non-atomic transfer (self-credit) | **Confirmed real vulnerability** — intended, correctly exploited |
| 4 | `config.json` exposure | Honeypot interaction — recon successfully located and engaged the trap |
| 5 | DB backup download | Honeypot interaction — recon successfully located and downloaded the trap |
| — | `/admin` SQLi / weak creds / cred reuse | Honeypot interaction — no real auth logic present to bypass |
| — | 2FA/email-verification "bypass" | **Out of scope** — required direct DB/server access, not a web-app finding |

Your statement-download false-alarm ruling-out (§10) and your restraint around `/security` (§11) both show the right process — this correction is really just about connecting those same instincts to the other three honeypot routes you didn't realize were also traps.
