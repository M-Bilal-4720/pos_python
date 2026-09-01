# Islamabad Restaurant & Cafe — Full Restaurant Ordering System

## What's inside
- Customer ordering site with QR table ordering (/)
- POS panel for staff (/pos)
- Kitchen Display panel (/kitchen)
- Admin panel — menu management, QR codes, sales (/admin)
- Bill/receipt printing — A4 and 80mm thermal formats (/bill/<id>)

## Run locally
```
pip install -r requirements.txt
python3 app.py
```
Then open http://localhost:5000

## Important — before going live
1. **Real address/phone**: edit `RESTAURANT` dict at top of `app.py` — phone number is a placeholder.
2. **Online payment**: card/FPX/e-wallet checkout currently SIMULATES payment success
   (see the `# PAYMENT GATEWAY HOOK` comment in `app.py`, function `api_checkout`).
   You need a real Malaysian gateway — Billplz or SenangPay are the easiest to integrate —
   get API keys, create a bill on their API, redirect customer to their payment page,
   and handle their webhook callback to confirm payment. I can wire this in once you
   have an account + API key.
3. **Tax rate**: hardcoded at 6% (SST placeholder) in two places in `app.py` — adjust or remove if not applicable.
4. **Thermal printer**: `/bill/<id>?format=thermal` is print-ready CSS for 80mm rolls.
   Connect it to your physical receipt printer via your browser's print dialog
   (select the thermal printer as destination) or via a print-server app if you want
   silent/automatic printing from POS.
5. **Deployment**: recommend Hetzner VPS (same as your other projects) with gunicorn +
   nginx + systemd service, same pattern as CexBoost/ZeeSocial. Runs on PostgreSQL —
   set `DATABASE_URL` before starting.
6. **Production server**: replace `app.run()` with gunicorn, bound to `127.0.0.1` behind
   your reverse proxy/Cloudflare Tunnel — not `0.0.0.0` — e.g. `gunicorn -w 4 -b 127.0.0.1:8000 app:app`.

## Required environment variables (set these before going live)
| Variable | Purpose |
|---|---|
| `DATABASE_URL` | **Required.** Postgres connection string, e.g. `postgresql://user:pass@localhost:5432/dbname`. The app will not start without it. |
| `SECRET_KEY` | Flask session signing key. Without it, a random key is generated per install and saved to `instance/.secret_key` — fine for local testing, but set an explicit long random value in production. |
| `ADMIN_PIN` | Master PIN staff use to void/modify a bill. Defaults to `1234` if unset — **change this**. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Needed only if you want "Sign in with Google" for customers. Get these from Google Cloud Console. Google login is disabled automatically if unset. |
| `HITPAY_API_KEY` / `HITPAY_SALT` | HitPay payment gateway credentials. `HITPAY_SALT` is required for the webhook to accept payment confirmations — without it the webhook rejects everything (fails closed, doesn't fail open). |
| `HITPAY_SANDBOX` | `true`/`false` — use HitPay's sandbox vs live environment. |
| `SESSION_COOKIE_SECURE` | Defaults to `true` (cookies only sent over HTTPS). Set to `false` only for local HTTP testing if your browser rejects it. |
| `HOST` | Defaults to `127.0.0.1`. Only set to `0.0.0.0` if you specifically need direct LAN/WAN access without going through Cloudflare Tunnel. |

Also update the staff accounts seeded in `app.py` (`STAFF_SEED`) — the default
`admin/admin123`, `manager/manager123`, `staff1/staff123` passwords are public
in this template and must be changed from the Admin panel before going live.

## Menu data
Seeded from your photographed menu (Chicken, Mutton, Beef, Rice, BBQ, Bread, Drinks).
Edit/add/remove items anytime from /admin — no code changes needed.

## QR ordering flow
1. Go to /admin, download each table's QR code.
2. Print and place on tables.
3. Customer scans → lands on `/?table=N` → menu shows "Table N" badge →
   order goes straight into POS + Kitchen as a dine-in order.
