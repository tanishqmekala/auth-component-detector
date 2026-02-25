# Auth Component Detector
**AI Engineer Technical Assessment — Tanishq Mekala**
[linkedin.com/in/tanishqmekala](https://www.linkedin.com/in/tanishqmekala/)

---

## What This Does

A **web application** that scrapes any website using a real headless browser and detects login/authentication components from the live HTML — including login forms, password input fields, OAuth buttons, SSO links, and auth containers.

Covers all assessment requirements:
- Scrapes 5 websites and extracts HTML markup
- Dynamic URL input via UI — scan any site on demand
- Returns the actual HTML snippet of each auth component found
- Deployed live on Railway (see link above)

---

## Live Demo

Deployed on Railway — accessible directly in the browser, no setup needed.

---

## Run Locally (3 steps)

### Step 1 — Install Python dependencies
```bash
pip install -r requirements.txt
```

### Step 2 — Install the headless browser (one-time)
```bash
playwright install chromium
```

### Step 3 — Start the app
```bash
python app.py
```

Open **http://localhost:5000** in your browser.

> Python 3.8+ required.

---

## Deploy on Railway (from scratch)

### Prerequisites
- A [Railway](https://railway.app) account (free, sign up with GitHub)
- [Git](https://git-scm.com) installed

### Step 1 — Create a GitHub repo and push the code

```bash
git init
git add .
git commit -m "initial commit"
```

Go to [github.com/new](https://github.com/new), create a new repository, then:

```bash
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
git branch -M main
git push -u origin main
```

### Step 2 — Deploy on Railway

1. Go to [railway.app](https://railway.app) and log in
2. Click **New Project → Deploy from GitHub repo**
3. Select your repository
4. Railway auto-detects Python and uses `nixpacks.toml` to install Chromium
5. Wait ~3 minutes for the build to complete
6. Click **Settings → Networking → Generate Domain** to get your public URL

That's it — your app is live.

---

## How to Use

**Scan any URL:** Paste any website URL into the input box and click Scan URL.

**Scan 5 demo sites at once:** Click "Scan 5 Demo Sites" for a full summary dashboard.

**Quick chips:** Click GitHub, LinkedIn, Facebook, Salesforce, or StackOverflow to instantly scan that site.

---

## Pre-loaded Demo Sites

| Site | URL |
|------|-----|
| GitHub | github.com/login |
| LinkedIn | linkedin.com/login |
| Facebook | facebook.com/login |
| Salesforce | login.salesforce.com |
| StackOverflow | stackoverflow.com/users/login |

---

## How the Detection Engine Works

5-layer approach to handle all the different ways sites structure their login UI:

```
Layer 1 → Find <input type="password"> then walk up to parent <form>
Layer 2 → Find <form> tags with auth keywords in id / class / action
Layer 3 → Find <div>/<section> containers with auth keywords + inputs
Layer 4 → Find OAuth/SSO buttons (e.g. "Sign in with Google")
Layer 5 → Find <a> links pointing to /login, /auth/, /sso endpoints
```

Keywords checked: `login, signin, auth, username, password, email, oauth, sso, credentials`

---

## Why Playwright Instead of requests?

Modern sites like LinkedIn, Facebook, and Salesforce render login forms via JavaScript (React/SPA). A plain HTTP request returns the page before JS runs — the login form doesn't exist yet in the response.

Playwright launches a real headless Chromium browser, waits for full JS rendering, then captures the complete DOM. This is what a real user's browser does.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3, Flask |
| Scraping | Playwright (headless Chromium) |
| Parsing | BeautifulSoup4 |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Deployment | Railway |

---

## Project Files

```
app.py            ← Complete application (Flask backend + animated frontend)
requirements.txt  ← Python dependencies
nixpacks.toml     ← Railway build config (installs Chromium on the server)
Procfile          ← Start command for Railway
runtime.txt       ← Pins Python 3.11
README.md         ← This file
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | / | Web UI |
| POST | /api/scan | Scan one URL. Body: `{"url": "https://..."}` |
| GET | /api/scan-defaults | Scan all 5 demo sites |

### Example
```bash
curl -X POST https://YOUR-APP.railway.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/login"}'
```

---

## Troubleshooting

**playwright install chromium fails locally:**
Try `python -m playwright install chromium`

**Port 5000 in use:**
`PORT=8080 python app.py`

**Facebook/some sites show no results:**
Some sites have aggressive bot detection. GitHub, LinkedIn, and Salesforce give the most reliable results.

---

## Author

**Tanishq Mekala**
[linkedin.com/in/tanishqmekala](https://www.linkedin.com/in/tanishqmekala/)
