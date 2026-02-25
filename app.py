"""
Auth Component Detector
-----------------------
A web app that scrapes websites and detects login/authentication components.
Run this file and open http://localhost:5000 in your browser.

Usage:
    pip install flask requests beautifulsoup4 playwright
    playwright install chromium
    python app.py
"""

from flask import Flask, request, jsonify
from bs4 import BeautifulSoup, Comment
import requests as http_requests
from urllib.parse import urlparse
import re
import time

app = Flask(__name__)


# ============================================================
#  AUTH DETECTION ENGINE
# ============================================================

AUTH_KEYWORDS = [
    'login', 'log-in', 'log_in', 'signin', 'sign-in', 'sign_in',
    'auth', 'authenticate', 'credentials', 'sso', 'oauth',
    'username', 'user-name', 'user_name', 'userid',
    'password', 'passwd', 'passcode',
    'email', 'e-mail',
]

AUTH_INPUT_NAMES = [
    'username', 'user', 'login', 'email', 'password', 'passwd',
    'pass', 'user_name', 'user_email', 'user_login',
    'session[email]', 'session[password]', 'credentials',
]

DEFAULT_SITES = [
    'https://github.com/login',
    'https://www.linkedin.com/login',
    'https://www.facebook.com/login',
    'https://login.salesforce.com/',
    'https://login.twitter.com/i/flow/login',
]


def fetch_html(url, timeout=15):
    import os
    from playwright.sync_api import sync_playwright

    # On Railway/Linux, use the system-installed Chromium
    # On local Mac/Windows, Playwright uses its own downloaded browser
    system_chromium = '/usr/bin/chromium'
    use_system = os.path.exists(system_chromium)

    with sync_playwright() as p:
        launch_kwargs = {
            'headless': True,
            'args': [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--no-first-run',
                '--no-zygote',
                '--single-process',
                '--disable-extensions',
            ]
        }
        if use_system:
            launch_kwargs['executable_path'] = system_chromium

        browser = p.chromium.launch(**launch_kwargs)
        context = browser.new_context(
            user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            viewport={'width': 1280, 'height': 800},
            locale='en-US',
        )
        page = context.new_page()
        page.goto(url, wait_until='load', timeout=timeout * 1000)
        page.wait_for_timeout(2000)
        html = page.content()
        browser.close()
    return html, 200


def check_attr_match(tag, keywords):
    attrs_to_check = ['id', 'class', 'name', 'action', 'aria-label',
                      'placeholder', 'data-testid', 'role', 'for', 'type']
    for attr in attrs_to_check:
        val = tag.get(attr, '')
        if isinstance(val, list):
            val = ' '.join(val)
        val_lower = val.lower()
        for kw in keywords:
            if kw in val_lower:
                return True
    return False


def detect_auth_components(html):
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup.find_all(['script', 'style', 'noscript']):
        tag.decompose()
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        comment.extract()

    components = []
    seen = set()

    def add(comp_type, element, context):
        snippet = str(element).strip()
        if len(snippet) > 3000:
            snippet = snippet[:3000] + '\n<!-- ... truncated ... -->'
        key = hash(snippet[:200])
        if key not in seen:
            seen.add(key)
            components.append({'type': comp_type, 'html_snippet': snippet, 'context': context})

    for pwd in soup.find_all('input', attrs={'type': 'password'}):
        parent_form = pwd.find_parent('form')
        if parent_form:
            add('Login Form (contains password field)', parent_form, 'Found <form> wrapping a password input')
        else:
            parent_div = pwd.find_parent(
                ['div', 'section', 'main'],
                attrs=lambda a: a and any(
                    any(kw in str(v).lower() for kw in AUTH_KEYWORDS)
                    for v in (a.values() if isinstance(a, dict) else [])
                )
            )
            if parent_div:
                add('Auth Container (div-based)', parent_div, 'Password input inside container with auth attributes')
            else:
                add('Password Input Field', pwd, 'Standalone password input (no parent form detected)')

    for form in soup.find_all('form'):
        if check_attr_match(form, AUTH_KEYWORDS):
            add('Authentication Form', form, 'Form with auth-related attributes (id/class/action)')
        else:
            has_auth = False
            for inp in form.find_all('input'):
                name = (inp.get('name', '') or '').lower()
                itype = (inp.get('type', '') or '').lower()
                placeholder = (inp.get('placeholder', '') or '').lower()
                if itype in ('password', 'email'): has_auth = True
                if any(kw in name for kw in AUTH_INPUT_NAMES): has_auth = True
                if any(kw in placeholder for kw in AUTH_KEYWORDS[:10]): has_auth = True
            if has_auth:
                add('Authentication Form', form, 'Form contains auth-related input fields')

    for tag_name in ['div', 'section', 'main', 'aside']:
        for elem in soup.find_all(tag_name):
            if check_attr_match(elem, ['login', 'signin', 'sign-in', 'auth', 'credentials']):
                if elem.find_all('input'):
                    add('Auth Section / Container', elem, f'<{tag_name}> with auth-related class/id + input fields')

    for btn in soup.find_all(['a', 'button']):
        text = btn.get_text(strip=True)
        if re.search(r'(sign\s*in|log\s*in|continue)\s*(with|using|via)', text, re.I):
            add('OAuth / SSO Button', btn, 'Social or SSO login button')

    for btn in soup.find_all(['a', 'button']):
        href = (btn.get('href', '') or '').lower()
        text = btn.get_text(strip=True).lower()
        if any(p in href for p in ['/auth/', '/login', '/sso', 'oauth']):
            if any(kw in text for kw in ['sign in', 'log in', 'login', 'sign up']):
                add('Auth Link / Button', btn, 'Link pointing to auth endpoint')

    types_found = list(set(c['type'] for c in components))
    summary = (
        f"Found {len(components)} auth component(s): {', '.join(types_found)}"
        if components else "No authentication components detected on this page."
    )
    return {'found': len(components) > 0, 'components': components, 'summary': summary, 'total_found': len(components)}


def scrape_and_detect(url):
    result = {'url': url, 'success': False, 'error': None, 'status_code': None, 'auth_result': None, 'page_title': None}
    try:
        html, status = fetch_html(url)
        result['status_code'] = status
        result['success'] = True
        title_tag = BeautifulSoup(html, 'html.parser').find('title')
        result['page_title'] = title_tag.get_text(strip=True) if title_tag else 'No title'
        result['auth_result'] = detect_auth_components(html)
    except http_requests.exceptions.Timeout:
        result['error'] = 'Request timed out — site took too long to respond.'
    except http_requests.exceptions.ConnectionError:
        result['error'] = 'Connection error — could not reach the website.'
    except http_requests.exceptions.HTTPError as e:
        result['error'] = f'HTTP error: {e.response.status_code}'
    except Exception as e:
        result['error'] = f'Error: {str(e)}'
    return result


@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing url'}), 400
    url = data['url'].strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return jsonify({'error': 'Invalid URL'}), 400
    start = time.time()
    result = scrape_and_detect(url)
    result['scan_time'] = round(time.time() - start, 2)
    return jsonify(result)


@app.route('/api/scan-defaults', methods=['GET'])
def api_scan_defaults():
    results = []
    for url in DEFAULT_SITES:
        start = time.time()
        result = scrape_and_detect(url)
        result['scan_time'] = round(time.time() - start, 2)
        results.append(result)
    return jsonify({
        'results': results,
        'total_scanned': len(results),
        'sites_with_auth': sum(1 for r in results if r.get('auth_result', {}).get('found')),
    })


@app.route('/')
def index():
    return HTML_PAGE


HTML_PAGE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Auth Component Detector</title>
<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --red:#e8192c; --red2:#ff3344; --red-dim:rgba(232,25,44,0.15);
  --red-glow:rgba(232,25,44,0.5); --black:#04060a;
  --surface:rgba(10,13,20,0.95); --border:rgba(232,25,44,0.22);
  --border2:rgba(255,255,255,0.06); --white:#f0f2f5;
  --muted:#606672; --code-bg:#060810;
}
*{margin:0;padding:0;box-sizing:border-box;}
html{scroll-behavior:smooth;}
body{font-family:'Rajdhani',sans-serif;background:var(--black);color:var(--white);min-height:100vh;overflow-x:hidden;}

#bgCanvas{position:fixed;inset:0;z-index:0;pointer-events:none;}
.scanlines{position:fixed;inset:0;z-index:1;pointer-events:none;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,0.07) 3px,rgba(0,0,0,0.07) 4px);}
.scan-beam{position:fixed;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent 0%,var(--red) 50%,transparent 100%);z-index:2;pointer-events:none;animation:beamMove 7s linear infinite;opacity:0.35;filter:blur(1px);box-shadow:0 0 14px var(--red-glow);}
@keyframes beamMove{0%{top:-2px;}100%{top:100vh;}}

.corner{position:fixed;width:50px;height:50px;z-index:3;pointer-events:none;}
.corner::before,.corner::after{content:'';position:absolute;background:var(--red);opacity:0.7;}
.corner::before{width:100%;height:2px;top:0;left:0;}
.corner::after{width:2px;height:100%;top:0;left:0;}
.corner.tl{top:14px;left:14px;}
.corner.tr{top:14px;right:14px;transform:scaleX(-1);}
.corner.bl{bottom:14px;left:14px;transform:scaleY(-1);}
.corner.br{bottom:14px;right:14px;transform:scale(-1);}

.container{position:relative;z-index:10;max-width:1000px;margin:0 auto;padding:52px 28px 72px;}

/* HEADER */
header{text-align:center;margin-bottom:48px;animation:slideDown 0.8s ease both;}
@keyframes slideDown{from{opacity:0;transform:translateY(-28px);}to{opacity:1;transform:translateY(0);}}
.eyebrow{font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--red);letter-spacing:5px;text-transform:uppercase;margin-bottom:12px;display:block;animation:fadeIn 0.8s ease 0.4s both;}
@keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
.title-block{position:relative;display:inline-block;}
h1{font-family:'Bebas Neue',sans-serif;font-size:76px;letter-spacing:7px;line-height:1;background:linear-gradient(100deg,#fff 0%,#fff 35%,var(--red2) 65%,#ff7080 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;position:relative;}
h1::before,h1::after{content:attr(data-text);position:absolute;top:0;left:0;background-clip:text;-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
h1::before{background:linear-gradient(100deg,var(--red),transparent);animation:glA 5s infinite;clip-path:polygon(0 15%,100% 15%,100% 35%,0 35%);}
h1::after{background:linear-gradient(100deg,#fff,var(--red2));animation:glB 5s infinite;clip-path:polygon(0 65%,100% 65%,100% 82%,0 82%);}
@keyframes glA{0%,88%,100%{transform:translate(0);opacity:0;}90%{transform:translate(-4px,1px);opacity:0.7;}93%{transform:translate(4px,-1px);opacity:0.7;}95%{transform:translate(0);opacity:0;}}
@keyframes glB{0%,85%,100%{transform:translate(0);opacity:0;}87%{transform:translate(4px,2px);opacity:0.6;}90%{transform:translate(-3px,-2px);opacity:0.6;}92%{transform:translate(0);opacity:0;}}

.divider{display:flex;align-items:center;justify-content:center;gap:14px;margin:18px auto 20px;max-width:360px;}
.divider::before{content:'';flex:1;height:1px;background:linear-gradient(90deg,transparent,var(--red));}
.divider::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--red),transparent);}
.diamond{width:9px;height:9px;background:var(--red);transform:rotate(45deg);box-shadow:0 0 12px var(--red-glow);animation:diamondPulse 2s ease-in-out infinite;}
@keyframes diamondPulse{0%,100%{box-shadow:0 0 6px var(--red-glow);transform:rotate(45deg) scale(1);}50%{box-shadow:0 0 22px var(--red-glow);transform:rotate(45deg) scale(1.35);}}
header p{color:var(--muted);font-size:15px;font-weight:400;letter-spacing:0.4px;max-width:500px;margin:0 auto;line-height:1.75;animation:fadeIn 0.8s ease 0.7s both;}

/* STATS */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px;animation:slideUp 0.7s ease 0.3s both;}
@keyframes slideUp{from{opacity:0;transform:translateY(18px);}to{opacity:1;transform:translateY(0);}}
.stat-tile{background:var(--surface);border:1px solid var(--border2);border-radius:10px;padding:18px 12px;text-align:center;position:relative;overflow:hidden;transition:border-color 0.3s,transform 0.2s,box-shadow 0.3s;}
.stat-tile::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--red),transparent);transform:scaleX(0);transition:transform 0.4s;}
.stat-tile:hover{border-color:var(--border);transform:translateY(-3px);box-shadow:0 8px 30px rgba(232,25,44,0.1);}
.stat-tile:hover::after{transform:scaleX(1);}
.stat-val{font-family:'Bebas Neue',sans-serif;font-size:38px;letter-spacing:2px;background:linear-gradient(135deg,#fff,var(--red));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;line-height:1;}
.stat-lbl{font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px;margin-top:5px;}

/* INPUT */
.input-section{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:28px;margin-bottom:26px;position:relative;overflow:hidden;box-shadow:0 0 60px rgba(232,25,44,0.07),0 20px 60px rgba(0,0,0,0.5);animation:slideUp 0.7s ease 0.15s both;}
.input-section::before{content:'';position:absolute;inset:0;border-radius:14px;background:linear-gradient(135deg,rgba(232,25,44,0.05) 0%,transparent 55%);pointer-events:none;}
.section-label{font-family:'Share Tech Mono',monospace;font-size:10px;color:var(--red);letter-spacing:3px;text-transform:uppercase;margin-bottom:16px;display:flex;align-items:center;gap:10px;}
.section-label::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent);}
.input-row{display:flex;gap:10px;margin-bottom:20px;}
.url-wrapper{flex:1;position:relative;}
.url-prefix{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--red);font-family:'Share Tech Mono',monospace;font-size:12px;pointer-events:none;opacity:0.6;}
.input-row input[type="text"]{width:100%;padding:14px 16px 14px 68px;font-size:14px;font-family:'Share Tech Mono',monospace;background:var(--code-bg);border:1px solid var(--border2);border-radius:8px;color:var(--white);outline:none;transition:border-color 0.25s,box-shadow 0.25s;letter-spacing:0.3px;}
.input-row input[type="text"]:focus{border-color:var(--red);box-shadow:0 0 0 3px rgba(232,25,44,0.12),inset 0 0 20px rgba(232,25,44,0.03);}
.input-row input[type="text"]::placeholder{color:#22262e;}
.btn{padding:14px 28px;font-size:13px;font-weight:700;font-family:'Rajdhani',sans-serif;letter-spacing:1.5px;text-transform:uppercase;border:none;border-radius:8px;cursor:pointer;transition:all 0.2s;white-space:nowrap;position:relative;overflow:hidden;}
.btn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,0.12) 0%,transparent 60%);opacity:0;transition:opacity 0.2s;}
.btn:hover::after{opacity:1;}
.btn-primary{background:linear-gradient(135deg,var(--red),#8a0f1a);color:#fff;box-shadow:0 4px 20px var(--red-glow),inset 0 1px 0 rgba(255,255,255,0.12);}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 32px var(--red-glow);}
.btn-primary:active{transform:translateY(0);}
.btn-primary:disabled{background:#180810;color:#38141a;box-shadow:none;cursor:not-allowed;transform:none;}
.btn-secondary{background:transparent;color:var(--white);border:1px solid var(--border);}
.btn-secondary:hover{border-color:var(--red);color:var(--red);background:var(--red-dim);transform:translateY(-1px);}
.btn-secondary:disabled{opacity:0.35;cursor:not-allowed;transform:none;}
.demo-row{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:14px;}
.demo-label{font-family:'Share Tech Mono',monospace;color:var(--muted);font-size:11px;letter-spacing:2px;text-transform:uppercase;}
.demo-chips{display:flex;gap:8px;flex-wrap:wrap;}
.chip{padding:5px 16px;font-size:12px;font-family:'Share Tech Mono',monospace;background:transparent;border:1px solid var(--border2);border-radius:4px;color:var(--muted);cursor:pointer;transition:all 0.2s;letter-spacing:0.5px;position:relative;overflow:hidden;}
.chip::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--red);transform:scaleY(0);transition:transform 0.2s;}
.chip:hover{border-color:var(--red);color:var(--red);background:var(--red-dim);}
.chip:hover::before{transform:scaleY(1);}

/* RESULTS */
.results-area{min-height:220px;}
.status-msg{text-align:center;padding:70px 20px;color:var(--muted);font-size:14px;font-family:'Share Tech Mono',monospace;}
.status-icon{font-size:40px;display:block;margin-bottom:18px;animation:float 3s ease-in-out infinite;}
@keyframes float{0%,100%{transform:translateY(0);}50%{transform:translateY(-9px);}}
.hint{display:block;margin-top:10px;font-size:11px;color:#1e222a;letter-spacing:1px;}

.loading-wrap{text-align:center;padding:70px 20px;}
.loading-text{font-family:'Share Tech Mono',monospace;font-size:13px;color:var(--red);letter-spacing:2px;text-transform:uppercase;margin-bottom:20px;animation:textPulse 1.5s ease-in-out infinite;}
@keyframes textPulse{0%,100%{opacity:1;}50%{opacity:0.4;}}
.loading-bar{width:220px;height:2px;background:#111;margin:0 auto;border-radius:2px;overflow:hidden;}
.loading-bar-fill{height:100%;width:30%;background:linear-gradient(90deg,transparent,var(--red),transparent);animation:barScan 1.2s ease-in-out infinite;}
@keyframes barScan{0%{transform:translateX(-200%);}100%{transform:translateX(400%);}}

/* CARDS */
.result-card{background:var(--surface);border:1px solid var(--border2);border-radius:12px;margin-bottom:14px;overflow:hidden;transition:border-color 0.25s,box-shadow 0.25s,transform 0.2s;animation:cardIn 0.5s ease both;}
@keyframes cardIn{from{opacity:0;transform:translateY(14px);}to{opacity:1;transform:translateY(0);}}
.result-card:hover{border-color:var(--border);box-shadow:0 0 28px rgba(232,25,44,0.06);transform:translateY(-1px);}
.result-header{padding:18px 22px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;transition:background 0.15s;}
.result-header:hover{background:rgba(232,25,44,0.02);}
.result-header-left h3{font-size:15px;font-weight:600;color:var(--white);margin-bottom:5px;letter-spacing:0.3px;}
.url-text{font-size:11px;font-family:'Share Tech Mono',monospace;color:var(--red);opacity:0.7;word-break:break-all;}
.result-meta{display:flex;gap:12px;align-items:center;flex-shrink:0;}
.badge{padding:4px 12px;border-radius:3px;font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;font-family:'Share Tech Mono',monospace;}
.badge-found{background:rgba(232,25,44,0.15);color:#ff4455;border:1px solid rgba(232,25,44,0.35);box-shadow:0 0 10px rgba(232,25,44,0.15);}
.badge-none{background:rgba(255,255,255,0.04);color:var(--muted);border:1px solid var(--border2);}
.badge-error{background:rgba(255,120,40,0.1);color:#ff8040;border:1px solid rgba(255,120,40,0.3);}
.scan-time{font-size:11px;font-family:'Share Tech Mono',monospace;color:#2a2f38;}
.expand-icon{color:var(--muted);font-size:12px;transition:transform 0.3s;opacity:0.4;}
.expand-icon.rotated{transform:rotate(90deg);opacity:0.8;}
.result-body{padding:0 22px;max-height:0;overflow:hidden;transition:max-height 0.45s ease,padding 0.3s;}
.result-body.open{max-height:3000px;padding:20px 22px;}
.component-item{margin-bottom:22px;padding-bottom:22px;border-bottom:1px solid rgba(255,255,255,0.04);animation:fadeIn 0.4s ease both;}
.component-item:last-child{margin-bottom:0;padding-bottom:0;border-bottom:none;}
.component-label{font-size:11px;font-weight:700;color:var(--red);text-transform:uppercase;letter-spacing:2px;margin-bottom:6px;font-family:'Share Tech Mono',monospace;display:flex;align-items:center;gap:8px;}
.component-label::before{content:'▸';}
.component-context{font-size:13px;color:var(--muted);margin-bottom:12px;font-style:italic;padding-left:16px;border-left:2px solid var(--border2);}
.code-block{background:var(--code-bg);border:1px solid rgba(255,255,255,0.05);border-left:3px solid var(--red);border-radius:6px;padding:16px;overflow-x:auto;max-height:280px;overflow-y:auto;position:relative;}
.code-block::before{content:'HTML';position:absolute;top:8px;right:12px;font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--red);opacity:0.4;letter-spacing:2px;}
.code-block pre{font-family:'Share Tech Mono',monospace;font-size:12px;color:#7080a0;white-space:pre-wrap;word-break:break-word;line-height:1.75;}
.error-msg{color:#ff8040;font-size:13px;font-family:'Share Tech Mono',monospace;padding:8px 0;}
.none-msg{color:var(--muted);font-size:14px;line-height:1.75;font-style:italic;padding:8px 0;}

/* SUMMARY */
.summary-bar{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:22px 28px;margin-bottom:20px;display:flex;justify-content:space-around;box-shadow:0 0 40px rgba(232,25,44,0.07);animation:slideUp 0.5s ease both;}
.summary-bar .stat{text-align:center;}
.summary-bar .stat-val{font-family:'Bebas Neue',sans-serif;font-size:40px;letter-spacing:2px;background:linear-gradient(135deg,#fff,var(--red));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;line-height:1;}
.summary-bar .stat-label{font-size:11px;color:var(--muted);margin-top:5px;text-transform:uppercase;letter-spacing:1px;font-family:'Share Tech Mono',monospace;}

/* FOOTER */
footer{text-align:center;margin-top:60px;padding-top:28px;border-top:1px solid rgba(255,255,255,0.04);color:#2a2f38;font-size:12px;font-family:'Share Tech Mono',monospace;letter-spacing:1px;animation:fadeIn 1s ease 1s both;}
footer a{color:var(--red);text-decoration:none;opacity:0.6;transition:opacity 0.2s,text-shadow 0.2s;}
footer a:hover{opacity:1;text-shadow:0 0 12px var(--red-glow);}

::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-track{background:var(--black);}
::-webkit-scrollbar-thumb{background:var(--red);border-radius:2px;}

@media(max-width:640px){
  h1{font-size:50px;}
  .stats-row{grid-template-columns:repeat(2,1fr);}
  .input-row{flex-direction:column;}
  .corner{display:none;}
}
</style>
</head>
<body>

<canvas id="bgCanvas"></canvas>
<div class="scanlines"></div>
<div class="scan-beam"></div>
<div class="corner tl"></div>
<div class="corner tr"></div>
<div class="corner bl"></div>
<div class="corner br"></div>

<div class="container">
  <header>
    <span class="eyebrow">// security intelligence tool v2.0</span>
    <div class="title-block">
      <h1 data-text="AUTH DETECTOR">AUTH DETECTOR</h1>
    </div>
    <div class="divider"><div class="diamond"></div></div>
    <p>Scan any website URL to extract login forms, password fields, OAuth buttons, and authentication components from its live HTML.</p>
  </header>

  <div class="stats-row">
    <div class="stat-tile"><div class="stat-val" id="st-scanned">0</div><div class="stat-lbl">Scanned</div></div>
    <div class="stat-tile"><div class="stat-val" id="st-auth">0</div><div class="stat-lbl">Auth Found</div></div>
    <div class="stat-tile"><div class="stat-val" id="st-comps">0</div><div class="stat-lbl">Components</div></div>
    <div class="stat-tile"><div class="stat-val" id="st-errors">0</div><div class="stat-lbl">Errors</div></div>
  </div>

  <div class="input-section">
    <div class="section-label">Target URL</div>
    <div class="input-row">
      <div class="url-wrapper">
        <span class="url-prefix">https://</span>
        <input type="text" id="urlInput" placeholder="www.example.com/login" autocomplete="off" spellcheck="false"/>
      </div>
      <button class="btn btn-primary" id="scanBtn" onclick="scanSingle()">&#9654; Scan URL</button>
    </div>
    <div class="demo-row">
      <button class="btn btn-secondary" id="demoBtn" onclick="scanDefaults()">Scan 5 Demo Sites</button>
      <span class="demo-label">— or pick one:</span>
    </div>
    <div class="demo-chips">
      <span class="chip" onclick="quick('https://github.com/login')">GitHub</span>
      <span class="chip" onclick="quick('https://www.linkedin.com/login')">LinkedIn</span>
      <span class="chip" onclick="quick('https://www.facebook.com/login')">Facebook</span>
      <span class="chip" onclick="quick('https://login.salesforce.com/')">Salesforce</span>
      <span class="chip" onclick="quick('https://login.twitter.com/i/flow/login',)">Twitter</span>
    </div>
  </div>

  <div class="results-area" id="results">
    <div class="status-msg">
      <span class="status-icon">&#128269;</span>
      AWAITING TARGET URL
      <span class="hint">// enter a url above to begin scanning</span>
    </div>
  </div>

  <footer>
    Built by Tanishq Mekala &nbsp;&middot;&nbsp;
    <a href="https://www.linkedin.com/in/tanishqmekala/" target="_blank">LinkedIn</a>
  </footer>
</div>

<script>
/* Particle canvas */
(function(){
  const cv=document.getElementById('bgCanvas');
  const cx=cv.getContext('2d');
  let W,H,pts=[];
  function resize(){W=cv.width=innerWidth;H=cv.height=innerHeight;}
  class P{
    constructor(){this.reset(true);}
    reset(init){
      this.x=Math.random()*W;
      this.y=init?Math.random()*H:(Math.random()>0.5?-4:H+4);
      this.vx=(Math.random()-0.5)*0.5;this.vy=(Math.random()-0.5)*0.5;
      this.r=Math.random()*1.8+0.3;this.a=Math.random()*0.55+0.08;
      this.red=Math.random()>0.65;
    }
    move(){this.x+=this.vx;this.y+=this.vy;if(this.x<-10||this.x>W+10||this.y<-10||this.y>H+10)this.reset(false);}
    draw(){
      cx.beginPath();cx.arc(this.x,this.y,this.r,0,Math.PI*2);
      cx.fillStyle=this.red?`rgba(232,25,44,${this.a})`:`rgba(160,170,190,${this.a*0.35})`;
      cx.fill();
    }
  }
  function init(){resize();pts=Array.from({length:130},()=>new P());}
  function connect(){
    for(let i=0;i<pts.length;i++){
      for(let j=i+1;j<pts.length;j++){
        const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y;
        const d=Math.sqrt(dx*dx+dy*dy);
        if(d<110){
          cx.beginPath();cx.moveTo(pts[i].x,pts[i].y);cx.lineTo(pts[j].x,pts[j].y);
          cx.strokeStyle=`rgba(232,25,44,${(1-d/110)*0.1})`;cx.lineWidth=0.5;cx.stroke();
        }
      }
    }
  }
  function frame(){
    cx.clearRect(0,0,W,H);
    cx.strokeStyle='rgba(232,25,44,0.022)';cx.lineWidth=0.5;
    const gs=80;
    for(let x=0;x<W;x+=gs){cx.beginPath();cx.moveTo(x,0);cx.lineTo(x,H);cx.stroke();}
    for(let y=0;y<H;y+=gs){cx.beginPath();cx.moveTo(0,y);cx.lineTo(W,y);cx.stroke();}
    connect();pts.forEach(p=>{p.move();p.draw();});
    requestAnimationFrame(frame);
  }
  window.addEventListener('resize',()=>{resize();pts.forEach(p=>p.reset(true));});
  init();frame();
})();

/* App */
const results=document.getElementById('results');
const urlInput=document.getElementById('urlInput');
const scanBtn=document.getElementById('scanBtn');
const demoBtn=document.getElementById('demoBtn');
let totalScanned=0,totalAuth=0,totalComps=0,totalErrors=0;

function updateStats(s,a,c,e){
  totalScanned+=s;totalAuth+=a;totalComps+=c;totalErrors+=e;
  animCount('st-scanned',totalScanned);animCount('st-auth',totalAuth);
  animCount('st-comps',totalComps);animCount('st-errors',totalErrors);
}
function animCount(id,target){
  const el=document.getElementById(id);
  const start=parseInt(el.textContent)||0;
  const dur=600,t0=performance.now();
  function tick(now){
    const p=Math.min((now-t0)/dur,1);
    el.textContent=Math.round(start+(target-start)*p);
    if(p<1)requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

urlInput.addEventListener('keydown',e=>{if(e.key==='Enter')scanSingle();});
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}

function loading(msg){
  results.innerHTML=`<div class="loading-wrap"><div class="loading-text">${esc(msg)}</div><div class="loading-bar"><div class="loading-bar-fill"></div></div></div>`;
  scanBtn.disabled=true;demoBtn.disabled=true;
}
function done(){scanBtn.disabled=false;demoBtn.disabled=false;}

function toggleCard(i){
  const b=document.getElementById('body-'+i);
  const ic=document.getElementById('icon-'+i);
  if(b)b.classList.toggle('open');
  if(ic)ic.classList.toggle('rotated');
}

function card(r,i){
  const err=!r.success;
  const ar=r.auth_result||{};
  const found=ar.found||false;
  const comps=ar.components||[];
  let badge;
  if(err)badge='<span class="badge badge-error">Error</span>';
  else if(found)badge='<span class="badge badge-found">'+comps.length+' Found</span>';
  else badge='<span class="badge badge-none">None Found</span>';
  let body;
  if(err){body='<div class="error-msg">&#9888; '+esc(r.error||'Unknown error')+'</div>';}
  else if(found){
    body=comps.map(c=>`
      <div class="component-item">
        <div class="component-label">${esc(c.type)}</div>
        <div class="component-context">${esc(c.context)}</div>
        <div class="code-block"><pre>${esc(c.html_snippet)}</pre></div>
      </div>`).join('');
  } else {
    body='<div class="none-msg">No auth components detected. The site may load its login form via JavaScript (SPA), or this page has no login section.</div>';
  }
  return `
  <div class="result-card" id="card-${i}" style="animation-delay:${i*0.08}s">
    <div class="result-header" onclick="toggleCard(${i})">
      <div class="result-header-left">
        <h3>${esc(r.page_title||'Unknown Page')}</h3>
        <div class="url-text">${esc(r.url)}</div>
      </div>
      <div class="result-meta">
        ${badge}
        <span class="scan-time">${r.scan_time||0}s</span>
        <span class="expand-icon" id="icon-${i}">&#9654;</span>
      </div>
    </div>
    <div class="result-body" id="body-${i}">${body}</div>
  </div>`;
}

function summaryBar(list){
  const tot=list.length;
  const auth=list.filter(r=>r.auth_result&&r.auth_result.found).length;
  const errs=list.filter(r=>!r.success).length;
  const comps=list.reduce((s,r)=>s+(r.auth_result?r.auth_result.total_found||0:0),0);
  return `<div class="summary-bar">
    <div class="stat"><div class="stat-val">${tot}</div><div class="stat-label">Sites Scanned</div></div>
    <div class="stat"><div class="stat-val">${auth}</div><div class="stat-label">Auth Detected</div></div>
    <div class="stat"><div class="stat-val">${comps}</div><div class="stat-label">Components</div></div>
    <div class="stat"><div class="stat-val">${errs}</div><div class="stat-label">Errors</div></div>
  </div>`;
}

async function scanSingle(){
  let url=urlInput.value.trim();
  if(!url){urlInput.focus();return;}
  if(!url.startsWith('http://')&&!url.startsWith('https://'))url='https://'+url;
  loading('Scanning '+url+' ...');
  try{
    const resp=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const data=await resp.json();
    if(resp.ok){
      updateStats(1,data.auth_result?.found?1:0,data.auth_result?.total_found||0,data.success?0:1);
      results.innerHTML=card(data,0);toggleCard(0);
    } else {
      results.innerHTML='<div class="status-msg" style="color:#ff7040;">'+esc(data.error||'Error')+'</div>';
    }
  } catch(e){
    results.innerHTML='<div class="status-msg" style="color:#ff7040;">Could not reach server. Make sure app.py is running.</div>';
  }
  done();
}

function quick(url){urlInput.value=url;scanSingle();}

async function scanDefaults(){
  loading('Scanning 5 demo sites — takes ~20 seconds...');
  try{
    const resp=await fetch('/api/scan-defaults');
    const data=await resp.json();
    const auth=data.results.filter(r=>r.auth_result&&r.auth_result.found).length;
    const comps=data.results.reduce((s,r)=>s+(r.auth_result?r.auth_result.total_found||0:0),0);
    const errs=data.results.filter(r=>!r.success).length;
    updateStats(data.results.length,auth,comps,errs);
    let html=summaryBar(data.results);
    data.results.forEach((r,i)=>{html+=card(r,i);});
    results.innerHTML=html;
  } catch(e){
    results.innerHTML='<div class="status-msg" style="color:#ff7040;">Could not reach server. Make sure app.py is running.</div>';
  }
  done();
}
</script>
</body>
</html>'''


if __name__ == '__main__':
    import os
    print()
    print('=' * 50)
    print('  Auth Component Detector is running!')
    print('  Open this in your browser:')
    print()
    print('  --> http://localhost:5000')
    print()
    print('  Press Ctrl+C to stop the server')
    print('=' * 50)
    print()
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
