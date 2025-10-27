import requests
from bs4 import BeautifulSoup
from .payloads import XSS_PAYLOADS, SQLI_PAYLOADS, SQL_ERRORS

def check_headers_for_url(url):
    try:
        r = requests.get(url, timeout=8)
    except Exception:
        return []
    headers = {k.lower(): v for k, v in r.headers.items()}
    required = ['x-frame-options', 'content-security-policy', 'strict-transport-security']
    missing = [h for h in required if h not in headers]
    return [{'type': 'missing_header', 'header': h, 'url': url} for h in missing]

def check_xss_for_form(form):
    findings = []
    for payload in XSS_PAYLOADS:
        data = {inp['name']: payload for inp in form['inputs']}
        try:
            if form['method'] == 'post':
                r = requests.post(form['action'], data=data, timeout=8)
            else:
                r = requests.get(form['action'], params=data, timeout=8)
        except Exception:
            continue
        if payload in r.text:
            findings.append({'type': 'xss', 'url': form['action'], 'payload': payload, 'form': form})
    return findings

def check_csrf_for_form(form):
    # If method is POST and no hidden token-looking input, flag it
    if form['method'] != 'post':
        return []
    hidden_tokens = [inp for inp in form['inputs'] if inp['type'] == 'hidden' and ('csrf' in inp['name'].lower() or 'token' in inp['name'].lower())]
    if not hidden_tokens:
        return [{'type': 'csrf_missing', 'url': form['action'], 'form': form}]
    return []

def check_sqli_for_url(url):
    findings = []
    for payload in SQLI_PAYLOADS:
        try:
            r = requests.get(url, params={'id': payload}, timeout=8)
        except Exception:
            continue
        body = r.text.lower()
        if any(err in body for err in SQL_ERRORS):
            findings.append({'type': 'sqli', 'url': url, 'payload': payload})
    return findings
