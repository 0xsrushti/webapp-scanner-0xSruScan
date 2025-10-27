# scanner/core.py
import time
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from .utils import is_same_domain, normalize_url
from .checks import check_xss_for_form, check_sqli_for_url, check_headers_for_url, check_csrf_for_form
from .dom_checker import analyze_page, render_and_extract
from .payloads import COMMON_PARAM_NAMES

class Scanner:
    def __init__(self, seed_url, max_pages=100, delay=0.2, session=None):
        self.seed = normalize_url(seed_url)
        self.max_pages = max_pages
        self.delay = delay
        self.visited = set()
        self.to_visit = [self.seed]
        self.findings = {'xss': [], 'sqli': [], 'csrf': [], 'headers': [], 'dom_xss': [], 'dom_sinks': []}
        self.session = session or requests.Session()

    def _get(self, url):
        try:
            r = self.session.get(url, timeout=10)
            return r
        except Exception:
            return None

    def _extract_links_static(self, base_url, html_text):
        soup = BeautifulSoup(html_text, 'html.parser')
        links = set()
        for a in soup.find_all('a', href=True):
            href = a['href']
            joined = urljoin(base_url, href)
            norm = normalize_url(joined)
            if is_same_domain(self.seed, norm):
                links.add(norm)
        return links

    def _extract_forms_static(self, url, html_text):
        soup = BeautifulSoup(html_text, 'html.parser')
        forms = []
        for f in soup.find_all('form'):
            action = f.get('action') or ''
            method = (f.get('method') or 'get').lower()
            inputs = []
            for inp in f.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    inputs.append({'name': name, 'type': inp.get('type', 'text')})
            forms.append({'action': urljoin(url, action), 'method': method, 'inputs': inputs, 'raw': str(f)})
        return forms

    def _scan_page(self, url):
        r = self._get(url)
        if not r:
            return
        html = r.text
        header_findings = check_headers_for_url(url)
        self.findings['headers'].extend(header_findings)

        # DOM XSS headless analysis (fast check)
        try:
            dom = analyze_page(url, screenshot_dir='screenshots')
            if dom.get('dom_xss'):
                self.findings.setdefault('dom_xss', []).append(dom)
            elif dom.get('sinks_found'):
                self.findings.setdefault('dom_sinks', []).extend(dom['sinks_found'])
        except Exception:
            pass

        # Prefer Playwright-rendered links/forms to find JS-generated content
        try:
            rendered_links, rendered_forms = render_and_extract(url)
        except Exception:
            rendered_links, rendered_forms = [], []

        links = set(rendered_links) if rendered_links else self._extract_links_static(url, html)
        forms = rendered_forms if rendered_forms else self._extract_forms_static(url, html)

        for l in links:
            norm = normalize_url(l)
            if norm not in self.visited and len(self.visited) + len(self.to_visit) < self.max_pages:
                if is_same_domain(self.seed, norm):
                    self.to_visit.append(norm)

        # Scan forms (XSS/CSRF)
        for form in forms:
            x = check_xss_for_form(form)
            if x:
                self.findings['xss'].extend(x)
            c = check_csrf_for_form(form)
            if c:
                self.findings['csrf'].extend(c)

        # SQLi: check common parameter names on this page
        for pname in COMMON_PARAM_NAMES:
            try:
                res = self.session.get(url, params={pname: "' OR '1'='1"}, timeout=8)
                body = res.text.lower()
                from .payloads import SQL_ERRORS
                if any(err in body for err in SQL_ERRORS):
                    self.findings['sqli'].append({'type': 'sqli', 'url': url, 'param': pname})
            except Exception:
                pass

        # naive sqli boolean test on id param
        try:
            r1 = self.session.get(url, params={'id': "1' OR '1'='1"}, timeout=8)
            r2 = self.session.get(url, params={'id': "1' AND '1'='2"}, timeout=8)
            if r1 and r2:
                if abs(len(r1.text) - len(r2.text)) > 50:
                    self.findings['sqli'].append({'type': 'sqli_boolean', 'url': url, 'note': 'response-length-diff'})
        except Exception:
            pass

    def run(self):
        while self.to_visit and len(self.visited) < self.max_pages:
            url = self.to_visit.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)
            try:
                self._scan_page(url)
            except Exception:
                pass
            time.sleep(self.delay)
        return {'seed': self.seed, 'visited': list(self.visited), 'findings': self.findings}
