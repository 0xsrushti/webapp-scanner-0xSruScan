# scanner/dom_checker.py
from playwright.sync_api import sync_playwright
import os, time
from urllib.parse import urljoin

# Safe DOM payload that sets a global flag instead of showing alerts
DOM_TEST_PAYLOAD = '"><img src=x onerror="window.__sru_dom_xss = 1">'

SINK_KEYWORDS = ['innerHTML', 'document.write', 'eval(', 'setTimeout(', 'innerText', 'outerHTML']

def analyze_page(url, timeout=10000, screenshot_dir=None):
    findings = {'url': url, 'sinks_found': [], 'dom_xss': False, 'screenshot': None}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=['--no-sandbox'])
        context = browser.new_context()
        page = context.new_page()
        try:
            page.goto(url, timeout=timeout)
            time.sleep(0.4)
            scripts = page.query_selector_all('script')
            for s in scripts:
                try:
                    txt = s.inner_text()
                except Exception:
                    txt = ''
                for k in SINK_KEYWORDS:
                    if k in txt:
                        findings['sinks_found'].append({'keyword': k, 'snippet': txt[:200]})
            inj_url = url
            if '?' in url:
                inj_url = url + '&q=' + DOM_TEST_PAYLOAD
            else:
                inj_url = url + '?q=' + DOM_TEST_PAYLOAD
            page.goto(inj_url, timeout=timeout)
            time.sleep(0.8)
            try:
                flag = page.evaluate('window.__sru_dom_xss ? 1 : 0')
            except Exception:
                flag = 0
            if flag:
                findings['dom_xss'] = True
                if screenshot_dir:
                    os.makedirs(screenshot_dir, exist_ok=True)
                    path = os.path.join(screenshot_dir, f"dom_xss_{int(time.time())}.png")
                    page.screenshot(path=path, full_page=True)
                    findings['screenshot'] = path
        except Exception as e:
            findings['error'] = str(e)
        finally:
            try:
                context.close()
                browser.close()
            except Exception:
                pass
    return findings

def render_and_extract(url, timeout=10000):
    links = set()
    forms = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=['--no-sandbox'])
        context = browser.new_context()
        page = context.new_page()
        try:
            page.goto(url, timeout=timeout)
            # extract absolute links
            try:
                hrefs = page.evaluate("Array.from(document.querySelectorAll('a[href]')).map(a=>a.href)")
                for h in hrefs:
                    if h:
                        links.add(h)
            except Exception:
                pass
            # extract forms and inputs
            try:
                form_nodes = page.query_selector_all('form')
                for f in form_nodes:
                    action = f.get_attribute('action') or url
                    method = (f.get_attribute('method') or 'get').lower()
                    inputs = page.evaluate('''(form) => {
                        const arr = [];
                        Array.from(form.querySelectorAll('input,textarea,select')).forEach(i=>{
                            if(i.name) arr.push({name:i.name, type:i.type||'text'});
                        });
                        return arr;
                    }''', f)
                    forms.append({'action': urljoin(url, action), 'method': method, 'inputs': inputs, 'raw': None})
            except Exception:
                pass
        except Exception:
            pass
        finally:
            try:
                context.close(); browser.close()
            except Exception:
                pass
    return list(links), forms

