from urllib.parse import urlparse, urlunparse

def normalize_url(u):
    if not u.startswith('http'):
        u = 'http://' + u
    parsed = urlparse(u)
    path = parsed.path or '/'
    query = parsed.query or ''
    normalized = urlunparse((parsed.scheme, parsed.netloc, path, '', query, ''))
    return normalized.rstrip('/')

def get_hostname(u):
    from urllib.parse import urlparse
    p = urlparse(u)
    return p.netloc.lower()

def is_same_domain(seed, other):
    return get_hostname(seed) == get_hostname(other)

