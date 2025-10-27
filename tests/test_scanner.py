# Very small smoke test for the scanner classes (no external requests made)
from scanner.core import Scanner

def test_scanner_init():
    s = Scanner('http://example.com', max_pages=1, delay=0)
    r = s.run()
    assert r['seed'].startswith('http')
    assert 'visited' in r
    assert 'findings' in r
