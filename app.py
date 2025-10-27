from flask import Flask, request, render_template, jsonify
from scanner.core import Scanner
import os

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

SCANNERS = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def run_scan():
    data = request.json or {}
    target = data.get('target')
    if not target:
        return jsonify({'error': 'missing target'}), 400
    max_pages = int(data.get('max_pages', 100))
    delay = float(data.get('delay', 0.2))
    # optional auth/session (not mandatory)
    session = None
    scanner = Scanner(seed_url=target, max_pages=max_pages, delay=delay, session=session)
    results = scanner.run()
    SCANNERS[target] = results
    return jsonify(results)

@app.route('/api/result', methods=['GET'])
def get_result():
    target = request.args.get('target')
    if not target or target not in SCANNERS:
        return jsonify({'error': 'no result'}), 404
    return jsonify(SCANNERS[target])

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

