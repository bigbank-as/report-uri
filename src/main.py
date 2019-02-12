import json
import logging
import re
from datetime import datetime
from logging.handlers import RotatingFileHandler

import jsonschema
from flask import Flask, request, jsonify
from flask_talisman import Talisman
from pythonjsonlogger import jsonlogger
from werkzeug.contrib.fixers import ProxyFix

app = Flask(__name__)

# Fix IP handling: source IP comes from X-Forwarded-For
app.wsgi_app = ProxyFix(app.wsgi_app)

# Add HTTP security headers
if not app.debug:
    Talisman(app)

# HTTP request body (JSON POST-s) will be logged here
requestLogger = logging.getLogger('requests')
requestLogger.setLevel(logging.INFO)
logHandler = RotatingFileHandler('/var/log/python/app.json', maxBytes=1000000)
logHandler.setFormatter(jsonlogger.JsonFormatter())
requestLogger.addHandler(logHandler)


# Healthcheck URL
@app.route('/', methods=['GET'])
def main():
    return jsonify({
        "description": "Collection endpoint for HTTP report-uri security headers.",
        "contact": "security at bigbank dot eu"})


@app.before_request
def log_request():
    if request.content_length:
        log_row = get_body()

        log_row.update(log_row.get('csp-report'))
        log_row.pop('csp-report', None)
        log_row['message'] = 'New report-uri report from {0}'.format(log_row.get('remote_addr'))

        requestLogger.info(log_row)


@app.after_request
def add_headers(response):
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Server'] = 'Coffee-Powered'
    response.headers['Expect-CT'] = 'enforce ,max-age=2592000'
    return response


def get_body():
    extra_fields = {
        'timestamp': str(datetime.utcnow().isoformat(timespec='milliseconds')),
        'remote_addr': request.remote_addr,
        'user-agent': request.user_agent.string
    }

    request_body = dict(request.get_json(force=True))
    request_body.update(extra_fields)
    return request_body


def validate(schema):
    schema = json.loads(open(schema).read())
    jsonschema.validate(request.get_json(force=True), schema)


def is_local(uri):
    return re.match(r'^https?://localhost', uri) is not None


@app.route('/csp', methods=['POST'])
def csp():
    try:
        validate('schema/content-security-policy-report-2.json')
    except jsonschema.ValidationError as e:
        jsonify({"error": e.message}), 400

    report = get_body()
    csp_report = report.get('csp-report')

    exclude = ['self', 'blob', 'chrome-extension://', 'safari-extension://', 'data']
    if csp_report.get('blocked-uri') in exclude or is_local(csp_report.get('document-uri')):
        return jsonify({"result": "Skipped recording"}), 201

    return jsonify({"result": "Report recorded"}), 201


@app.route('/hpkp', methods=['POST'])
def hpkp():
    try:
        validate('schema/http-public-key-pinning-report.json')
    except jsonschema.ValidationError as e:
        return jsonify({"error": e.message}), 400

    return jsonify({"result": "Report recorded"}), 201


# https://tools.ietf.org/html/draft-ietf-httpbis-expect-ct-02
@app.route('/ct', methods=['POST'])
def expect_ct():
    report = get_body().get('expect-ct-report', None)

    if not report:
        return jsonify({"error": 'Invalid Expect-CT report body'}), 400

    return jsonify({"result": "Report recorded"}), 201


if __name__ == '__main__':
    app.run('0.0.0.0', 8080)
