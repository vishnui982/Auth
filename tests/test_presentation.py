"""Presentation trust labeling and local mutation-boundary regressions."""
from email.message import Message
import json
import re

import pytest

from agent_guard.errors import GuardError
from agent_guard.integration.demo import validate_run_request
from agent_guard.integration.presentation import illustrative_story, render_site


def headers():
    result = Message()
    for key, value in [('Host', '127.0.0.1:8787'), ('Content-Type', 'application/json'),
                       ('Content-Length', '2'), ('Origin', 'http://127.0.0.1:8787')]:
        result[key] = value
    return result


def test_local_run_accepts_same_origin_json():
    validate_run_request(headers(), 8787)


@pytest.mark.parametrize('key,value', [('Origin', 'https://attacker.example'),
    ('Origin', 'null'), ('Host', 'attacker.example'), ('Content-Type', 'text/plain'),
    ('Transfer-Encoding', 'chunked'), ('Sec-Fetch-Site', 'cross-site')])
def test_local_run_rejects_cross_origin_and_ambiguous_requests(key, value):
    h = headers()
    if key in h:
        h.replace_header(key, value)
    else:
        h[key] = value
    with pytest.raises(GuardError):
        validate_run_request(h, 8787)


def test_duplicate_origin_is_rejected():
    h = headers()
    h['Origin'] = 'http://127.0.0.1:8787'
    with pytest.raises(GuardError):
        validate_run_request(h, 8787)


def test_presentation_cannot_inject_script_or_claim_signed_evidence(tmp_path):
    story = illustrative_story()
    story[0]['title'] = '</script><script>alert(1)</script>'
    render_site(tmp_path, story)
    html = (tmp_path/'index.html').read_text()
    raw = re.search(r'<script id="demo-data" type="application/json">(.*?)</script>', html, re.S).group(1)
    data = json.loads(raw)
    assert data['verified'] is False
    assert all(item['event'] is None for item in data['story'])
    assert '<script>' not in raw
    assert data['story'][0]['title'] == story[0]['title']
    assert 'protected_read_prevents_later_leak' in data['sources']['lean']
    assert 'default allow := false' in data['sources']['rego']
