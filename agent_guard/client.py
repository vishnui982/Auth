"""Agent-side transport only. Never give an untrusted agent the server's state."""

import urllib.error
import urllib.request

from .canonical import MAX_BYTES, canonical, loads
from .errors import GuardError


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise GuardError("gateway_redirect_refused")


def request(url, token, body, endpoint="act", *, api_version="v1"):
    if endpoint not in ("act", "authorize", "execute"):
        raise ValueError("unknown endpoint")
    if api_version not in ("v1", "v2"):
        raise ValueError("unknown API version")
    req = urllib.request.Request(url.rstrip("/") + "/" + api_version + "/" + endpoint,
                                 data=canonical(body), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(req, timeout=10)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return response.status, loads(response.read(MAX_BYTES + 1))
