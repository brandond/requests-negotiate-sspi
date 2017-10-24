import requests

__all__ = ['requests_negotiate_sspi']
from .requests_negotiate_sspi import HttpNegotiateAuth  # noqa

# Monkeypatch urllib3 to expose the peer certificate
HTTPResponse = requests.packages.urllib3.response.HTTPResponse
orig_HTTPResponse__init__ = HTTPResponse.__init__

HTTPAdapter = requests.adapters.HTTPAdapter
orig_HTTPAdapter_build_response = HTTPAdapter.build_response


def new_HTTPResponse__init__(self, *args, **kwargs):
    orig_HTTPResponse__init__(self, *args, **kwargs)
    try:
        self.peercert = self._connection.sock.getpeercert(binary_form=True)
    except AttributeError:
        self.peercert = None


def new_HTTPAdapter_build_response(self, request, resp):
    response = orig_HTTPAdapter_build_response(self, request, resp)
    try:
        response.peercert = resp.peercert
    except AttributeError:
        response.peercert = None
    return response


HTTPResponse.__init__ = new_HTTPResponse__init__
HTTPAdapter.build_response = new_HTTPAdapter_build_response
