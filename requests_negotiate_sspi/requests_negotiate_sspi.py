import base64
import hashlib
import logging
import socket
import struct

from requests.auth import AuthBase
from requests.exceptions import HTTPError

import pywintypes
import sspi
import sspicon
import win32security

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

_logger = logging.getLogger(__name__)


class HttpNegotiateAuth(AuthBase):
    _auth_info = None
    _service = 'HTTP'
    _host = None
    _delegate = False

    def __init__(self, username=None, password=None, domain=None, service=None, host=None, delegate=False):
        """Create a new Negotiate auth handler

           Args:
            username: Username.
            password: Password.
            domain: NT Domain name.
                Default: '.' for local account.
            service: Kerberos Service type for remote Service Principal Name.
                Default: 'HTTP'
            host: Host name for Service Principal Name.
                Default: Extracted from request URI
            delegate: Indicates that the user's credentials are to be delegated to the server.
                Default: False

            If username and password are not specified, the user's default credentials are used.
            This allows for single-sign-on to domain resources if the user is currently logged on
            with a domain account.
        """
        if domain is None:
            domain = '.'

        if username is not None and password is not None:
            self._auth_info = (username, domain, password)

        if service is not None:
            self._service = service

        if host is not None:
            self._host = host

        self._delegate = delegate

    def _retry_using_http_Negotiate_auth(self, response, scheme, args):
        if 'Authorization' in response.request.headers:
            return response

        if self._host is None:
            targeturl = urlparse(response.request.url)
            self._host = targeturl.hostname
            try:
                self._host = socket.getaddrinfo(self._host, None, 0, 0, 0, socket.AI_CANONNAME)[0][3]
            except socket.gaierror as e:
                _logger.info('Skipping canonicalization of name %s due to error: %s', self._host, e)

        targetspn = '{}/{}'.format(self._service, self._host)

        # Set up SSPI connection structure
        pkg_info = win32security.QuerySecurityPackageInfo(scheme)
        clientauth = sspi.ClientAuth(scheme, targetspn=targetspn, auth_info=self._auth_info)
        sec_buffer = win32security.PySecBufferDescType()

        # Calling sspi.ClientAuth with scflags set requires you to specify all the flags, including defaults.
        # We just want to add ISC_REQ_DELEGATE.
        if self._delegate:
            clientauth.scflags |= sspicon.ISC_REQ_DELEGATE

        # Channel Binding Hash (aka Extended Protection for Authentication)
        # If this is a SSL connection, we need to hash the peer certificate, prepend the RFC5929 channel binding type,
        # and stuff it into a SEC_CHANNEL_BINDINGS structure.
        # This should be sent along in the initial handshake or Kerberos auth will fail.
        if hasattr(response, 'peercert') and response.peercert is not None:
            md = hashlib.sha256()
            md.update(response.peercert)
            appdata = 'tls-server-end-point:'.encode('ASCII')+md.digest()
            cbtbuf = win32security.PySecBufferType(pkg_info['MaxToken'], sspicon.SECBUFFER_CHANNEL_BINDINGS)
            cbtbuf.Buffer = struct.pack('LLLLLLLL{}s'.format(len(appdata)), 0, 0, 0, 0, 0, 0, len(appdata), 32, appdata)
            sec_buffer.append(cbtbuf)

        content_length = int(response.request.headers.get('Content-Length', '0'), base=10)

        if hasattr(response.request.body, 'seek'):
            if content_length > 0:
                response.request.body.seek(-content_length, 1)
            else:
                response.request.body.seek(0, 0)

        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        response.content
        response.raw.release_conn()
        request = response.request.copy()

        # this is important for some web applications that store
        # authentication-related info in cookies
        if response.headers.get('set-cookie'):
            request.headers['Cookie'] = response.headers.get('set-cookie')

        # Send initial challenge auth header
        try:
            error, auth = clientauth.authorize(sec_buffer)
            request.headers['Authorization'] = '{} {}'.format(scheme, base64.b64encode(auth[0].Buffer).decode('ASCII'))
            _logger.debug('Sending Initial Context Token - error={} authenticated={}'.format(error, clientauth.authenticated))
        except pywintypes.error as e:
            _logger.debug('Error calling {}: {}'.format(e[1], e[2]), exc_info=e)
            return response

        # A streaming response breaks authentication.
        # This can be fixed by not streaming this request, which is safe
        # because the returned response3 will still have stream=True set if
        # specified in args. In addition, we expect this request to give us a
        # challenge and not the real content, so the content will be short
        # anyway.
        args_nostream = dict(args, stream=False)
        response2 = response.connection.send(request, **args_nostream)

        # Should get another 401 if we are doing challenge-response (NTLM)
        if response2.status_code != 401:
            if response2.status_code == 200:
                # Kerberos may have succeeded; if so, finalize our auth context
                final = response2.headers.get('WWW-Authenticate')
                if final is not None:
                    try:
                        # Sometimes Windows seems to forget to prepend 'Negotiate' to the success response,
                        # and we get just a bare chunk of base64 token. Not sure why.
                        final = final.replace(scheme, '', 1).lstrip()
                        tokenbuf = win32security.PySecBufferType(pkg_info['MaxToken'], sspicon.SECBUFFER_TOKEN)
                        tokenbuf.Buffer = base64.b64decode(final)
                        sec_buffer.append(tokenbuf)
                        error, auth = clientauth.authorize(sec_buffer)
                        _logger.debug('Kerberos Authentication succeeded - error={} authenticated={}'.format(error, clientauth.authenticated))
                    except TypeError:
                        pass

            # Regardless of whether or not we finalized our auth context,
            # without a 401 we've got nothing to do. Update the history and return.
            response2.history.append(response)
            return response2

        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        response2.content
        response2.raw.release_conn()
        request = response2.request.copy()

        # Keep passing the cookies along
        if response2.headers.get('set-cookie'):
            request.headers['Cookie'] = response2.headers.get('set-cookie')

        # Extract challenge message from server
        challenge = [val[len(scheme)+1:] for val in response2.headers.get('WWW-Authenticate', '').split(', ') if scheme in val]
        if len(challenge) != 1:
            raise HTTPError('Did not get exactly one {} challenge from server.'.format(scheme))

        # Add challenge to security buffer
        tokenbuf = win32security.PySecBufferType(pkg_info['MaxToken'], sspicon.SECBUFFER_TOKEN)
        tokenbuf.Buffer = base64.b64decode(challenge[0])
        sec_buffer.append(tokenbuf)
        _logger.debug('Got Challenge Token (NTLM)')

        # Perform next authorization step
        try:
            error, auth = clientauth.authorize(sec_buffer)
            request.headers['Authorization'] = '{} {}'.format(scheme, base64.b64encode(auth[0].Buffer).decode('ASCII'))
            _logger.debug('Sending Response - error={} authenticated={}'.format(error, clientauth.authenticated))
        except pywintypes.error as e:
            _logger.debug('Error calling {}: {}'.format(e[1], e[2]), exc_info=e)
            return response

        response3 = response2.connection.send(request, **args)

        # Update the history and return
        response3.history.append(response)
        response3.history.append(response2)

        return response3

    def _response_hook(self, r, **kwargs):
        if r.status_code == 401:
            for scheme in ('Negotiate', 'NTLM'):
                if scheme.lower() in r.headers.get('WWW-Authenticate', '').lower():
                    return self._retry_using_http_Negotiate_auth(r, scheme, kwargs)

    def __call__(self, r):
        r.headers['Connection'] = 'Keep-Alive'
        r.register_hook('response', self._response_hook)
        return r
