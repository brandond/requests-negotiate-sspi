from requests.auth import AuthBase
from requests.exceptions import HTTPError
import hashlib
import logging
import struct
import base64
import sspi, sspicon, win32security

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

_logger = logging.getLogger(__name__)
_package = 'Negotiate'

class HttpNegotiateAuth(AuthBase):
    def __init__(self):
        pass

    def retry_using_http_Negotiate_auth(self, response, args):
        if 'Authorization' in response.request.headers:
            return response

        targeturl = urlparse(response.request.url)
        targetspn = 'http/'+targeturl.netloc.split(':')[0]

        # Set up SSPI connection structure
        pkg_info = win32security.QuerySecurityPackageInfo(_package)
        clientauth = sspi.ClientAuth(_package, targetspn=targetspn)
        sec_buffer = win32security.PySecBufferDescType()
        
        # Channel Binding Hash (aka Extended Protection for Authentication)
        # If this is a SSL connection, we need to hash the peer certificate, prepend the RFC5929 channel binding type,
        # and stuff it into a SEC_CHANNEL_BINDINGS structure.
        # This should be sent along in the initial handshake or Kerberos auth will fail.
        if response.peercert is not None:
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

        # Initial challenge auth header
        error, auth = clientauth.authorize(sec_buffer)
        request.headers['Authorization'] = '{} {}'.format(_package, base64.b64encode(auth[0].Buffer).decode('ASCII'))
        _logger.debug('Sending Initial Context Token - error={} authenticated={}'.format(error, clientauth.authenticated))

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
                        final.replace(_package, '', 1).lstrip()
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
        challenge = [val[len(_package)+1:] for val in response2.headers.get('WWW-Authenticate', '').split(', ') if _package in val]
        if len(challenge) != 1:
            raise HTTPError('Did not get exactly one {} challenge from server.'.format(_package))

        # Add challenge to security buffer
        tokenbuf = win32security.PySecBufferType(pkg_info['MaxToken'], sspicon.SECBUFFER_TOKEN)
        tokenbuf.Buffer = base64.b64decode(challenge[0])
        sec_buffer.append(tokenbuf)
        _logger.debug('Got Challenge Token (NTLM)')

        # Perform next authorization step
        error, auth = clientauth.authorize(sec_buffer)
        request.headers['Authorization'] = '{} {}'.format(_package, base64.b64encode(auth[0].Buffer).decode('ASCII'))
        _logger.debug('Sending Response - error={} authenticated={}'.format(error, clientauth.authenticated))

        response3 = response2.connection.send(request, **args)

        # Update the history and return
        response3.history.append(response)
        response3.history.append(response2)

        return response3
        
    def response_hook(self, r, **kwargs):
        if r.status_code == 401:
            if 'negotiate' in r.headers.get('WWW-Authenticate', '').lower():
                return self.retry_using_http_Negotiate_auth(r, kwargs)

            
    def __call__(self, r):
        r.headers['Connection'] = 'Keep-Alive'
        r.register_hook('response', self.response_hook)
        return r
