requests-negotiate-sspi
=======================

An implementation of HTTP Negotiate authentication for Requests.
This module provides single-sign-on using Kerberos or NTLM using the
Windows SSPI interface.

The module does not (at this time) support password-based authentication.

Usage
-----
.. code-block:: python

   import requests
   from requests_ntlm_sspi import HTTPNegotiateAuth

   r = requests.get('https://iis.contoso.com', auth=HTTPNegotiateAuth())
