requests-negotiate-sspi
=======================

An implementation of HTTP Negotiate authentication for Requests.
This module provides single-sign-on using Kerberos or NTLM using the
Windows SSPI interface.

This module supports Extended Protection for Authentication (aka 
Channel Binding Hash), which makes it usable for services that require
it, including Active Directory Federation Services.

The module does not (at this time) support password-based authentication.

Usage
-----
.. code-block:: python

   import requests
   from requests_negotiate_sspi import HttpNegotiateAuth

   r = requests.get('https://iis.contoso.com', auth=HTTPNegotiateAuth())
