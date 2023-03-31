requests-negotiate-sspi
=======================

[![image](https://badge.fury.io/py/requests-negotiate-sspi.svg)](https://badge.fury.io/py/requests-negotiate-sspi)
[![image](https://travis-ci.com/brandond/requests-negotiate-sspi.svg?branch=master)](https://travis-ci.com/brandond/requests-negotiate-sspi)

An implementation of HTTP Negotiate authentication for Requests. This
module provides single-sign-on using Kerberos or NTLM using the Windows
SSPI interface.

This module supports Extended Protection for Authentication (aka Channel
Binding Hash), which makes it usable for services that require it,
including Active Directory Federation Services.

Usage
-----

```python
import requests
from requests_negotiate_sspi import HttpNegotiateAuth

r = requests.get('https://iis.contoso.com', auth=HttpNegotiateAuth())
```

Options
-------

  - `username`: Username.
    Default: None

  - `password`: Password.
    Default: None

  - `domain`: NT Domain name.
    Default: None

  - `service`: Kerberos Service type for remote Service Principal.
    Name.
    Default: 'HTTP'

  - `host`: Host name for Service Principal Name.
    Default: Extracted from request URI

  - `delegate`: Indicates that the user's credentials are to be delegated to the server.
    Default: False


If username and password are not specified, the user's default
credentials are used. This allows for single-sign-on to domain resources
if the user is currently logged on with a domain account.
