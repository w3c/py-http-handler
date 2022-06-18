#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""checkremote - Common security checks for remote resources"""
# <http://dev.w3.org/2004/PythonLib-IH/checkremote.py>
#
# Copyright © 2013 World Wide Web Consortium, (Massachusetts Institute
# of Technology, European Research Consortium for Informatics and
# Mathematics, Keio University, Beihang). All Rights Reserved. This
# work is distributed under the W3C® Software License [1] in the hope
# that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.
#
# [1] http://www.w3.org/Consortium/Legal/2002/copyright-software-20021231
#
# Written October 2013 by Brett Smith <brett@w3.org>
# This module depends on the python standard library ipaddress module,
# which is available in python3 and backported to python2 as well.
# <https://docs.python.org/3/howto/ipaddress.html>

from __future__ import print_function
# to make code backward compatible between py2 and py3
from builtins import str

import ipaddress
import socket

try:
    import urllib2 as urlreq
    from urllib2 import URLError
    from urlparse import urlparse
except ImportError:  # Running under Python 3
    import urllib.request as urlreq
    from urllib.error import URLError
    from urllib.parse import urlparse

NONE_LOCAL = 0
SOME_LOCAL = 1
ALL_LOCAL = 2

class UnsupportedResourceError(URLError):
    def __init__(self, res_type, resource):
        super(UnsupportedResourceError, self).__init__(
            "unsupported %s: %s" % (res_type, resource))


def all_addrs(host):
    """Iterate over IPAddress objects associated with this hostname.

    You may pass in an IP address string.  That will simply return an
    iterator with the corresponding IPAddress object.

    If the hostname cannot be resolved, a URLError is raised."""
    try:
        addr_info = socket.getaddrinfo(host, None)
    except socket.error as error:
        raise URLError(error)
    for addr in set(info[4][0].split('%', 1)[0] for info in addr_info):
        yield ipaddress.ip_address(str(addr))

def is_addr_local(addr):
    """Return true if the given IPAddress is local, else false.

    An address is local if it's link-local, loopback, or for a private
    network (e.g., 10.0.0.0/8)."""
    return any(getattr(addr, test)
               for test in ['is_link_local', 'is_loopback', 'is_private'])

def is_host_local(host):
    """Test if a hostname has local IP addresses.

    This function checks every IP address associated with the given
    hostname, and returns NONE_LOCAL, SOME_LOCAL, or ALL_LOCAL to
    reflect how many of those addresses are local.  NONE_LOCAL is
    false; the other return values are true.  In most situations, you
    can simply use this function as a boolean test.

    You may pass in an IP address string.  The function will return
    ALL_LOCAL if the address is local, else NONE_LOCAL."""
    addresses = list(all_addrs(host))
    local_count = len([a for a in addresses if is_addr_local(a)])
    if local_count == 0:
        return NONE_LOCAL
    elif local_count == len(addresses):
        return ALL_LOCAL
    else:
        return SOME_LOCAL

def check_port(port, service, extra_ports=frozenset(), min_safe_port=1024):
    """Check if a port is acceptable for remote resources.

    The first argument is the port to test.  It is considered safe if it
    passes any of the following criteria:
    * It matches the canonical port number for the service named in the
      service argument.
    * It is listed in the extra_ports argument.  By default this is an
      empty set, meaning this test will never pass.
    * It is greater than or equal to min_safe_port.  By default this is 1024,
      so all unreserved ports are accepted.

    If the port does not pass these tests, this function raises an
    UnsupportedResourceError."""
    try:
        serv_port = socket.getservbyname(service)
    except socket.error:      # No service by that name
        serv_port = port - 1  # Can't be equal
    if not ((port == serv_port) or (port in extra_ports) or
            (port >= min_safe_port)):
        raise UnsupportedResourceError("port", port)

def check_url_safety(url, schemes=frozenset(['http', 'https', 'ftp']),
                     check_port_func=check_port):
    """Check if a URL points to an acceptable remote resource.

    The first argument is the URL to test.  It is considered safe if it
    passes all of the following tests:
    * The URL scheme is included in the schemes argument.  Acceptable
      schemes should be listed as all-lowercase strings.  By default,
      http, https, and ftp are accepted.  If None, all schemes are accepted.
    * The URL port, if specified, is checked using check_port_func.  This
      function is passed two arguments: the port number, and the lowercase
      URL scheme.  The default is this module's check_port function.
    * The URL host address is not local.  This is checked with the
      is_host_local function.

    If any of these tests fail, this function raises an
    UnsupportedResrouceError."""
    parsed_url = urlparse(url)
    if (schemes is not None) and (parsed_url.scheme.lower() not in schemes):
        raise UnsupportedResourceError("scheme", url)
    if parsed_url.port is not None:
        check_port_func(parsed_url.port, parsed_url.scheme.lower())
    if is_host_local(parsed_url.hostname):
        raise UnsupportedResourceError("address", url)

class URLSafetyHandler(urlreq.BaseHandler):
    """urllib handler to safety check all URLs.

    This is a simple handler that will pass all URLs through a safety
    check function before opening it.  You can instantiate this class
    with the safety check function to use as an argument; by default,
    it uses this module's check_url_safety function.

    Each time a request is passed through this handler, the check
    function will be called with the request URL as an argument.  It
    should raise an exception if the URL is unsafe to handle."""
    def __init__(self, check_func=check_url_safety):
        self.check_url = check_func

    def default_open(self, req, *args, **kwargs):
        self.check_url(req.get_full_url())


safe_url_opener = urlreq.build_opener(URLSafetyHandler())

if __name__ == '__main__':
    import itertools
    good_urls = ['http://www.w3.org/index.html',
                 'https://w3.org:8080/Overview.html',
                 'ftp://ftp.w3.org']
    bad_urls = ['file:///etc/passwd',
                'rsync://w3.org/',
                'http://www.w3.org:22/',
                'http://localhost/server-status',
                'http://localhost:8001/2012/pyRdfa/Overview.html']
    test_opener = urlreq.OpenerDirector()
    test_opener.add_handler(URLSafetyHandler())
    check_funcs = [check_url_safety, test_opener.open]
    def is_check_passed(call, *args, **kwargs):
        try:
            call(*args, **kwargs)
        except UnsupportedResourceError:
            return False
        return True

    for host in ['127.0.0.1', '127.254.1.2', '10.1.2.3', '10.254.4.5',
                 '172.16.1.2', '172.31.4.5', '192.168.0.1', '192.168.254.5',
                 'fe80::1', 'fe80:ffff::ffff', 'localhost', 'ip6-localhost']:
        assert is_host_local(host), "local host %s not recognized" % (host,)
    for host in ['4.2.2.1', '2a03::1', 'w3.org', 'www.w3.org']:
        assert not is_host_local(host), "non-local host %s misflagged" % (host,)

    for url, check_func in itertools.product(good_urls, check_funcs):
        assert is_check_passed(check_func, url), \
            "safe URL %s failed safety check" % (url,)
    for url, check_func in itertools.product(bad_urls, check_funcs):
        assert not is_check_passed(check_func, url), \
            "unsafe URL %s passed safety check" % (url,)

    class FakeRedirector(urlreq.BaseHandler):
        handler_order = URLSafetyHandler.handler_order + 100
        def __init__(self, url):
            self.url = url
        def http_request(self, req, *args, **kwargs):
            return urlreq.Request(self.url)
        ftp_request = https_request = http_request

    for url in bad_urls:
        opener = urlreq.OpenerDirector()
        opener.add_handler(FakeRedirector(url))
        opener.add_handler(URLSafetyHandler())
        assert not is_check_passed(opener.open, good_urls[0]), \
            "tried to open unsafe URL %s" % (url,)

    print("Tests passed.")
