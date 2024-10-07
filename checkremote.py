#!/usr/bin/env python3
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
#
# Changes:
# 07/2024 J. Kahan:
#  * Support a configuration file to give more specific behavior and
#    exemptions to what is consider a local address. The default
#    location for this file is /usr/local/etc/hostcheck.conf
#  * Use configuration options to give local IP addresses that should be
#    considered as remote. This is useful when you have local server
#    that are open to others in your local net.
#  * Use configuration options to be able to specify if addresses that
#    are part of a subnet should be considered local. This is useful
#    if you have IPv6 address that don't correspond to addresses that
#    ipaddress or the system libraries don't considers as local.
# 09/2024 J. Kahan;
# *  Support configuration options to declare a set of local hosts
#    than can bypass sso authentication as well as the header allowing
#    to do so

#
# This module depends on the python standard library ipaddress module,
# which is available in python3.

import ipaddress
import socket

from collections import OrderedDict
from configparser import ConfigParser
from os import linesep

import urllib.request as urlreq
from urllib.error import URLError
from urllib.parse import urlparse

NONE_LOCAL = 0
SOME_LOCAL = 1
ALL_LOCAL = 2

DEFAULT_CONFIG_FILE='/usr/local/etc/hostcheck.conf'

class ConfigParserMultiValues(OrderedDict):
    """Extends ConfigParser to allow parsing a file
    that has multiple values for identical option keys.

    https://docs.python.org/3/library/configparser.html
    https://stackoverflow.com/questions/15848674/how-to-configparse-a-file-keeping-multiple-values-for-identical-keys"""

    def __setitem__(self, key, value):
        if key in self and isinstance(value, list):
            self[key].extend(value)
        else:
            super().__setitem__(key, value)

    @staticmethod
    def getlist(value):
        """returns the single (or multiple) values of an option as a list"""
        return value.split(linesep)


class UnsupportedResourceError(URLError):
    def __init__(self, res_type, resource):
        super().__init__(
            f'unsupported {res_type}: {resource}')


def parse_config(config_file=DEFAULT_CONFIG_FILE):
    """ reads local config for specific local subnets and local ip
    addresses.

    Returns a dictionary with the parsed configuration organized with
    the following keys:

    'local_subnets'
    'addr_local_exemptions',
    'addr_local_sso_bypass',
    'sso_bypass_header'

    Each one of the first three entries is a list made
    with the the different values of the respective configuration file
    sections converted to ipaddr objects. 'sso_bypass_header is a dictionary.

    If the configuration file is missing a section, the value for the key
    will be empty.

    See hostcheck.conf.dist for syntax of the configuration file"""

    parsed_config = ConfigParser(strict=False, empty_lines_in_values=False,
                                 dict_type=ConfigParserMultiValues,
                                 converters={'list':
                                             ConfigParserMultiValues.getlist})

    parsed_config.read(config_file)

    if parsed_config.has_section('local_subnets'):
        local_subnets = parsed_config.getlist('local_subnets',
                                              'subnet')
        local_subnets = [ipaddress.ip_network(value) for value in
                         local_subnets]
    else:
        local_subnets = []

    if parsed_config.has_section('addr_local_exemptions'):
        addr_local_exemptions = parsed_config.getlist('addr_local_exemptions',
                                                      'addr')
        addr_local_exemptions = [ipaddress.ip_address(value) for value
                                 in addr_local_exemptions]
    else:
        addr_local_exemptions = []

    if parsed_config.has_section('addr_local_sso_bypass'):
        addr_local_sso_bypass = parsed_config.getlist('addr_local_sso_bypass',
                                                      'addr')
        addr_local_sso_bypass = [ipaddress.ip_address(value) for value
                                 in addr_local_sso_bypass]
    else:
        addr_local_sso_bypass = []

    sso_bypass_header = {}
    if (
            parsed_config.has_section('sso_bypass_header')
            and parsed_config.has_option('sso_bypass_header', 'name')
            and parsed_config.has_option('sso_bypass_header', 'value')
    ):

        name = parsed_config.get('sso_bypass_header', 'name')
        value = parsed_config.get('sso_bypass_header','value')

        if name and value:
            sso_bypass_header['name'] = name
            sso_bypass_header['value'] = value

    return { 'local_subnets' : local_subnets,
             'addr_local_exemptions': addr_local_exemptions,
             'addr_local_sso_bypass' : addr_local_sso_bypass,
             'sso_bypass_header' : sso_bypass_header }

def all_addrs(host):
    """Iterate over IPAddress objects associated with this hostname.

    You may pass in an IP address string.  That will simply return an
    iterator with the corresponding IPAddress object.

    If the hostname cannot be resolved, a URLError is raised.
    """
    try:
        addr_info = socket.getaddrinfo(host, None)
    except socket.error as error:
        raise URLError(error)
    for addr in set(info[4][0].split('%', 1)[0] for info in addr_info):
        yield ipaddress.ip_address(str(addr))

def is_addr_in_local_subnet(addr, local_subnets=None):
    """Return true if the given IPAddress is in local_subnets, else false.
    """
    if local_subnets is None:
        local_subnets = []

    for subnet in local_subnets:
        if addr in subnet:
            return True
    return False

def is_addr_local_exemption(addr, addr_local_exemptions=None):
    """Return true if the gven IPAddress is in the local addresses
    exemptions
    """
    if addr_local_exemptions is None:
        addr_local_exemptions=[]

    if addr in addr_local_exemptions:
        return True
    return False

def is_addr_local(addr, local_subnets=None, addr_local_exemptions=None):
    """Return true if the given IPAddress is local, else false.

    An address is local if it's link-local, loopback, or for a private
    network (e.g., 10.0.0.0/8).
    """
    if local_subnets is None:
        local_subnets=[]

    if addr_local_exemptions is None:
        addr_local_exemptions=[]

    is_local = any(getattr(addr, test)
                   for test in ['is_link_local', 'is_loopback', 'is_private'])

    if not is_local:
        is_local = is_addr_in_local_subnet(addr, local_subnets)

    if ( is_local and not getattr(addr, 'is_loopback') and
         is_addr_local_exemption(addr, addr_local_exemptions) ):
        is_local = False

    return is_local

def is_host_local(host, config_file=DEFAULT_CONFIG_FILE, config_parsed=None):
    """Test if a hostname has local IP addresses.

    This function checks every IP address associated with the given
    hostname, and returns NONE_LOCAL, SOME_LOCAL, or ALL_LOCAL to
    reflect how many of those addresses are local.  NONE_LOCAL is
    false; the other return values are true.  In most situations, you
    can simply use this function as a boolean test.

    You may pass in an IP address string.  The function will return
    ALL_LOCAL if the address is local, else NONE_LOCAL.
    """

    # check that output of parse_config returns a list if config_file doesn't exist
    if not config_parsed:
        config_parsed = parse_config(config_file)
    local_subnets = config_parsed['local_subnets']
    addr_local_exemptions = config_parsed['addr_local_exemptions']

    addresses = list(all_addrs(host))
    local_count = \
        len([a for a in addresses if is_addr_local(a, local_subnets,
                                                   addr_local_exemptions)])
    if local_count == 0:
        rv = NONE_LOCAL
    elif local_count == len(addresses):
        rv = ALL_LOCAL
    else:
        rv = SOME_LOCAL

    return rv

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
                     check_port_func=check_port,
                     config_file=DEFAULT_CONFIG_FILE,
                     config_parsed=None):
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
    UnsupportedResrouceError.
    """
    parsed_url = urlparse(url)
    if (schemes is not None) and (parsed_url.scheme.lower() not in schemes):
        raise UnsupportedResourceError("scheme", url)
    if parsed_url.port is not None:
        check_port_func(parsed_url.port, parsed_url.scheme.lower())
    if is_host_local(parsed_url.hostname, config_file, config_parsed):
        raise UnsupportedResourceError("address", url)

def is_host_local_sso_bypass(host, config_file=DEFAULT_CONFIG_FILE, config_parsed=None):
    """Test if a host requires an sso bypass header.

    You may pass in an IP address string. The function will return
    the bypass header name and value if the test is succesful,
    None otherwise.
    """
    rv = None

    # check that output of parse_config returns a list if config_file doesn't exist
    if not config_parsed:
        config_parsed = parse_config(config_file)
    addr_local_sso_bypass = config_parsed['addr_local_sso_bypass']
    sso_bypass_header = config_parsed['sso_bypass_header']

    if addr_local_sso_bypass and sso_bypass_header:
        addresses = list(all_addrs(host))
        local_count = \
            len([a for a in addresses if a in addr_local_sso_bypass])

        if local_count > 0:
            rv = sso_bypass_header

    return rv

def check_sso_bypass(url,
                     config_file=DEFAULT_CONFIG_FILE,
                     config_parsed=None):
    """if the remote host is configured to do an sso bpyass,
    the function then returns the sso bypass header name and value,
    otherwise returns None.
    """
    parsed_url = urlparse(url)
    rv = is_host_local_sso_bypass(parsed_url.hostname, config_file, config_parsed)

    return rv

class URLSafetyHandler(urlreq.BaseHandler):
    """urllib handler to safety check all URLs.

    This is a simple handler that will pass all URLs through a safety
    check function before opening it.  You can instantiate this class
    with the safety check function to use as an argument; by default,
    it uses this module's check_url_safety function.

    Each time a request is passed through this handler, the check
    function will be called with the request URL as an argument.  It
    should raise an exception if the URL is unsafe to handle."""
    def __init__(self, check_func=check_url_safety, config_file=DEFAULT_CONFIG_FILE,
                 config_parsed=None):
        self.check_url = check_func
        self.config_file = config_file
        self.config_parsed = config_parsed

    def default_open(self, req, *args, **kwargs):
        self.check_url(req.get_full_url(), config_file=self.config_file,
                       config_parsed=self.config_parsed)


safe_url_opener = urlreq.build_opener(URLSafetyHandler(config_file=DEFAULT_CONFIG_FILE))

if __name__ == '__main__':
    import itertools
    import tempfile
    import atexit
    import os

    def rmfile(filename):
        try:
            os.unlink(filename)
        except:
            pass

    def write_test_config(fp):
        fp.write(b"""
# a comment

[local_subnets]
subnet = 2001:0000:130F:0000::/56

[addr_local_exemptions]
addr = 10.0.0.23
addr = 2001:0000:130F:0000:0000:09C0:876A:130B

[addr_local_sso_bypass]
addr = 10.0.0.23
addr = 2001:0000:130F:0000:0000:09C0:876A:130B

[sso_bypass_header]
name = Foo
value = Bar
        """)
        fp.flush()

    def is_check_passed(call, *args, **kwargs):
        try:
            call(*args, **kwargs)
        except UnsupportedResourceError:
            return False
        return True

    def prepare_extra_args(add_config_file=False, config_file=DEFAULT_CONFIG_FILE):
        if add_config_file:
            extra_args = { 'config_file': config_file }
        else:
            extra_args = {}
        return extra_args

    good_urls = ['http://www.w3.org/index.html',
                 'https://w3.org:8080/Overview.html',
                 'https://10.0.0.23/index.html',
                 'https://[2001:0000:130F:0000:0000:09C0:876A:130B]/index.html']
    bad_urls = ['file:///etc/passwd',
                'rsync://w3.org/',
                'http://www.w3.org:22/',
                'http://localhost/server-status',
                'http://localhost:8001/2012/pyRdfa/Overview.html',
                'https://10.0.0.24/index.html',
                'https://[2001:0000:130F:0000:0000:09C0:876A:130C]/index.html']

    test_config_file = tempfile.NamedTemporaryFile(delete=False)
    print("created {test_config_file.name}")
    atexit.register(rmfile, test_config_file.name)
    write_test_config(test_config_file)

    test_opener = urlreq.OpenerDirector()
    test_opener.add_handler(URLSafetyHandler(config_file=test_config_file.name))
    # the value after the function name says if the function accepts
    # the config_file parameter
    check_funcs = [(check_url_safety, True), (test_opener.open, False)]

    for host in ['127.0.0.1', '127.254.1.2', '10.1.2.3', '10.254.4.5',
                 '172.16.1.2', '172.31.4.5', '192.168.0.1', '192.168.254.5',
                 'fe80::1', 'fe80:ffff::ffff', 'localhost', 'ip6-localhost',
                 '10.0.0.24',
                 '2001:0000:130F:0000:0000:09C0:876A:130C'
                 ]:
        assert is_host_local(host, test_config_file.name), f"local host {host} not recognized"

    for host in ['4.2.2.1', '2a03::1', 'w3.org',
                 '10.0.0.23',
                 '2001:0000:130F:0000:0000:09C0:876A:130B'
                 ]:
        assert not is_host_local(host, test_config_file.name), f"non-local host {host} misflagged"

    for host in ['10.0.0.23',
                 '2001:0000:130F:0000:0000:09C0:876A:130B'
                 ]:
        assert is_host_local_sso_bypass(host, test_config_file.name), f"sso bypass host {host} not recognized"

    for host in ['4.2.2.1', '2a03::1', 'w3.org',
                 '2001:0000:130F:0000:0000:09C0:876A:130C'
                 ]:
        assert not is_host_local_sso_bypass(host, test_config_file.name), f"non sso bypass host {host} misflagged"

    sso_bypass_header = is_host_local_sso_bypass('10.0.0.23', test_config_file.name)
    assert sso_bypass_header, f"sso bypass header is None"
    assert sso_bypass_header['name'] == 'Foo', f"sso bypass header name, expected 'Foo' got {sso_bypass_header['name']}"
    assert sso_bypass_header['value'] == 'Bar', f"sso bypass header value, expected 'Bar' got {sso_bypass_header['name']}"

    for url, check_func in itertools.product(good_urls, check_funcs):
        extra_args = prepare_extra_args(add_config_file=check_func[1],
                                        config_file=test_config_file.name)
        assert is_check_passed(check_func[0], url, **extra_args), \
            f"safe URL {url} failed safety check"

    for url, check_func in itertools.product(bad_urls, check_funcs):
        extra_args = prepare_extra_args(add_config_file=check_func[1],
                                        config_file=test_config_file.name)
        assert not is_check_passed(check_func[0], url, **extra_args), \
            f"unsafe URL {url} passed safety check"

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
        opener.add_handler(URLSafetyHandler(config_file=test_config_file.name))
        assert not is_check_passed(opener.open, good_urls[0]), \
            f"tried to open unsafe URL {url}"

    print("Tests passed.")
