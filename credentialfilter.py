#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""credentialfilter - Common tools to format and decide if security
credentials can be transmitted to remote hosts"""

#
# Copyright © 2024 World Wide Web Consortium, (Massachusetts Institute
# of Technology, European Research Consortium for Informatics and
# Mathematics, Keio University, Beihang). All Rights Reserved. This
# work is distributed under the W3C® Software License [1] in the hope
# that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.
#
# [1] http://www.w3.org/Consortium/Legal/2002/copyright-software-20021231
#
# Written July 2024 by J. Kahan <jose@w3.org>
#

from collections import OrderedDict
from configparser import ConfigParser
from os import linesep
from enum import Enum
from urllib.error import URLError
from urllib.parse import urlparse

DEFAULT_CONFIG_FILE='/usr/local/etc/credential_filter.conf'

_filter = None

class HostTrustLevels(Enum):
    """The different trust levels that can be associated with a host.
    """
    UNSAFE = 0
    SAFE = 1
    TRUSTED = 2


class ConfigParserMultiValues(OrderedDict):
    """Extends ConfigParser to allow parsing a file
    that has multiple values for identical option keys.

    https://docs.python.org/3/library/configparser.html
    https://stackoverflow.com/questions/15848674/how-to-configparse-a-file-keeping-multiple-values-for-identical-keys
    """

    def __setitem__(self, key, value):
        if key in self and isinstance(value, list):
            self[key].extend(value)
        else:
            super().__setitem__(key, value)

    @staticmethod
    def getlist(value):
        """returns the single (or multiple) values of an option as a list.
        """
        return value.split(linesep)


class UnsupportedResourceError(URLError):
    """Custom exception
    """
    def __init__(self, res_type, resource):
        super().__init__(
            f'unsupported {res_type}: {resource}')


class CredentialFilter():
    """urllib handler to safety check all URLs.

    This is a simple filter function that for an HTTP request to a
    given host, will filter all cookies associated with the request in
    function of the trust level of the host, as given by a
    configuration file.  The filter will return the target host's
    trust level (HostTrustLevels) and a number of HTTP Set-Cookie
    lines that can be added to a temporary cookie jar.
    """

    def __init__(self, config_file=DEFAULT_CONFIG_FILE):
        if config_file is None:
            config_file = DEFAULT_CONFIG_FILE

        self.config_file = config_file
        self.parse_config(config_file)

    def parse_config(self, config_file=DEFAULT_CONFIG_FILE):
        """reads local config for specific local subnets and local ip
        addresses.

        Initializes the global variables 'local_subnets' and
        'addr_local_exemptions'. Each one of these variables is a list made
        with the the different values of the respective configuration file
        sections converted to ipaddr objects.

        See credential_filter.conf.dist for syntax of the configuration file.
        """

        parsed_config = ConfigParser(strict=False, empty_lines_in_values=False,
                                     dict_type=ConfigParserMultiValues,
                                     converters={'list':
                                                 ConfigParserMultiValues.getlist})

        parsed_config.read(config_file)

        if parsed_config.has_section('trusted_hosts'):
            self.trusted_hosts = parsed_config.getlist('trusted_hosts',
                                                       'host')
        else:
            self.trusted_hosts = []

        if parsed_config.has_section('trusted_cookie_names'):
            self.trusted_cookie_names = parsed_config.getlist('trusted_cookie_names',
                                                              'cookie_name')
        else:
            self.trusted_cookie_names = []

        if parsed_config.has_section('safe_domains'):
            self.safe_domains = parsed_config.getlist('safe_domains',
                                                 'domain')
        else:
            self.safe_domains = []

        if parsed_config.has_section('safe_domain_cookie_names'):
            self.safe_domain_cookie_names = parsed_config.getlist('safe_domain_cookie_names',
                                                                  'cookie_name')
        else:
            self.safe_domain_cookie_names = []

    def _append_configuration_list(self, config_list, item=None):
        if item:
            config_list.append(item)

    def add_trusted_host(self, host):
        self._append_configuration_list(self.trusted_hosts, host)

    def add_safe_domain(self, domain):
        self._append_configuration_list(self.safe_domains, domain)

    def add_trusted_cookie_name(self, cookie_name):
        self._append_configuration_list(self.trusted_cookie_names, cookie_name)

    def add_safe_domain_cookie_name(self, cookie_name):
        self._append_configuration_list(self.safe_domain_cookie_names, cookie_name)

    def host_trust_level(self, url=None, target_host=None):
        """returns a HostTrustLevel depending if a host
        is declared in the trusted_hosts list, the safe_hosts lists
        or none of the above.
        """

        if url:
            target_host = self.extract_host_from_url(url)

        rv = HostTrustLevels.UNSAFE.value
        if target_host:
            if target_host in self.trusted_hosts:
                rv =  HostTrustLevels.TRUSTED.value
            else:
                for safe_domain in self.safe_domains:
                    if target_host.endswith(safe_domain):
                        rv =  HostTrustLevels.SAFE.value
                        break
        return rv

    def extract_host_from_url(self, url=None):
        """Parses a URL and returns its hostname if found, None otherwise.
        """
        if url is None:
            return None
        parsed_url = urlparse(url)

        if parsed_url.hostname is None:
            raise UnsupportedResourceError('extract_host_from_url',
                                           f"couldn't extract host from url {url}")

        return parsed_url.hostname

    def cookie_filter(self, cookies=None, passthru_cookie_names=None, hosts=None):
        """For each cookie in cookies that is in passthru_cookie_names
        and each host in hosts, the function will synthesize a the
        value of a Set-Cookies header using a given host as a Domain,
        and using path '/'.

        Returns a list with the Set-Cookie headers for the cookies
        that made it thru the filter, one for each filtered cookie and
        host, or an empty list if all cookies were filtered out.
        """
        filtered_cookies = []
        if passthru_cookie_names is None:
            passthru_cookie_names = []
        if hosts is None:
            hosts = []

        if cookies and cookies != '':
            cookies_list = cookies.split(';')

            for cookie in cookies_list:
                # remove all spaces (ascii, unicode)
                cookie = ''.join(cookie.split())
                if cookie == '':
                    continue

                [ cookie_name, cookie_value ] = cookie.split('=')
                if cookie_name == '' or cookie_value == '':
                    continue

                if cookie_name in passthru_cookie_names:
                    for host in hosts:
                        fake_cookie = f'{cookie_name}={cookie_value}; ' \
                            + f'Domain={host}; ' \
                            + 'Path=/; Secure; HttpOnly;'
                        filtered_cookies.append(fake_cookie)

        return filtered_cookies

    def _purge_empty_elements(self, input_list):
        """removes empty elements in list; returns purged list.
        """
        if input_list:
            rv = list(filter(lambda item: item is not None, input_list))
        else:
            rv = input_list
        return rv

    def credential_filter(self, cookies, url=None, target_host=None, merge_cookies=True):
        """Transforms the value of an HTTP cookie header into a filtered list
        of Set-Cookie headers.

        Returns a tuple stating if a given target_host can be trusted
        to handle Basic Auth information, together with a list of Set-Cookie
        headers that can be added to a cookie jar.
        Caller can either explicitly give the target_host name or use a URL
        that points to the host.
        """
        trusted_cookies = []
        safe_domain_cookies = []
        host_trust_level = HostTrustLevels.UNSAFE.value

        if url is None and target_host is None:
            raise UnsupportedResourceError('credential_filter',
                                           'url or target_host must have a value')

        if url is not None:
            target_host = self.extract_host_from_url(url)

        # if target_host is one of the trusted hosts, we generate cookies
        # for all the trusted_hosts

        if target_host in self.trusted_hosts:
            trusted_cookies = self.cookie_filter (cookies,
					          self.trusted_cookie_names,
					          self.trusted_hosts)
            host_trust_level = HostTrustLevels.TRUSTED.value

        # if the target host belongs to our safe domain, we generate safe cookies
        # for all our safe domains
        for safe_domain in self.safe_domains:
            if target_host.endswith(safe_domain):
                safe_domain_cookies = cookie_filter (cookies,
                                                     self.safe_domain_cookie_names,
                                                     self.safe_domains)
                host_trust_level |= HostTrustLevels.SAFE.value
                break

        # adjust for the | addition of the levels bitlevel
        if host_trust_level > HostTrustLevels.TRUSTED.value:
            host_trust_level = HostTrustLevels.TRUSTED.value

        if merge_cookies:
            trusted_cookies.extend(safe_domain_cookies)
            cookies = trusted_cookies
	    # purge empty elements
            cookies = self._purge_empty_elements(cookies)
            rv = (host_trust_level, cookies)

        else:
            # purge empty elements
            trusted_cookies = self._purge_empty_elements(trusted_cookies)
            safe_domain_cookies = self._purge_empty_elements(safe_domain_cookies)
            rv = (host_trust_level, trusted_cookies, safe_domain_cookies)

        return rv


def init(config_file=None):
    """Initializes an instance of CredentialFilter and assigns it to
    global variable _filter
    """
    global _filter
    if config_file is None:
        config_file=DEFAULT_CONFIG_FILE
    _filter = CredentialFilter(config_file)

def init_filter(config_file):
    """@@Planning to use this one as a decorator.
    """
    if _filter is None:
        init(config_file)

def extract_host_from_url(url=None, config_file=None):
    if _filter is None:
        init(config_file)
    return _filter.extract_host_from_url(url)

def host_trust_level(target_host=None, config_file=None):
    if _filter is None:
        init(config_file)
    return _filter.host_trust_level(target_host=target_host)

def cookie_filter(cookies=None, passthru_cookie_names=None, hosts=None,
                  config_file=None):
    if _filter is None:
        init(config_file)
    return _filter.cookie_filter(cookies=cookies,
                                 passthru_cookie_names=passthru_cookie_names,
                                 hosts=hosts)

def credential_filter(cookies, url=None, target_host=None,
                      merge_cookies=True, config_file=None):
    if _filter is None:
        init(config_file)
    return _filter.credential_filter(cookies, url, target_host, merge_cookies)

if __name__ == '__main__':
    import tempfile

    trusted_hosts = [ 'www.w3.org', 'foo.w3.org' ]
    safe_hosts = [ 'bar.w3.org', 'content.bar.w3.org' ]
    unsafe_hosts = [ 'lemonde.fr', 'youtube.com', 'example.org' ]
    url_hosts = {
        'https://www.w3.org/' : 'www.w3.org',
        'http://foo.example.com/path1/path2?qs=bar+l=t' : 'foo.example.com'
    }
    safe_domains = [ '.w3.org' ]
    passthru_cookie_names = ['trusted_cookie', 'cloudflare_bot']
    test_cookies = 'trusted_cookie=abcdefgh; outside_cookie=b1b2b3b4; cloudflare_bot=12345678'
    trusted_cookies = ['trusted_cookie=abcdefgh']
    safe_domain_cookies = ['cloudflare_bot=12345678']
    outside_cookie = ['outside_cookie=b1b2b3b4']
    test_config_file = tempfile.NamedTemporaryFile(delete=True)

    # the value after the function name says if the function accepts
    # the config_file parameter
    #check_funcs = [(check_url_safety, True), (test_opener.open, False)]

    def write_test_config(fp):
        fp.write(b"""
# a comment

[trusted_hosts]
host = www.w3.org
host = foo.w3.org

[trusted_cookie_names]
# trusted cookie
cookie_name = trusted_cookie

[safe_domains]
domain = .w3.org

[safe_domain_cookie_names]
cookie_name = cloudflare_bot
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

    write_test_config(test_config_file)

    for host in trusted_hosts:
        assert host_trust_level(target_host=host,
                                config_file=test_config_file.name) == HostTrustLevels.TRUSTED.value, \
                                f'local host {host} should be trusted'

    for host in safe_hosts:
        assert host_trust_level(target_host=host,
                                config_file=test_config_file.name) == HostTrustLevels.SAFE.value, \
                                f'local host {host} should be safe'

    for host in unsafe_hosts:
        assert host_trust_level(target_host=host,
                                config_file=test_config_file.name) == HostTrustLevels.UNSAFE.value, \
                                f'local host {host} should not be trusted'


    for host in unsafe_hosts:
        assert host_trust_level(target_host=host,
                                config_file=test_config_file.name) == HostTrustLevels.UNSAFE.value, \
                                f'local host {host} should be unsafe'

    for url, host in url_hosts.items():
        assert extract_host_from_url(url=url,
                                     config_file=test_config_file.name) == host, \
                                     f"couldn't extract host {host} from url {url}"

    filtered_cookies = cookie_filter(cookies=test_cookies,
                                     passthru_cookie_names=passthru_cookie_names,
                                     hosts=trusted_hosts,
                                     config_file=test_config_file.name)

    assert len(filtered_cookies) == 4, \
        f'expected two filtered cookies got {len(filtered_cookies)}'

    fc_cursor = 0
    for trusted_cookie in trusted_cookies:
        for host_cursor in trusted_hosts:
            assert filtered_cookies[fc_cursor].startswith(f'{trusted_cookie}; Domain={host_cursor};'), \
                f'expected cookie {trusted_cookie} and domain {host_cursor}; got {filtered_cookies[fc_cursor]}'
            fc_cursor += 1

    for safe_domain_cookie in safe_domain_cookies:
        for host_cursor in trusted_hosts:
            assert filtered_cookies[fc_cursor].startswith(f'{safe_domain_cookie}; Domain={host_cursor};'), \
                f'expected cookie {safe_domain_cookie} and domain {host_cursor}; got {filtered_cookies[fc_cursor]}'
            fc_cursor += 1

    # trusted hosts credential filtering test
    for host in trusted_hosts:
        # get merged cookies
        (host_trust_level,
         filtered_cookies) = credential_filter(cookies=test_cookies,
                                               target_host=host,
                                               config_file=test_config_file.name,)

        # get unmerged cookies for same host
        (host_trust_level,
         filtered_trusted_cookies,
         filtered_safe_domain_cookies) = credential_filter(cookies=test_cookies,
                                                           target_host=host,
                                                           config_file=test_config_file.name,
                                                           merge_cookies=False)

        assert host_trust_level & HostTrustLevels.TRUSTED.value, \
            'expected trusted host level got {host_trust_level} trust level'

        assert len(filtered_trusted_cookies) == 2, \
            f'expected 0 len(trusted_cookies), got {len(trusted_cookies)} is not zero'

        assert len(filtered_safe_domain_cookies) == 1, \
            f'expected 2 filtered safe domain cookies, got {len(filtered_safe_domain_cookies)}'

        # check that merged cookies is working
        assert len(filtered_cookies) == 3, \
            f'expected 3 filtered_cookies, got {len(filtered_cookies)}'

        for filtered_cookie in filtered_trusted_cookies:
            # get cookie name
            cookie = filtered_cookie.split(';')[0]
            assert cookie in trusted_cookies, \
                f'filtered_trusted cookie {cookie} missing in trusted_cookies'

        for filtered_cookie in filtered_safe_domain_cookies:
            # get cookie name
            cookie = filtered_cookie.split(';')[0]
            assert cookie in safe_domain_cookies, \
                f'filtered_safe cookie {cookie} missing in safe_domain_cookies'

    # safe domain hosts credential filtering tests
    for host in safe_hosts:
        # get merged cookies
        (host_trust_level,
         filtered_cookies) = credential_filter(cookies=test_cookies,
                                               target_host=host,
                                               config_file=test_config_file.name,)

        # get unmerged cookies for same host
        (host_trust_level,
         filtered_trusted_cookies,
         filtered_safe_domain_cookies) = credential_filter(cookies=test_cookies,
                                                           target_host=host,
                                                           config_file=test_config_file.name,
                                                           merge_cookies=False)

        assert host_trust_level == HostTrustLevels.SAFE.value, \
            'expected safe_domain trust level got {host_trust_level} trust level'

        assert len(filtered_trusted_cookies) == 0, \
            f'expected 0 len(trusted_cookies), got {len(trusted_cookies)} is not zero'

        assert len(filtered_safe_domain_cookies) == 1, \
            f'expected 1 filtered safe domain cookies, got {len(filtered_safe_domain_cookies)}'

        # check that merged cookies is working
        assert len(filtered_cookies) == 1, \
            f'expected 1 len(filtered_cookies), got {len(filtered_cookies)}'

        for filtered_cookie in filtered_safe_domain_cookies:
            # get cookie name
            cookie = filtered_cookie.split(';')[0]
            assert cookie in safe_domain_cookies, \
                f'filtered_safe cookie {cookie} missing in safe_domain_cookies'

    # unsafe hosts credential filtering tests
    for host in unsafe_hosts:
        # get merged cookies
        (host_trust_level,
         filtered_cookies) = credential_filter(cookies=test_cookies,
                                               target_host=host,
                                               config_file=test_config_file.name,)

        # get unmerged cookies for same host
        (host_trust_level,
         filtered_trusted_cookies,
         filtered_safe_domain_cookies) = credential_filter(cookies=test_cookies,
                                                           target_host=host,
                                                           config_file=test_config_file.name,
                                                           merge_cookies=False)

        assert host_trust_level == HostTrustLevels.UNSAFE.value, \
            'expected unsafe level got {host_trust_level} trust level'

        assert len(filtered_trusted_cookies) == 0, \
            f'len(trusted_cookies) {len(trusted_cookies)} is not zero'

        assert len(filtered_safe_domain_cookies) == 0, \
            f'expected 0 filtered safe domain cookies, got {len(filtered_cookies)}'

        # check that merged cookies is working
        assert len(filtered_cookies) == 0, \
            f'expected 0 len(filtered_cookies), got {len(filtered_cookies)}'

    print('Tests passed.')
