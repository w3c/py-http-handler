#!/usr/bin/env python3
"""
Classes for doing rule constrained HTTP requests. Used in conjunction
with checkremote.py.

Module originally written by Dan Conolly and subsequently maintained
by Dominique Hazael-Massieu and Brett Smith (2002-2021)

2024-10-02: J. Kahan
            module rewrite and updated to use OpenerDirector handlers,
            fix security issues, and add a new configurable bypass
            header option.
"""

import urllib
import sys
import requests

# cf https://github.com/w3c/py-http-handler/blob/master/checkremote.py
from checkremote import( parse_config, check_url_safety,
                         check_sso_bypass, UnsupportedResourceError )

# cf https://github.com/w3c/py-http-handler/blob/master/surbl.py
import surbl


class ProtectedURLopener():
    """
    Expands urllib.open with handlers that apply rule constrains to
    HTTP requests.
    """
    version = "W3C HTTP Proxy Auth URL Opener/1.2"

    class CheckUrl():
        """
        Interface to checkremote.py to avoid having to open and parse
        the config file each time a request is redirected
        """
        def __init__(self):
            self.config_parsed  = parse_config()
            self.surblchecker = surbl.SurblChecker(
                '/usr/local/share/surbl/two-level-tlds', '/usr/local/etc/surbl.whitelist')

        def check_url_safety(self, url):
            """
            checks if a URL is safe to be opened using checkremote.py.
            raises an exception if url is not safe.
            """
            try:
                check_url_safety(url, config_parsed=self.config_parsed)
            except UnsupportedResourceError:
                raise OSError( 403, f"Access to url {url} is not allowed" )
            if self.surblchecker.isMarkedAsSpam(url):
                raise OSError(
                    403,
                    f"Access to url {url} is not allowed as it is marked as spam in SURBL")

        def check_sso_bypass_header(self, req):
            """
            If the target url needs an sso bypass header, the function will
            add it to the request; otherwise it will delete it if it's
            part of the request headers.
            The function receives a request object and returns the modified request object
            """
            url = req.full_url

            sso_bypass_header = self.config_parsed['sso_bypass_header']
            if not sso_bypass_header:
                return req

            add_header = check_sso_bypass(url, config_parsed=self.config_parsed)

            sso_bypass_header_name = sso_bypass_header['name']
            sso_bypass_header_value = sso_bypass_header['value']

            # urllib converts header name to all lowercase
            # except for the first letter
            c14n_sso_bypass_header_name = sso_bypass_header_name.lower().capitalize()

            if add_header:
                # add sso header if missing in req
                if not req.has_header( c14n_sso_bypass_header_name ):
                    req.add_header(sso_bypass_header_name, sso_bypass_header_value)
            else:
                # remove sso header if it is part of req
                if req.has_header( c14n_sso_bypass_header_name ):
                    req.remove_header(sso_bypass_header_name)

            return req


    class HTTPSHandler(urllib.request.HTTPSHandler):
        """
        Extends https_open to check for url safety and
        sso bypass headers.
        """
        def __init__(self, check_url, *args, **kwargs):
            self.check_url = check_url
            super().__init__(*args, **kwargs)

        def https_open(self, req):
            self.check_url.check_url_safety(req.full_url)
            req = self.check_url.check_sso_bypass_header(req)
            return super().https_open(req)


    class HTTPHandler(urllib.request.HTTPHandler):
        """
        Extends http_open to check for url safety and
        sso bypass headers.
        """
        def __init__(self, check_url, *args, **kwargs):
            self.check_url = check_url
            super().__init__(*args, **kwargs)

        def http_open(self, req):
            self.check_url.check_url_safety(req.full_url)
            req = self.check_url.check_sso_bypass_header(req)
            return super().http_open(req)


    class HTTPRedirectHandler(urllib.request.HTTPRedirectHandler):
        """
        Completes urllib with an HTTP 304 handler.
        """

        def http_error_304(self, *args, **kwargs):
            """
            handler for HTTP 304 as it is still missing in urllib.requests.py
            We just generate an error message.
            """
            print('HTTP/1.1 304 Not Modified')


    class HTTPDefaultErrorHandler(urllib.request.HTTPDefaultErrorHandler):
        """
        Default error handler so we get an HTTP page showing the error
        instead of a python stack dump.
        """
        def __init__(self, protected_url_opener_instance, *args, **kwargs):
            self.protected_url_opener_instance = protected_url_opener_instance
            super().__init__(*args, **kwargs)

        def http_error_default(self, req, fp, code, msg, hdrs):
            self.protected_url_opener_instance.set_error(repr(code) + " " + msg)
            super().http_error_default(req, fp, code, msg, hdrs)


    def __init__(self, *args, **kwargs):
        """
        Adds custom handlers to urllib.open
        """

        super().__init__(*args, **kwargs)

        # filled-up as needed by the default_http_handler
        self.protected_url_opener_error = ""

        check_url = self.CheckUrl()

        # initialize and associate our handlers with the opener
        #

        # adds HTTP 304 handler
        http_redirection_handler = self.HTTPRedirectHandler()

        # will call checkhosts to do different checks on URLs and
        # add / remove custom HTTP headers as needed
        https_handler = self.HTTPSHandler(check_url)
        http_handler = self.HTTPHandler(check_url)

        # make it easy for the error handler to find the caller of the class
        # to store a custom error message
        http_default_error_handler = \
            self.HTTPDefaultErrorHandler(protected_url_opener_instance = self)

        handlers = [
            urllib.request.UnknownHandler,
            https_handler,
            http_handler,
            http_default_error_handler,
            http_redirection_handler,
            urllib.request.HTTPErrorProcessor ]

        # create "opener" (OpenerDirector instance)
        self.opener = urllib.request.OpenerDirector()

        # and associate it with our handlers, no default handlers unless
        # specified in the handlers list
        for handler in handlers:
            if callable(handler):
                self.opener.add_handler(handler())
            else:
                self.opener.add_handler(handler)

        # make all calls to urllib.request.urlopen use our opener.
        urllib.request.install_opener(self.opener)

    def set_error(self, error):
        self.protected_url_opener_error = error

    def open(self, url, *args, **kwargs):
        """
        Opens a URL using the opener director
        """

        # clear previous error if we're reusing the same opener
        self.protected_url_opener_error = ""

        req = urllib.request.Request(url, unverifiable=True)
        resp = urllib.request.urlopen( req,
                                       #timeout in seconds
                                       timeout=3.05,
                                      )
        return resp

class ProxyAuthURLopener(ProtectedURLopener):
    """
    Dummy class to provide for backward compatibility while updating existing
    scripts to the consolidated parent class
    """
    pass

def tests():
    """
    Small testsuite to ease module maintenance.
    """

    def test_url(opener,  url):
        """
        opens a url and returns the response object or
        an error message.
        """
        try:
            resp = opener.open( url )
        except urllib.error.HTTPError as e:
            opener.protected_url_opener_error = f"HTTP Error {e.code} {e.reason}"
            resp = None
        except urllib.error.URLError as e:
            # use this exp one instead of http.client in htmldiff
            opener.protected_url_opener_error = f"URL error: invalid URL"
            resp = None
        except OSError as e:
            opener.protected_url_opener_error = f"I/O error: {e.errno} {e.strerror}"
            resp = None
        except ValueError as e:
            opener.protected_url_opener_error = str(e)
            resp = None
        except AttributeError:  # ProtectedURLopener returned None.
            pass                # There's already an error set.

        if resp is None:
            error_msg = opener.protected_url_opener_error
        else:
            error_msg = None

        return (resp, error_msg)

    opener = ProtectedURLopener()

    # public, not-redirected url
    url = 'https://www.w3.org/'
    (resp, error_msg) = test_url(opener, url)
    assert resp.code == 200, 'expected code 200'
    assert resp.url == url, "didn't open expected url"

    # public redirect
    url = 'https://www.w3.org/a.html'
    (resp, error_msg) = test_url(opener, url)
    assert resp.code == 200, 'expected code 200'
    assert resp.url == 'https://www.w3.org/A.html', 'no redirection to expected url'

    # public 304
    url = 'https://httpbin.org/status/304'
    (resp, error_msg) = test_url(opener, url)
    assert resp is None
    assert error_msg.startswith('HTTP Error 304 '), 'expected HTTP Error 304 '

    # protected URI
    url = 'https://httpbin.org/basic-auth/foo/bar'
    (resp, error_msg) = test_url(opener, url)
    assert resp is None, 'expected empty resp object'
    assert error_msg.startswith('HTTP Error 401 '), 'expected HTTP Error 401'

    # localfiles
    url = 'file:///etc/debian_version'
    (resp, error_msg) = test_url(opener, url)
    assert resp is None, 'expected empty resp object'
    assert error_msg == 'URL error: invalid URL', 'expected URL error'

    url = '/etc/debian_version'
    (resp, error_msg) = test_url(opener, url)
    assert resp is None, 'expected empty resp object'
    assert error_msg.startswith('unknown url type: '), 'expected unkown url type'

    # data uri
    url = 'data:text/plain;base64,SGVsbG8sIFdvcmxkIQ=='
    (resp, error_msg) = test_url(opener, url)
    assert resp is None, 'expected empty resp object'
    assert error_msg == 'URL error: invalid URL', 'expected URL error'

    # invalid urls
    url = 'https://doesnexist.com/'
    (resp, error_msg) = test_url(opener, url)
    assert resp is None, 'expected empty resp object'
    assert error_msg == 'URL error: invalid URL', 'expected URL error'

    url = 'https://doesnexist.comeonthisdomainnameisimaginary/'
    (resp, error_msg) = test_url(opener, url)
    assert resp is None, 'expected empty resp object'
    assert error_msg == 'URL error: invalid URL', 'expected URL error'


    print( '\nall tests completed\n' )

if __name__ == '__main__':
    tests()
